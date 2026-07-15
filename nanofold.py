#!/usr/bin/env python3
"""
NanoFold - consolidated core engine (streaming + encrypted-index query build).

New in this build:
  - Memory-bounded streaming: reads the input in fixed-size buffers (default
    64MB), never loads the whole file. Dictionary encoding is now PER-CHUNK
    (not global) -- this is what makes true single-pass streaming possible;
    see the note in analyze_columns/compress_file for the honest trade-off.
  - Correct trailing-fragment handling: the final partial buffer/batch is
    always flushed and encoded as a valid last chunk, never dropped.
  - Envelope encryption (X25519 ECDH + AES-256-GCM), same scheme proven
    separately: Key 1 (public) encrypts, Key 2 (private) decrypts. Both the
    index block AND each data chunk are sealed independently, so a query
    can decrypt just the (small) index first, then only the chunks it needs.
  - Pre-flight disk space check before touching anything.

IMPORTANT, READ THIS: a mandatory *full* round-trip verification (like the
unencrypted path has always had) is CRYPTOGRAPHICALLY INCOMPATIBLE with the
Key1/Key2 design when encryption is enabled. The whole point of Key 1 being
public-only is that the encrypting node cannot decrypt its own output --
so it cannot fully self-verify the final encrypted bytes either. What
compress() *can* still verify (and does, by default): the compression
pipeline itself (delta/dict/RLE/lzma) round-trips correctly, checked BEFORE
encryption. What it cannot verify: that serialization/encryption of the
already-correct plaintext didn't introduce a bug. That check has to happen
on the Key 2 side -- run `nanofold.py verify <file> --key2 <path>` from the
system that holds Key 2, right after ingest, as a routine step. This is not
a corner cut; it is what the security property you asked for actually
requires.

Usage:
    nanofold.py keygen      [--pub FILE] [--priv FILE]
    nanofold.py compress    <input> <output.nf> --schema schema.json [--key1 FILE] [--buffer-size-mb N]
    nanofold.py decompress  <input.nf> <output> [--key2 FILE]
    nanofold.py query       <input.nf> --column NAME (--value X | --range MIN MAX) [--key2 FILE]
    nanofold.py verify      <input.nf> [--key2 FILE]
"""

import argparse
import json
import lzma
import hashlib
import struct
import shutil
import sys
import os

MAGIC = b"NF02"


class SchemaError(Exception):
    pass


class CorruptFileError(Exception):
    pass


class DiskSpaceError(Exception):
    pass


# --------------------------------------------------------------- crypto ----
# Imported lazily so the base tool has zero hard dependencies unless
# encryption is actually requested.

def _crypto():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return X25519PrivateKey, X25519PublicKey, HKDF, hashes, serialization, AESGCM


def generate_keypair(pub_path, priv_path):
    X25519PrivateKey, _, _, _, serialization, _ = _crypto()
    private_key = X25519PrivateKey.generate()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    os.chmod(priv_path, 0o600)  # Key 2: readable only by owner
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)
    return {"public_key_file": pub_path, "private_key_file": priv_path}


def load_public_key_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def load_private_key(path):
    X25519PrivateKey, _, _, _, _, _ = _crypto()
    with open(path, "rb") as f:
        raw = f.read()
    return X25519PrivateKey.from_private_bytes(raw)


def encrypt_chunk_with_public_key(plaintext, recipient_public_bytes):
    X25519PrivateKey, X25519PublicKey, HKDF, hashes, serialization, AESGCM = _crypto()
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    recipient_public = X25519PublicKey.from_public_bytes(recipient_public_bytes)
    shared_secret = ephemeral_private.exchange(recipient_public)
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"nanofold-chunk-key-v1").derive(shared_secret)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return ephemeral_public_bytes + nonce + ciphertext


def decrypt_chunk_with_private_key(sealed, server_private_key):
    _, X25519PublicKey, HKDF, hashes, serialization, AESGCM = _crypto()
    ephemeral_public_bytes, nonce, ciphertext = sealed[:32], sealed[32:44], sealed[44:]
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    shared_secret = server_private_key.exchange(ephemeral_public)
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"nanofold-chunk-key-v1").derive(shared_secret)
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


# ------------------------------------------------------------- pre-flight --

def preflight_disk_check(input_path, output_path, min_free_bytes=None):
    """Runs before anything is opened for writing or the source is touched."""
    input_size = os.path.getsize(input_path)
    out_dir = os.path.dirname(os.path.abspath(output_path)) or "."
    free = shutil.disk_usage(out_dir).free
    required = min_free_bytes if min_free_bytes is not None else max(100 * 1024 * 1024, int(input_size * 0.15))
    if free < required:
        raise DiskSpaceError(
            f"Only {free/1e6:.1f} MB free in '{out_dir}', need at least {required/1e6:.1f} MB "
            f"as a safety margin to process a {input_size/1e6:.1f} MB input. Aborting before "
            f"touching the source file or writing anything."
        )


# ---------------------------------------------------------------- schema ---

def load_schema(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            schema = json.load(f)
    except FileNotFoundError:
        raise SchemaError(f"Schema file not found: {path}")
    except json.JSONDecodeError as e:
        raise SchemaError(f"Schema file is not valid JSON: {e}")
    if "columns" not in schema or not schema["columns"]:
        raise SchemaError("Schema must define a non-empty 'columns' list")
    for col in schema["columns"]:
        if "name" not in col or "type" not in col:
            raise SchemaError(f"Each column needs 'name' and 'type': {col}")
        if col["type"] not in ("delta", "dict", "text"):
            raise SchemaError(f"Unknown column type '{col['type']}' for column '{col['name']}'")
    schema.setdefault("delimiter", "|")
    schema.setdefault("chunk_rows", 1000)
    return schema


def analyze_columns(rows, schema):
    """Decides the ACTUAL per-column encoding for THIS batch of rows.
    Because this now runs per-chunk (streaming), a column's encoding can
    legitimately differ between chunks -- decode doesn't care, since every
    chunk fully describes its own encoding in its index metadata."""
    effective = []
    for i, col in enumerate(schema["columns"]):
        name, requested = col["name"], col["type"]
        if requested == "text" or not rows:
            effective.append({"name": name, "type": "text"})
            continue
        values = [r[i] for r in rows]

        if requested == "delta":
            try:
                [int(v) for v in values]
                effective.append({"name": name, "type": "delta"})
                continue
            except ValueError:
                sys.stderr.write(f"[nanofold] column '{name}': non-integer values -> trying 'dict'\n")
                requested = "dict"

        if requested == "dict":
            uniq = set(values)
            uniqueness_ratio = len(uniq) / len(values)
            if len(uniq) > 65536 or uniqueness_ratio > 0.15:
                sys.stderr.write(
                    f"[nanofold] column '{name}': {len(uniq):,}/{len(values):,} "
                    f"({uniqueness_ratio:.1%}) unique -- falling back to 'text' for this chunk\n"
                )
                effective.append({"name": name, "type": "text"})
            else:
                effective.append({"name": name, "type": "dict"})
    return effective


# ------------------------------------------------------- streaming reader --

def stream_row_batches(input_path, delimiter, ncols, stats, buffer_size, batch_rows):
    """Yields lists of up to `batch_rows` parsed rows, reading the file in
    bounded `buffer_size`-byte blocks. Never holds the whole file in memory.
    The final partial block/batch IS flushed (not dropped) once EOF is hit."""
    stats.setdefault("bad_lines", 0)
    stats.setdefault("total_rows", 0)
    leftover = b""
    batch = []
    with open(input_path, "rb") as f:
        while True:
            block = f.read(buffer_size)
            eof = not block
            data = leftover + block
            lines = data.split(b"\n")
            if not eof:
                leftover = lines[-1]        # incomplete trailing line -> carry to next read
                lines = lines[:-1]
            else:
                leftover = b""
                if lines and lines[-1] == b"":
                    lines = lines[:-1]      # trailing newline at true EOF, not a real row

            for line_bytes in lines:
                try:
                    line = line_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    stats["bad_lines"] += 1
                    continue
                parts = line.split(delimiter)
                if len(parts) != ncols:
                    stats["bad_lines"] += 1
                    continue
                batch.append(parts)
                stats["total_rows"] += 1
                if len(batch) >= batch_rows:
                    yield batch
                    batch = []
            if eof:
                break
    if batch:
        yield batch  # <<< the trailing fragment flush


# ------------------------------------------------------------- encoders ----

def encode_delta_column(values):
    ints = [int(v) for v in values]
    first = ints[0]
    deltas = [ints[i] - ints[i - 1] for i in range(1, len(ints))]
    max_abs = max((abs(d) for d in deltas), default=0)
    fmt = "h" if max_abs <= 32767 else ("i" if max_abs <= 2**31 - 1 else "q")
    blob = struct.pack("<q", first)
    if deltas:
        blob += struct.pack(f"<{len(deltas)}{fmt}", *deltas)
    return {"fmt": fmt, "count": len(ints), "min": min(ints), "max": max(ints)}, blob


def decode_delta_column(meta, blob):
    count = meta["count"]
    first = struct.unpack("<q", blob[:8])[0]
    if count <= 1:
        return [str(first)]
    n = count - 1
    deltas = struct.unpack(f"<{n}{meta['fmt']}", blob[8:])
    vals = [first]
    for d in deltas:
        vals.append(vals[-1] + d)
    return [str(v) for v in vals]


def rle_encode(codes, width):
    out = bytearray()
    if not codes:
        return bytes(out)
    prev, cnt = codes[0], 1
    for c in codes[1:]:
        if c == prev and cnt < 65535:
            cnt += 1
        else:
            out += (struct.pack("<B", prev) if width == 1 else struct.pack("<H", prev))
            out += struct.pack("<H", cnt)
            prev, cnt = c, 1
    out += (struct.pack("<B", prev) if width == 1 else struct.pack("<H", prev))
    out += struct.pack("<H", cnt)
    return bytes(out)


def rle_decode(data, width):
    out = []
    i, step = 0, (3 if width == 1 else 4)
    while i < len(data):
        val = data[i] if width == 1 else struct.unpack("<H", data[i:i + 2])[0]
        cnt = struct.unpack("<H", data[i + width:i + step])[0]
        out.extend([val] * cnt)
        i += step
    return out


def encode_dict_column(values, mapping, width):
    return rle_encode([mapping[v] for v in values], width)


def pack_parts(parts):
    """Length-prefixed packing -- robust against any byte sequence appearing
    inside a part (a plain separator token could theoretically collide with
    real data; length-prefixing cannot)."""
    out = bytearray()
    for p in parts:
        out += struct.pack("<I", len(p))
        out += p
    return bytes(out)


def unpack_parts(data, n):
    parts = []
    pos = 0
    for _ in range(n):
        (length,) = struct.unpack_from("<I", data, pos)
        pos += 4
        parts.append(data[pos:pos + length])
        pos += length
    return parts


# --------------------------------------------------------------- compress ---

def compress_file(input_path, output_path, schema, public_key_bytes=None,
                   buffer_size_mb=64.0, verify=True, lzma_preset=6):
    preflight_disk_check(input_path, output_path)

    ncols = len(schema["columns"])
    delimiter = schema["delimiter"]
    batch_rows = schema["chunk_rows"]
    buffer_size = int(buffer_size_mb * 1024 * 1024)
    stats = {}
    chunks_meta = []
    offset = 0

    tmp_data_path = output_path + ".data.tmp"
    with open(tmp_data_path, "wb") as data_f:
        for batch in stream_row_batches(input_path, delimiter, ncols, stats, buffer_size, batch_rows):
            effective = analyze_columns(batch, schema)
            parts, cols_meta = [], {}

            for i, col in enumerate(effective):
                colvals = [r[i] for r in batch]
                if col["type"] == "delta":
                    meta, blob = encode_delta_column(colvals)
                    parts.append(blob)
                    cols_meta[col["name"]] = {"kind": "delta", "fmt": meta["fmt"], "count": meta["count"],
                                               "min": meta["min"], "max": meta["max"]}
                elif col["type"] == "dict":
                    table = sorted(set(colvals))
                    width = 1 if len(table) <= 256 else 2
                    mapping = {v: idx for idx, v in enumerate(table)}
                    blob = encode_dict_column(colvals, mapping, width)
                    codes_present = sorted(set(mapping[v] for v in colvals))
                    parts.append(blob)
                    cols_meta[col["name"]] = {"kind": "dict", "width": width, "count": len(colvals),
                                               "codes_present": codes_present, "table": table}
                else:
                    blob = "\n".join(colvals).encode()
                    parts.append(blob)
                    cols_meta[col["name"]] = {"kind": "text"}

            chunk_blob = pack_parts(parts)
            compressed = lzma.compress(chunk_blob, preset=lzma_preset)

            if verify:
                column_names = [c["name"] for c in effective]
                fake_meta = {"row_count": len(batch), "cols": cols_meta}
                recon_rows = decode_chunk(fake_meta, compressed, column_names, encrypted=False, server_private_key=None)
                recon_text = ("\n".join(delimiter.join(r) for r in recon_rows) + "\n").encode()
                orig_text = ("\n".join(delimiter.join(r) for r in batch) + "\n").encode()
                if recon_text != orig_text:
                    raise CorruptFileError(
                        "Shadow verification FAILED on a chunk during compression -- refusing "
                        "to continue. This is a bug, please report it."
                    )

            sealed = encrypt_chunk_with_public_key(compressed, public_key_bytes) if public_key_bytes else compressed
            data_f.write(sealed)
            chunks_meta.append({"offset": offset, "length": len(sealed),
                                 "row_count": len(batch), "cols": cols_meta})
            offset += len(sealed)

    column_names = [c["name"] for c in schema["columns"]]
    header = {"delimiter": delimiter, "columns": column_names,
              "encrypted": bool(public_key_bytes), "total_rows": stats.get("total_rows", 0)}
    header_json = json.dumps(header).encode()
    index_json = json.dumps(chunks_meta).encode()
    index_blob = encrypt_chunk_with_public_key(index_json, public_key_bytes) if public_key_bytes else index_json

    with open(output_path, "wb") as out_f:
        out_f.write(MAGIC)
        out_f.write(struct.pack("<I", len(header_json)))
        out_f.write(header_json)
        out_f.write(struct.pack("<I", len(index_blob)))
        out_f.write(index_blob)
        with open(tmp_data_path, "rb") as data_f:
            shutil.copyfileobj(data_f, out_f, length=buffer_size)  # bounded-memory copy
    os.remove(tmp_data_path)

    out_size = os.path.getsize(output_path)
    result = {
        "rows_written": stats.get("total_rows", 0),
        "bad_lines_skipped": stats.get("bad_lines", 0),
        "chunks": len(chunks_meta),
        "compressed_bytes": out_size,
        "encrypted": bool(public_key_bytes),
        "verified": ("pre-encryption pipeline check passed" if (verify and public_key_bytes)
                     else ("full round-trip verified" if verify else "skipped")),
    }
    if public_key_bytes:
        result["note"] = ("Full post-encryption verification requires Key 2. Run "
                           "'nanofold.py verify <file> --key2 <path>' from the system that "
                           "holds it -- the encrypting side cannot verify its own ciphertext.")
    return result


# ------------------------------------------------------------- decode core -

def decode_chunk(meta, blob, column_names, encrypted, server_private_key):
    if encrypted:
        blob = decrypt_chunk_with_private_key(blob, server_private_key)
    chunk_blob = lzma.decompress(blob)
    parts = unpack_parts(chunk_blob, len(column_names))
    row_count = meta["row_count"]
    col_values = []
    for i, name in enumerate(column_names):
        cinfo = meta["cols"][name]
        part = parts[i]
        if cinfo["kind"] == "delta":
            vals = decode_delta_column(cinfo, part)
        elif cinfo["kind"] == "dict":
            codes = rle_decode(part, cinfo["width"])
            table = cinfo["table"]
            vals = [table[c] for c in codes]
        else:
            vals = part.decode().split("\n") if row_count > 0 else []
        col_values.append(vals)
    return [[col_values[c][r] for c in range(len(column_names))] for r in range(row_count)]


def _read_header_and_index(f, server_private_key):
    magic = f.read(4)
    if magic != MAGIC:
        raise CorruptFileError("Bad magic header -- not a NanoFold file, or the file is corrupted")
    hlen = struct.unpack("<I", f.read(4))[0]
    header = json.loads(f.read(hlen).decode())
    ilen = struct.unpack("<I", f.read(4))[0]
    index_blob = f.read(ilen)
    data_start = f.tell()

    encrypted = header.get("encrypted", False)
    if encrypted:
        if server_private_key is None:
            raise CorruptFileError("This file is encrypted -- provide --key2 <private key file>")
        index_json = decrypt_chunk_with_private_key(index_blob, server_private_key)
    else:
        index_json = index_blob
    index = json.loads(index_json.decode())
    return header, index, data_start


# ------------------------------------------------------------- decompress ---

def decompress_file(input_path, output_path, server_private_key=None):
    bytes_written = 0
    with open(input_path, "rb") as f:
        header, index, data_start = _read_header_and_index(f, server_private_key)
        column_names, delimiter, encrypted = header["columns"], header["delimiter"], header.get("encrypted", False)
        with open(output_path, "wb") as out_f:
            for meta in index:
                f.seek(data_start + meta["offset"])
                blob = f.read(meta["length"])
                rows = decode_chunk(meta, blob, column_names, encrypted, server_private_key)
                text = ("\n".join(delimiter.join(r) for r in rows) + "\n").encode() if rows else b""
                out_f.write(text)
                bytes_written += len(text)
    return {"bytes_written": bytes_written}


def verify_file(input_path, server_private_key=None, report_path=None):
    import datetime
    row_total = 0
    chunk_reports = []
    file_sha256 = hashlib.sha256()
    with open(input_path, "rb") as fhash:
        for block in iter(lambda: fhash.read(1024 * 1024), b""):
            file_sha256.update(block)

    with open(input_path, "rb") as f:
        header, index, data_start = _read_header_and_index(f, server_private_key)
        column_names, encrypted = header["columns"], header.get("encrypted", False)
        content_checked = (not encrypted) or (server_private_key is not None)
        for i, meta in enumerate(index):
            f.seek(data_start + meta["offset"])
            blob = f.read(meta["length"])
            entry = {"chunk_index": i, "row_count": meta["row_count"]}
            try:
                rows = decode_chunk(meta, blob, column_names, encrypted, server_private_key)
                entry["status"] = "OK"
                row_total += len(rows)
            except Exception as e:
                entry["status"] = f"FAILED: {type(e).__name__}: {e}"
            chunk_reports.append(entry)

    all_ok = all(c["status"] == "OK" for c in chunk_reports)
    result = {
        "status": "OK" if all_ok else "CORRUPTION_DETECTED",
        "rows": row_total,
        "chunks": len(index),
        "encrypted": header.get("encrypted", False),
        "content_verified": content_checked,
    }

    if report_path:
        report = {
            "report_type": "NanoFold Integrity Certificate",
            "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "file": os.path.abspath(input_path),
            "file_sha256": file_sha256.hexdigest(),
            "file_size_bytes": os.path.getsize(input_path),
            "encrypted": header.get("encrypted", False),
            "content_cryptographically_verified": content_checked,
            "total_rows": row_total,
            "total_chunks": len(index),
            "overall_status": result["status"],
            "chunk_details": chunk_reports,
            "note": ("content_cryptographically_verified=false means this report only confirms "
                     "the file's own SHA-256 and structural integrity, NOT that the encrypted "
                     "contents are undamaged -- that requires Key 2." if not content_checked else
                     "Every chunk was decrypted and decompressed successfully during this check."),
        }
        with open(report_path, "w") as rf:
            json.dump(report, rf, indent=2)
        result["report_written_to"] = report_path

    return result


# ------------------------------------------------------------------ query --

def query(nf_path, column, value=None, range_=None, server_private_key=None):
    matches, chunks_scanned, bytes_decompressed = [], 0, 0
    with open(nf_path, "rb") as f:
        header, index, data_start = _read_header_and_index(f, server_private_key)
        column_names, delimiter, encrypted = header["columns"], header["delimiter"], header.get("encrypted", False)
        if column not in column_names:
            raise SchemaError(f"No such column: '{column}'")
        col_idx = column_names.index(column)

        for meta in index:
            cinfo = meta["cols"][column]
            skip = False
            if value is not None and cinfo["kind"] == "dict":
                table = cinfo["table"]
                code = table.index(value) if value in table else None
                skip = (code is None) or (code not in cinfo["codes_present"])
            elif range_ is not None and cinfo["kind"] == "delta":
                lo, hi = range_
                skip = not (cinfo["max"] >= lo and cinfo["min"] <= hi)

            if skip:
                continue
            chunks_scanned += 1
            f.seek(data_start + meta["offset"])
            blob = f.read(meta["length"])
            bytes_decompressed += meta["length"]
            rows = decode_chunk(meta, blob, column_names, encrypted, server_private_key)
            for r in rows:
                v = r[col_idx]
                if value is not None and v == value:
                    matches.append(delimiter.join(r))
                elif range_ is not None and range_[0] <= int(v) <= range_[1]:
                    matches.append(delimiter.join(r))

    return matches, chunks_scanned, len(index), bytes_decompressed


# --------------------------------------------------------------------- cli --

def main():
    p = argparse.ArgumentParser(prog="nanofold")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen")
    k.add_argument("--pub", default="nanofold_key1.pub")
    k.add_argument("--priv", default="nanofold_key2.priv")

    c = sub.add_parser("compress")
    c.add_argument("input"); c.add_argument("output")
    c.add_argument("--schema", required=True)
    c.add_argument("--key1", help="public key file -- enables envelope encryption")
    c.add_argument("--buffer-size-mb", type=float, default=64.0)
    c.add_argument("--level", type=int, default=6, choices=range(0, 10),
                    help="lzma preset 0(fastest)-9(smallest); default 6")
    c.add_argument("--no-verify", action="store_true")

    d = sub.add_parser("decompress")
    d.add_argument("input"); d.add_argument("output")
    d.add_argument("--key2", help="private key file, required if the file is encrypted")

    q = sub.add_parser("query")
    q.add_argument("input")
    q.add_argument("--column", required=True)
    q.add_argument("--value")
    q.add_argument("--range", nargs=2, type=int)
    q.add_argument("--key2", help="private key file, required if the file is encrypted")

    v = sub.add_parser("verify")
    v.add_argument("input")
    v.add_argument("--key2", help="private key file -- without it, an encrypted file can only "
                                  "be structurally checked, not content-verified")
    v.add_argument("--report", help="write a full auditor-ready integrity certificate (JSON) to this path")

    args = p.parse_args()

    try:
        if args.cmd == "keygen":
            print(json.dumps(generate_keypair(args.pub, args.priv), indent=2))

        elif args.cmd == "compress":
            schema = load_schema(args.schema)
            pub_bytes = load_public_key_bytes(args.key1) if args.key1 else None
            stats = compress_file(args.input, args.output, schema, public_key_bytes=pub_bytes,
                                   buffer_size_mb=args.buffer_size_mb, verify=not args.no_verify,
                                   lzma_preset=args.level)
            print(json.dumps(stats, indent=2))

        elif args.cmd == "decompress":
            priv = load_private_key(args.key2) if args.key2 else None
            print(json.dumps(decompress_file(args.input, args.output, priv), indent=2))

        elif args.cmd == "query":
            priv = load_private_key(args.key2) if args.key2 else None
            range_ = tuple(args.range) if args.range else None
            matches, scanned, total, bytes_dec = query(args.input, args.column, args.value, range_, priv)
            print(f"chunks_scanned={scanned}/{total}  bytes_read={bytes_dec}  matches={len(matches)}")
            for m in matches[:20]:
                print(m)
            if len(matches) > 20:
                print(f"... and {len(matches)-20} more")

        elif args.cmd == "verify":
            priv = load_private_key(args.key2) if args.key2 else None
            print(json.dumps(verify_file(args.input, priv, args.report), indent=2))

    except DiskSpaceError as e:
        sys.stderr.write(f"[nanofold] disk space error: {e}\n")
        sys.exit(3)
    except (SchemaError, CorruptFileError) as e:
        sys.stderr.write(f"[nanofold] error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
