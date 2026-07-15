# NanoFold

**Domain-aware compression for structured logs, telemetry, and cold-storage archives — built to be verifiable, not hyped.**

> Every number in this README came from an actual script run on synthetic-but-realistic data, included in this repo (`benchmark.py`, `dict_test.py`, `index_test.py`). Run them yourself. That's the point.

---

## Why NanoFold

Generic compressors (gzip, zstd, lzma) treat your structured logs as flat text. NanoFold treats them as what they actually are: columns of timestamps, categorical codes, and free-text — and applies the right transform to each *before* handing the result to a strong generic compressor. That's the entire trick. No new math, no "impossible" ratios — just domain-aware preprocessing, the same category of idea used by Parquet, ClickHouse, and Uber's CLP.

## Core Features

- **Delta encoding** for monotonic/near-monotonic numeric columns (timestamps, auto-increment IDs)
- **Dictionary encoding** for low-cardinality categorical columns (status codes, log levels, IPs, methods)
- **Run-length encoding** on the resulting code streams
- **Shared preset dictionaries** — a schema trained once, reused across many small files, with zero per-file dictionary overhead (real win specifically for many-small-files scenarios like hourly log rotation)
- **Columnar chunking + index block** — query by timestamp range or field value *without* decompressing the whole file
- **Shadow decompression verification** — every compress operation round-trips and SHA-256-checks itself before anything is committed
- **Per-chunk encryption model** (design) — chunks stay independently decryptable, so indexed queries never need to decrypt more than they touch
- **Automatic fallback to plain zstd/lzma** when data doesn't benefit from the structured transform (never worse than baseline)
- **Zero-migration daemon** (design) — watches existing log directories, compresses in place, no schema/infra changes required

## Real, Measured Benchmarks

**50,000-row synthetic structured log (3.15 MB raw):**

| Method | Size | Ratio vs raw |
|---|---|---|
| gzip -9 | 564,857 B | 5.58x |
| lzma/xz -9 | 426,856 B | 7.39x |
| **NanoFold pipeline** (delta+dict+RLE+lzma) | **293,752 B** | **10.74x** (1.45x better than plain lzma) |

Per-column breakdown (same final compressor; only the transform differs):
- Timestamps: **1.66x** better than raw-text+lzma
- Categorical fields (ip/method/status/level): **1.47x** better
- Free-text messages: ~0 gain from delta/dict (expected — this is where classic compression is already near its ceiling)

Round-trip SHA-256 verification: **bit-perfect match, actually executed, not asserted.**

**Shared preset dictionary (many small files vs one big file):**

| Scenario | No shared dict | With shared dict | Gain |
|---|---|---|---|
| 180 small rotated log files (~19 KB each) | 758,746 B | 612,145 B | **1.24x** |
| One large 50,000-row file | 566,144 B | 565,005 B | 1.002x (negligible) |

Honest takeaway: shared dictionaries help small, frequently-rotated files. They do essentially nothing for one big blob, because the file already has enough internal redundancy. Don't oversell this feature outside its real use case.

**Indexed selective query (200,000 rows, chunked + indexed):**

| Query | Chunks touched | Bytes decompressed |
|---|---|---|
| Timestamp range (~500 rows out of 200,000) | 1 / 200 | 63,453 B (vs 12,656,250 B full file — ~200x less) |
| Specific IP (high-frequency value) | 200 / 200 | no benefit — value present in nearly every chunk |
| Specific IP (rare value) | 75 / 200 | 62.5% of chunks skippable |

Honest takeaway: min/max range indexing on naturally-sorted columns (timestamps) is a reliable, large win. Membership-based pruning on categorical columns only helps for rare values — common values need a real secondary inverted index, not just chunk membership.

**Single-core throughput (measured, not estimated):**

| Compressor | Throughput |
|---|---|
| lzma -9 | 1.3 MB/s (best ratio, too slow for PB-scale without heavy parallelization) |
| gzip -6 | 42.2 MB/s |

At petabyte scale, this is why production systems use zstd-class speed, not max-preset lzma, and why I/O — not the algorithm — is usually the real bottleneck.

## Honest Non-Goals

- **Not** a universal "compress anything by 99%" engine — no compressor can do this for high-entropy or already-compressed data (this is an information-theoretic limit, not an engineering gap)
- **Not** for live transactional databases — targets cold storage, backups, log archives
- **Not** a replacement for encryption — compression schemas are not secrets; use real AES for confidentiality
- Realistic scope: **1 PB of structured logs → roughly 50–100 TB**, not megabytes

## Roadmap

- [ ] Secondary inverted index for high-need categorical lookups (rare *and* common values)
- [ ] Dictionary versioning for schema/format drift (versioned preset dictionaries, not "AI" — same idea as Avro/Parquet schema evolution)
- [ ] Per-chunk AES-GCM encryption, wired into the index
- [ ] Linux daemon (inotify-based watcher + atomic writes + idempotent processing)
- [ ] Public benchmark suite against Parquet+zstd and CLP on real (anonymized) log samples

## v0.2 — Consolidated & Hardened

The three separate prototypes above were merged into one tool, `nanofold.py`,
with real fixes found by actually testing it (not assumed):

- **Fixed a real bug:** the dictionary-encoding fallback originally only checked
  an absolute cardinality cap (≤65536). On a test file where one column was
  ~99% unique values (embedded numeric IDs), that column still got dictionary-
  encoded and actively *hurt* the ratio: **1.82x** instead of the ~10x we'd
  seen before. Fixed by adding a uniqueness-ratio check (>15% unique → fall
  back to text). Same file, same schema, after the fix: **7.72x**.
- **Byte-perfect round trip confirmed independently** — compressed a 20,000-row
  log, decompressed it, and ran the OS `diff` command against the original
  (not just an internal hash check): files were identical.
- **Selective query confirmed on real CLI output:** timestamp-range query
  touched 1/20 chunks (8,156 bytes decompressed) instead of the full file;
  IP-value query correctly returned all matches even in the case (common IP)
  where no chunk could be skipped.
- **Edge cases tested and handled without crashing:** empty input file,
  malformed lines (wrong column count — skipped with a warning, not a crash),
  broken pipe on CLI output (e.g. piping into `head`).

## Usage

```
python3 nanofold.py compress   sample.log sample.nf --schema schema.json
python3 nanofold.py decompress sample.nf   sample_out.log
python3 nanofold.py verify     sample.nf
python3 nanofold.py query      sample.nf --column ip --value 10.0.0.5
python3 nanofold.py query      sample.nf --column ts --range 1710000000 1710000500
```

`schema.json` defines your delimiter and per-column types (`delta`, `dict`,
`text`) — see the docstring at the top of `nanofold.py` for the format.
Uses Python's standard library only (`lzma`, `hashlib`, `struct`, `json`) —
no external dependencies, no internet access required.

## v0.3 — Streaming, Encryption, Selective Encrypted Query

- **Memory-bounded streaming:** input is read in fixed buffers (default 64MB), never loaded whole. Tested down to a ~20-byte buffer forcing constant line-boundary splits — still byte-perfect.
- **Trade-off made for real streaming:** dictionary tables are now built **per-chunk**, not globally. A single-pass global dictionary would require seeing the whole file first, which contradicts bounded memory. Small honest cost: slightly larger index (small per-chunk tables) in exchange for true single-pass processing.
- **Envelope encryption (X25519 + AES-256-GCM):** `nanofold.py keygen` generates Key 1 (public, safe to deploy anywhere) and Key 2 (private, 0600 permissions, keep off edge nodes entirely). Both the index and each data chunk are sealed independently.
- **Selective encrypted query:** `--query` decrypts only the (small) index first using Key 2, then decrypts only the matching chunks. Verified: a range query touched 1/20 chunks and decrypted 8,152 bytes instead of the full file.
- **Pre-flight disk check:** aborts before touching the source file if free space looks unsafe; verified it leaves the source untouched.
- **Important limitation, stated plainly:** full post-encryption round-trip verification cannot happen on the encrypting side — that would require Key 1 to be able to decrypt, which defeats its purpose. `compress` verifies the pre-encryption pipeline; full content verification of an encrypted file requires running `verify --key2` from the system that holds Key 2.
- **No absolute "zero disk trace" claim:** a temp file is used during compression, but it only ever holds already-compressed/encrypted bytes, never staged plaintext. OS-level swap/page-cache behavior is outside any application's control — stated honestly rather than promised away.

### Usage

```
python3 nanofold.py keygen --pub key1.pub --priv key2.priv
python3 nanofold.py compress input.log out.nf --schema schema.json --key1 key1.pub
python3 nanofold.py decompress out.nf output.log --key2 key2.priv
python3 nanofold.py query out.nf --column ts --range T1 T2 --key2 key2.priv
python3 nanofold.py verify out.nf --key2 key2.priv
```

Optional dependency: `cryptography` (only needed if using `--key1`/`--key2`; plain compression has zero dependencies).


## v0.4 — Daemon: Env-Injected Keys, True Non-Blocking Loop

- **Key 1 via environment variable** (`NANOFOLD_KEY1_B64`), read once into memory -- the daemon itself never writes a key file to disk. `compress_file()` is now called **in-process** (no subprocess), so the key never round-trips through argv or a shell either.
- **Two integration modes:** `hook <file> <out_dir>` for a logrotate `postrotate` script (preferred wherever logrotate already manages rotation), and `watch <dir> <out_dir>` as a continuous fallback loop for directories nothing else manages.
- **Real bug found and fixed:** the first version of the watch loop's stability check ran its own internal blocking poll (sleeping *inside* a single scan until a file stopped growing or timed out) -- so a single actively-growing file could stall the loop from moving on. Verified with a real growing file. Fixed by tracking size across separate, interval-spaced **scan cycles** instead (one quick `stat()` per file per scan, no internal blocking loop) -- confirmed with a repeat test: a growing file was correctly left untouched across two fast scans, and picked up automatically once a later scan found it unchanged.
- Example `logrotate` postrotate config and a `systemd` unit (with `LoadCredential=`, least-privilege sandboxing) are in `deployment_examples.conf`.


---

**Author:** [Your Name] — built and benchmarked incrementally, every claim tested before it was written down. Bugs found by testing were fixed and documented here, not hidden.
