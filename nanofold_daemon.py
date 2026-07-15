"""
NanoFold daemon v2 -- in-process, env-injected Key 1, logrotate-ready.

Key 1 handling: read from the NANOFOLD_KEY1_B64 environment variable
(base64-encoded raw 32-byte X25519 public key). It lives only in this
process's memory for its lifetime -- the daemon itself never writes a key
file to disk. `nanofold.compress_file()` is called in-process (no
subprocess), so the key bytes never round-trip through argv or a shell
either. `--key1-file` is accepted as a fallback for secrets-manager setups
that only offer file-mount injection, but the env-var path is what avoids
any daemon-owned key file existing on the host at all.

Two integration modes:
  hook  <file> <out_dir> --schema S
      Synchronous, single-file. Call this directly from a logrotate
      `postrotate` script right after rotation -- logrotate already knows
      the file is done being written, so no stability guessing is needed.
      This is the PREFERRED path for anything logrotate already manages.

  watch <dir> <out_dir> --schema S [--interval N]
      Non-blocking continuous loop (just sleeps between scans -- it does
      not block or hold locks on anything else on the system) for
      directories logrotate/archive_command don't manage. Uses the same
      stability check as before: never touches a file that is still
      growing, and now also respects an optional max-size guard.
"""

import os
import sys
import time
import json
import base64
import hashlib
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nanofold  # in-process import -- key bytes never appear in argv or a subprocess

STATE_FILE = ".nanofold_daemon_state.json"


def get_key1_bytes(args):
    env_val = os.environ.get("NANOFOLD_KEY1_B64")
    if env_val:
        return base64.b64decode(env_val)
    if getattr(args, "key1_file", None):
        sys.stderr.write("[daemon] warning: reading Key 1 from a file path -- prefer the "
                          "NANOFOLD_KEY1_B64 env var so no key file exists on this host\n")
        return nanofold.load_public_key_bytes(args.key1_file)
    return None


def wait_until_stable(path, checks=3, interval=0.5, timeout=30, max_size_bytes=None):
    last_size = -1
    stable_count = 0
    start = time.time()
    while time.time() - start < timeout:
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            return False, "disappeared"
        if max_size_bytes and size > max_size_bytes:
            return False, f"exceeds max-size guard ({max_size_bytes:,} bytes) -- will retry next cycle"
        if size == last_size:
            stable_count += 1
            if stable_count >= checks:
                return True, "stable"
        else:
            stable_count = 0
        last_size = size
        time.sleep(interval)
    return False, "still growing after timeout"


def load_state(watch_dir):
    path = os.path.join(watch_dir, STATE_FILE)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def save_state(watch_dir, state):
    path = os.path.join(watch_dir, STATE_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)


def file_checksum(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def process_one_file(path, schema, out_dir, key1_bytes, state=None, state_key=None, state_dir=None):
    """Never raises out to the caller -- always returns a status string, so
    one bad file can never take the whole loop/hook down."""
    try:
        checksum = file_checksum(path)
    except FileNotFoundError:
        return "vanished_before_checksum"

    if state is not None and state.get(state_key) == checksum:
        return "already_processed"

    basename = os.path.basename(path)
    os.makedirs(out_dir, exist_ok=True)
    nf_tmp = os.path.join(out_dir, basename + ".nf.tmp")
    nf_final = os.path.join(out_dir, basename + ".nf")

    try:
        stats = nanofold.compress_file(path, nf_tmp, schema, public_key_bytes=key1_bytes)
    except nanofold.DiskSpaceError as e:
        sys.stderr.write(f"[daemon] disk space too low, skipping {path} this cycle: {e}\n")
        if os.path.exists(nf_tmp):
            os.remove(nf_tmp)
        return "disk_space_skip"
    except nanofold.CorruptFileError as e:
        sys.stderr.write(f"[daemon] verification failed for {path}, leaving source untouched: {e}\n")
        if os.path.exists(nf_tmp):
            os.remove(nf_tmp)
        return "compress_failed"
    except Exception as e:
        sys.stderr.write(f"[daemon] unexpected error on {path}, leaving source untouched: "
                          f"{type(e).__name__}: {e}\n")
        if os.path.exists(nf_tmp):
            os.remove(nf_tmp)
        return "unexpected_error"

    os.replace(nf_tmp, nf_final)   # atomic -- the .nf path only ever appears fully-formed
    try:
        os.remove(path)             # only after the verified .nf is safely and atomically in place
    except FileNotFoundError:
        pass

    if state is not None:
        state[state_key] = checksum
        save_state(state_dir, state)

    return f"processed rows={stats['rows_written']} bytes={stats['compressed_bytes']} encrypted={stats['encrypted']}"


def cmd_hook(args):
    schema = nanofold.load_schema(args.schema)
    key1_bytes = get_key1_bytes(args)
    max_bytes = args.max_size_mb * 1024 * 1024 if args.max_size_mb else None
    stable, reason = wait_until_stable(args.file, max_size_bytes=max_bytes)
    if not stable:
        sys.stderr.write(f"[daemon] {args.file} not safe to process ({reason}) -- "
                          f"leaving it untouched, exiting non-zero\n")
        sys.exit(1)
    result = process_one_file(args.file, schema, args.out_dir, key1_bytes)
    print(result)
    sys.exit(0 if (result.startswith("processed") or result == "already_processed") else 1)


def cmd_watch(args):
    schema = nanofold.load_schema(args.schema)
    key1_bytes = get_key1_bytes(args)
    max_bytes = args.max_size_mb * 1024 * 1024 if args.max_size_mb else None
    os.makedirs(args.out_dir, exist_ok=True)
    print(f"[daemon] watching {args.watch_dir} -> {args.out_dir} "
          f"encrypted={'yes' if key1_bytes else 'no'} interval={args.interval}s", flush=True)

    # Genuinely non-blocking: one os.path.getsize() per file per scan, no internal
    # sleep-loop. A file only counts as "stable" once its size has been identical
    # across `required_stable_scans` consecutive, interval-spaced scans -- so
    # stability naturally emerges from the loop's own cadence instead of blocking
    # inside a single scan waiting for one file to finish.
    size_history = {}   # abspath -> (last_size, consecutive_unchanged_scans)
    required_stable_scans = 2
    iterations = 0

    while True:
        state = load_state(args.watch_dir)
        for name in sorted(os.listdir(args.watch_dir)):
            if name == STATE_FILE or name.startswith("."):
                continue
            full = os.path.join(args.watch_dir, name)
            if not os.path.isfile(full):
                continue
            key = os.path.abspath(full)
            try:
                size = os.path.getsize(full)
            except FileNotFoundError:
                size_history.pop(key, None)
                continue

            if max_bytes and size > max_bytes:
                print(f"[daemon] {name}: exceeds max-size guard ({max_bytes:,} bytes), skipping", flush=True)
                size_history.pop(key, None)
                continue

            last_size, stable_scans = size_history.get(key, (None, 0))
            stable_scans = stable_scans + 1 if size == last_size else 1
            size_history[key] = (size, stable_scans)

            if stable_scans < required_stable_scans:
                continue  # seen it growing/new -- non-blocking, just re-check next scan

            result = process_one_file(full, schema, args.out_dir, key1_bytes,
                                       state=state, state_key=key, state_dir=args.watch_dir)
            if result != "already_processed":
                print(f"[daemon] {name}: {result}", flush=True)
            size_history.pop(key, None)

        iterations += 1
        if args.max_iterations and iterations >= args.max_iterations:
            break
        time.sleep(args.interval)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hook", help="single-file mode for a logrotate postrotate script")
    h.add_argument("file"); h.add_argument("out_dir")
    h.add_argument("--schema", required=True)
    h.add_argument("--key1-file", help="fallback only -- prefer NANOFOLD_KEY1_B64 env var")
    h.add_argument("--max-size-mb", type=float, default=None)

    w = sub.add_parser("watch", help="continuous non-blocking loop for unmanaged directories")
    w.add_argument("watch_dir"); w.add_argument("out_dir")
    w.add_argument("--schema", required=True)
    w.add_argument("--key1-file", help="fallback only -- prefer NANOFOLD_KEY1_B64 env var")
    w.add_argument("--interval", type=float, default=5.0)
    w.add_argument("--max-size-mb", type=float, default=None)
    w.add_argument("--max-iterations", type=int, default=None, help="for testing; omit to run forever")

    args = p.parse_args()
    (cmd_hook if args.cmd == "hook" else cmd_watch)(args)


if __name__ == "__main__":
    main()
