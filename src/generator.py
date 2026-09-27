#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import math
import signal
import time
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
from mnemonic import Mnemonic
from supabase import create_client

NUM_WORKERS = 40
OUTPUT_FILE = "valid_seeds.txt"
PART_DIR = "seed_parts"
LOG_INTERVAL = 2_000_000
FLUSH_EVERY = 100_000
MAX_PERMS = int(os.getenv("MAX_PERMS", "0"))

ATOMIC_ID = 1


def load_db_config():
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (
        os.path.join(here, "db.txt"),
        os.path.join(os.path.dirname(here), "db.txt"),
        os.path.join(os.path.dirname(os.path.dirname(here)), "db.txt"),
    ):
        if os.path.exists(path):
            cfg = {}
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, _, v = line.partition("=")
                        cfg[k.strip()] = v.strip().strip('"')
            return cfg
    raise FileNotFoundError("db.txt not found")


def get_supabase():
    cfg = load_db_config()
    return create_client(cfg["SUPABASE_URL"], cfg["SUPABASE_KEY"])


def get_atomic_row():
    supabase = get_supabase()
    res = supabase.table("atomic").select("*").eq("id", ATOMIC_ID).limit(1).execute()
    return res.data[0] if res.data else None


def update_atomic(fields):
    supabase = get_supabase()
    supabase.table("atomic").update(fields).eq("id", ATOMIC_ID).execute()


def get_progress_flag():
    row = get_atomic_row()
    return row.get("progress") if row else None


def set_progress_flag(value):
    update_atomic({"progress": value})
    print(f"Set atomic.progress = {value}.")


def store_seed_phrase(seed_phrase):
    last_err = None
    for attempt in range(1, 6):
        try:
            update_atomic({"seed_phrase": seed_phrase})
            return True
        except Exception as e:
            last_err = e
            wait = min(2 ** attempt, 30)
            print(f"atomic update failed (attempt {attempt}/5): {e}")
            if attempt < 5:
                time.sleep(wait)
    raise RuntimeError(f"Could not store seed phrase in atomic: {last_err}")


def permutation_at(words, idx):
    arr = words[:]
    k = idx
    perm = []
    for j in range(len(arr), 0, -1):
        fact = math.factorial(j - 1)
        pos = k // fact
        k %= fact
        perm.append(arr.pop(pos))
    return perm


def worker(start_idx, count, worker_id, stop_event, words, part_file,
           done_counter, valid_counter, counter_lock, total_perms):
    mnemo = Mnemonic("english")
    written = 0
    last_flushed_done = 0
    last_flushed_valid = 0

    with open(part_file, "w", encoding="utf-8") as f:
        for offset in range(count):
            if stop_event.is_set():
                break
            idx = start_idx + offset
            perm = permutation_at(words, idx)
            mnemonic = " ".join(perm)
            if mnemo.check(mnemonic):
                f.write(mnemonic + "\n")
                written += 1

            done = offset + 1
            if done % FLUSH_EVERY == 0 or done == count:
                delta_done = done - last_flushed_done
                delta_valid = written - last_flushed_valid
                last_flushed_done = done
                last_flushed_valid = written

                with counter_lock:
                    prev_total = done_counter.value
                    new_total = prev_total + delta_done
                    done_counter.value = new_total
                    valid_counter.value += delta_valid
                    log_now = (prev_total // LOG_INTERVAL) < (new_total // LOG_INTERVAL)
                    valid_snapshot = valid_counter.value

                if log_now:
                    pct = 100.0 * new_total / total_perms if total_perms else 0.0
                    print(f"Progress: {new_total:,}/{total_perms:,} ({pct:.1f}%)  valid={valid_snapshot:,}", flush=True)

    return written


def merge_parts(part_files, output_path):
    total_lines = 0
    with open(output_path, "w", encoding="utf-8") as out:
        for pf in part_files:
            if not os.path.exists(pf):
                continue
            with open(pf, "r", encoding="utf-8") as inp:
                for line in inp:
                    out.write(line)
                    total_lines += 1
    return total_lines


def run_permutations(words):
    total_perms = math.factorial(len(words))
    if MAX_PERMS > 0:
        total_perms = min(total_perms, MAX_PERMS)

    print(f"Total permutations to test: {total_perms:,}")
    print(f"Output file: {OUTPUT_FILE}")

    os.makedirs(PART_DIR, exist_ok=True)
    for name in os.listdir(PART_DIR):
        if name.startswith("part_"):
            try:
                os.remove(os.path.join(PART_DIR, name))
            except OSError:
                pass

    manager = mp.Manager()
    stop_event = manager.Event()
    done_counter = manager.Value("q", 0)
    valid_counter = manager.Value("q", 0)
    counter_lock = manager.Lock()

    def _signal_handler(sig, frame):
        print("\nInterrupt received. Setting stop event...")
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)

    chunk = total_perms // NUM_WORKERS
    remainder = total_perms % NUM_WORKERS

    tasks = []
    start = 0
    for w in range(NUM_WORKERS):
        count = chunk + (1 if w < remainder else 0)
        if count == 0:
            continue
        part_file = os.path.join(PART_DIR, f"part_{w+1:03d}.txt")
        tasks.append((start, count, w + 1, part_file))
        start += count

    print(f"Launching {len(tasks)} workers...")

    t0 = time.time()
    total_valid = 0

    with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = [
            executor.submit(worker, s, c, wid, stop_event, words, pf,
                            done_counter, valid_counter, counter_lock, total_perms)
            for (s, c, wid, pf) in tasks
        ]
        try:
            for fut in as_completed(futures):
                try:
                    total_valid += fut.result()
                except Exception as e:
                    print(f"Worker error: {e}")
        except KeyboardInterrupt:
            print("Interrupted, waiting for workers to stop...")
            stop_event.set()
            for fut in futures:
                try:
                    fut.result(timeout=10)
                except Exception:
                    pass

    elapsed = time.time() - t0
    print(f"All workers finished in {elapsed:.1f}s. Total valid seeds: {total_valid:,}")

    print(f"Merging part files into {OUTPUT_FILE}...")
    merged_lines = merge_parts([pf for (_, _, _, pf) in tasks], OUTPUT_FILE)

    for (_, _, _, pf) in tasks:
        try:
            if os.path.exists(pf):
                os.remove(pf)
        except OSError:
            pass
    try:
        os.rmdir(PART_DIR)
    except OSError:
        pass

    size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    print(f"Wrote {OUTPUT_FILE} ({size_mb:.2f} MB, {merged_lines:,} lines)")


def should_run():
    flag = get_progress_flag()
    file_exists = os.path.exists(OUTPUT_FILE) and os.path.getsize(OUTPUT_FILE) > 0

    print(f"atomic.progress = {flag!r}   valid_seeds.txt exists = {file_exists}")

    if flag is True:
        return True
    if not file_exists:
        return True
    return False


def main():
    row = get_atomic_row()
    if row is None:
        print("ERROR: atomic table has no row with id=1. Run the SQL setup first.")
        sys.exit(1)

    if not should_run():
        print("Nothing to do — seed phrases already generated and awaiting scan.")
        sys.exit(0)

    mnemo = Mnemonic("english")

    seed_phrase = mnemo.generate(strength=128)
    words = seed_phrase.split()
    if len(words) != 12:
        print(f"ERROR: expected 12 words, got {len(words)}")
        sys.exit(1)

    print(f"Seed phrase: {seed_phrase}")

    try:
        store_seed_phrase(seed_phrase)
        print("Stored seed phrase in atomic.seed_phrase.")
    except Exception as e:
        print(f"ERROR: could not store seed phrase: {e}")
        sys.exit(1)

    set_progress_flag(False)

    try:
        run_permutations(words)
    except Exception as e:
        print(f"ERROR: permutation run failed: {e}")
        sys.exit(1)

    print("Done.")


if __name__ == "__main__":
    main()