#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import math
import signal
import time
import hashlib
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
from mnemonic import Mnemonic
from supabase import create_client

NUM_WORKERS = 40
OUTPUT_FILE = "valid_seeds.txt"
PART_DIR = "seed_parts"
LOG_VALID_INTERVAL = 2_000_000
MAX_LOGS = 10
FLUSH_EVERY = 500_000
STOP_CHECK_MASK = 0x3FFF
MAX_PERMS = int(os.getenv("MAX_PERMS", "0"))

ATOMIC_ID = 1

MNEMO = Mnemonic("english")
WORDLIST = MNEMO.wordlist
WORD_TO_IDX = {w: i for i, w in enumerate(WORDLIST)}
FACTORIALS = [math.factorial(i) for i in range(13)]


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


def permutation_indices(base_indices, rank):
    arr = list(base_indices)
    k = rank
    perm = [0] * 12
    for j in range(12, 0, -1):
        f = FACTORIALS[j - 1]
        pos = k // f
        k %= f
        perm[12 - j] = arr.pop(pos)
    return perm


def checksum_ok(perm):
    bits = 0
    for i in perm:
        bits = (bits << 11) | i
    entropy = bits >> 4
    checksum = bits & 0xF
    expected = hashlib.sha256(entropy.to_bytes(16, "big")).digest()[0] >> 4
    return checksum == expected


def worker(start_idx, count, worker_id, stop_event, base_indices, part_file,
           done_counter, valid_counter, counter_lock, total_perms):
    written = 0
    last_flushed_done = 0
    last_flushed_valid = 0

    with open(part_file, "w", encoding="utf-8") as f:
        for offset in range(count):
            if (offset & STOP_CHECK_MASK) == 0 and stop_event.is_set():
                break

            rank = start_idx + offset
            perm = permutation_indices(base_indices, rank)

            if checksum_ok(perm):
                words = [WORDLIST[i] for i in perm]
                f.write(" ".join(words) + "\n")
                written += 1

            done = offset + 1
            if done % FLUSH_EVERY == 0 or done == count:
                delta_done = done - last_flushed_done
                delta_valid = written - last_flushed_valid
                last_flushed_done = done
                last_flushed_valid = written

                with counter_lock:
                    done_counter.value += delta_done
                    prev_valid = valid_counter.value
                    new_valid = prev_valid + delta_valid
                    valid_counter.value = new_valid

                    prev_level = prev_valid // LOG_VALID_INTERVAL
                    new_level = new_valid // LOG_VALID_INTERVAL
                    should_log = (new_level > prev_level) and (new_level <= MAX_LOGS)
                    log_value = new_level * LOG_VALID_INTERVAL

                if should_log:
                    print(f"{log_value:,} valid seeds", flush=True)

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


def run_permutations(seed_phrase):
    words = seed_phrase.split()
    try:
        base_indices = [WORD_TO_IDX[w] for w in words]
    except KeyError as e:
        print(f"ERROR: seed contains unknown word: {e}")
        sys.exit(1)

    total_perms = FACTORIALS[12]
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
            executor.submit(worker, s, c, wid, stop_event, base_indices, pf,
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
    rate = total_perms / elapsed if elapsed else 0
    print(f"Done in {elapsed:.1f}s ({rate:,.0f} perms/s). Valid seeds: {total_valid:,}")

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

    seed_phrase = MNEMO.generate(strength=128)
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
        run_permutations(seed_phrase)
    except Exception as e:
        print(f"ERROR: permutation run failed: {e}")
        sys.exit(1)

    print("Done.")


if __name__ == "__main__":
    main()