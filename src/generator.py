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
LOG_VALID_INTERVAL = 3_000_000
MAX_LOGS = 10
FLUSH_EVERY = 1_000_000
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


def set_progress_flag(value):
    update_atomic({"progress": value})
    print(f"progress = {value}")


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


def worker(start_idx, count, worker_id, stop_event, base_indices, part_file,
           done_counter, valid_counter, counter_lock, total_perms):
    b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11 = base_indices
    written = 0
    last_flushed_done = 0
    last_flushed_valid = 0

    f11, f10, f9, f8, f7, f6 = 39916800, 3628800, 362880, 40320, 5040, 720
    f5, f4, f3, f2 = 120, 24, 6, 2

    sha256 = hashlib.sha256
    wordlist = WORDLIST
    stop_is_set = stop_event.is_set

    with open(part_file, "w", encoding="utf-8") as f:
        for offset in range(count):
            if (offset & STOP_CHECK_MASK) == 0 and stop_is_set():
                break

            k = start_idx + offset

            a = [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11]
            i = k // f11; k -= i * f11; p0 = a.pop(i)
            i = k // f10; k -= i * f10; p1 = a.pop(i)
            i = k // f9;  k -= i * f9;  p2 = a.pop(i)
            i = k // f8;  k -= i * f8;  p3 = a.pop(i)
            i = k // f7;  k -= i * f7;  p4 = a.pop(i)
            i = k // f6;  k -= i * f6;  p5 = a.pop(i)
            i = k // f5;  k -= i * f5;  p6 = a.pop(i)
            i = k // f4;  k -= i * f4;  p7 = a.pop(i)
            i = k // f3;  k -= i * f3;  p8 = a.pop(i)
            i = k // f2;  k -= i * f2;  p9 = a.pop(i)
            p10 = a.pop(k)
            p11 = a[0]

            bits = (p0 << 121) | (p1 << 110) | (p2 << 99) | (p3 << 88) | \
                   (p4 << 77) | (p5 << 66) | (p6 << 55) | (p7 << 44) | \
                   (p8 << 33) | (p9 << 22) | (p10 << 11) | p11

            if (bits & 0xF) == (sha256((bits >> 4).to_bytes(16, "big")).digest()[0] >> 4):
                f.write(f"{wordlist[p0]} {wordlist[p1]} {wordlist[p2]} {wordlist[p3]} "
                        f"{wordlist[p4]} {wordlist[p5]} {wordlist[p6]} {wordlist[p7]} "
                        f"{wordlist[p8]} {wordlist[p9]} {wordlist[p10]} {wordlist[p11]}\n")
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
                    print(f"{log_value:,} valid", flush=True)

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
        print(f"ERROR: unknown word in seed: {e}")
        sys.exit(1)

    total_perms = FACTORIALS[12]
    if MAX_PERMS > 0:
        total_perms = min(total_perms, MAX_PERMS)

    print(f"perms: {total_perms:,}")

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
        print("interrupt")
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
                    print(f"worker error: {e}")
        except KeyboardInterrupt:
            stop_event.set()
            for fut in futures:
                try:
                    fut.result(timeout=10)
                except Exception:
                    pass

    elapsed = time.time() - t0
    rate = total_perms / elapsed if elapsed else 0

    part_files = [pf for (_, _, _, pf) in tasks]
    merged_lines = merge_parts(part_files, OUTPUT_FILE)

    for pf in part_files:
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
    print(f"done: {elapsed:.0f}s, {rate:,.0f}/s, valid={merged_lines:,}, {size_mb:.0f} MB")


def decide_action(row):
    """
    Decide what to do based on atomic state.

    Returns:
        "skip"        — valid_seeds.txt already present, progress=False: do nothing
        "new_seed"    — progress=True: generate a brand new seed phrase
        "resume_seed" — progress=False and file missing: reuse atomic.seed_phrase
        "first_run"   — no seed anywhere: generate a brand new seed phrase
    """
    flag = row.get("progress")
    existing_seed = row.get("seed_phrase")
    file_exists = os.path.exists(OUTPUT_FILE) and os.path.getsize(OUTPUT_FILE) > 0

    has_valid_existing_seed = (
        isinstance(existing_seed, str)
        and len(existing_seed.strip().split()) == 12
    )

    if flag is True:
        return "new_seed"
    if file_exists:
        return "skip"
    if has_valid_existing_seed:
        return "resume_seed"
    return "first_run"


def main():
    row = get_atomic_row()
    if row is None:
        print("ERROR: atomic row id=1 missing")
        sys.exit(1)

    action = decide_action(row)
    print(f"action: {action}")

    if action == "skip":
        print("nothing to do")
        sys.exit(0)

    if action == "new_seed":
        seed_phrase = MNEMO.generate(strength=128)
        print(f"seed: {seed_phrase}")
        try:
            store_seed_phrase(seed_phrase)
        except Exception as e:
            print(f"ERROR: store failed: {e}")
            sys.exit(1)
        set_progress_flag(False)

    elif action == "resume_seed":
        seed_phrase = row["seed_phrase"].strip()
        print(f"seed (resume): {seed_phrase}")

    else:
        seed_phrase = MNEMO.generate(strength=128)
        print(f"seed: {seed_phrase}")
        try:
            store_seed_phrase(seed_phrase)
        except Exception as e:
            print(f"ERROR: store failed: {e}")
            sys.exit(1)
        set_progress_flag(False)

    try:
        run_permutations(seed_phrase)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()