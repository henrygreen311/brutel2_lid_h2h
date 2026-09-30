#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import io
import json
import math
import os
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import requests
from mnemonic import Mnemonic
from supabase import create_client


# ============================================================================
# CONFIG — edit these, then run:   python3 repo_scanner.py
# ============================================================================

# How many new repos to scan this run.
COUNT = 100

# Number of concurrent workers (download + scan in parallel).
MAX_WORKERS = 5

# Star range. Small repos (0..4) leak secrets the most.
USE_STARS_FILTER = True
MIN_STARS = 0
MAX_STARS = 4

# Language filter. Set to None to scan any language.
LANGUAGE = None              # e.g. "python", "javascript", "go", "rust"

# Only scan repos pushed within the last N days (from now).
PUSHED_WITHIN_DAYS = 7

# Extra GitHub search qualifiers. Set to None to disable.
EXTRA_QUERY = None           # e.g. "topic:iot"

# Push findings to Supabase gitbot.findings after the run completes.
UPLOAD_FINDINGS = True

# ============================================================================


GITHUB_API = "https://api.github.com"
CODELOAD = "https://codeload.github.com"

DEFAULT_TAXONOMY = Path("taxonomy.json")
DEFAULT_SCANNED = Path("scan/git_url.txt")
DEFAULT_OUT = Path("bug/findings.json")

GITBOT_TABLE = "gitbot"
GITBOT_ROW_ID = 1
GITBOT_NAME = "gitbot"

BIP39_LENGTHS = (12, 15, 18, 21, 24)
BIP39_TRIGGER_RULE = "bip39-mnemonic"
BIP39_REPORT_RULE = "bip39-seed-phrase"

RISK_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------
# db.txt / supabase
# --------------------------------------------------------------------------

def load_db_config():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "db.txt"),
        os.path.join(here, "..", "db.txt"),
        os.path.join(here, "..", "..", "db.txt"),
        os.path.join(os.path.dirname(here), "db.txt"),
        os.path.join(os.path.dirname(os.path.dirname(here)), "db.txt"),
    ]
    for path in candidates:
        path = os.path.abspath(path)
        if os.path.exists(path):
            cfg = {}
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, _, v = line.partition("=")
                        cfg[k.strip()] = v.strip().strip('"').strip("'")
            return cfg
    raise FileNotFoundError("db.txt not found")


def get_supabase():
    cfg = load_db_config()
    return create_client(cfg["SUPABASE_URL"], cfg["SUPABASE_KEY"])


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return []
    return value


def load_tokens_from_gitbot():
    supabase = get_supabase()
    res = (
        supabase.table(GITBOT_TABLE)
        .select("git_token")
        .eq("id", GITBOT_ROW_ID)
        .limit(1)
        .execute()
    )
    if not res.data:
        return []
    tokens = _as_list(res.data[0].get("git_token"))
    out = []
    for t in tokens:
        if isinstance(t, dict):
            tok = (t.get("token") or "").strip()
        else:
            tok = str(t).strip()
        if tok:
            out.append(tok)
    return out


def push_findings_to_gitbot(payload):
    supabase = get_supabase()
    supabase.table(GITBOT_TABLE).update({
        "findings": payload,
        "updated_at": now_iso(),
    }).eq("id", GITBOT_ROW_ID).execute()


# --------------------------------------------------------------------------
# entropy / helpers
# --------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_probably_binary(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return True
    sample = data[:8192]
    if not sample:
        return False
    try:
        sample.decode("utf-8")
        return False
    except UnicodeDecodeError:
        non_text = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
        return non_text / len(sample) > 0.30


def is_mostly_non_ascii(data: bytes, threshold: float = 0.60) -> bool:
    sample = data[:16384]
    if not sample:
        return False
    non_ascii = sum(1 for b in sample if b > 127)
    return non_ascii / len(sample) > threshold


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}…{secret[-4:]}"


# --------------------------------------------------------------------------
# scanned-repo ledger
# --------------------------------------------------------------------------

class ScannedRepos:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seen: set[str] = set()
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self.seen.add(line.lower())

    def contains(self, full_name: str) -> bool:
        return full_name.lower() in self.seen

    def add(self, full_name: str) -> None:
        if self.contains(full_name):
            return
        self.seen.add(full_name.lower())
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(full_name + "\n")


# --------------------------------------------------------------------------
# taxonomy
# --------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    description: str
    category: str
    risk: str
    pattern: re.Pattern
    secret_group: int
    entropy: float
    keywords: tuple[str, ...]
    allowlist: tuple[re.Pattern, ...]


@dataclass
class Settings:
    min_entropy: float
    max_file_size_kb: int
    skip_extensions: tuple[str, ...]
    skip_filenames: tuple[str, ...]
    skip_paths: tuple[str, ...]


def load_taxonomy(path: Path) -> tuple[Settings, list[Rule]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    s = data.get("settings", {})
    settings = Settings(
        min_entropy=float(s.get("min_entropy", 3.0)),
        max_file_size_kb=int(s.get("max_file_size_kb", 2048)),
        skip_extensions=tuple(e.lower() for e in s.get("skip_extensions", [])),
        skip_filenames=tuple(n.lower() for n in s.get("skip_filenames", [])),
        skip_paths=tuple(p.replace("\\", "/") for p in s.get("skip_paths", [])),
    )

    rules: list[Rule] = []
    for raw in data["rules"]:
        try:
            pattern = re.compile(raw["regex"])
        except re.error as e:
            log(f"bad regex in rule {raw.get('id')!r}: {e}")
            continue
        try:
            allowlist = tuple(
                re.compile(a) for a in raw.get("allowlist", {}).get("regexes", [])
            )
        except re.error as e:
            log(f"bad allowlist in rule {raw.get('id')!r}: {e}")
            allowlist = ()
        rules.append(Rule(
            id=raw["id"],
            description=raw["description"],
            category=raw["category"],
            risk=raw.get("risk", "medium"),
            pattern=pattern,
            secret_group=int(raw.get("secret_group", 1)),
            entropy=float(raw.get("entropy", 0.0)),
            keywords=tuple(k.lower() for k in raw.get("keywords", [])),
            allowlist=allowlist,
        ))
    return settings, rules


def load_bip39() -> set[str]:
    return set(Mnemonic("english").wordlist)


# --------------------------------------------------------------------------
# repo discovery
# --------------------------------------------------------------------------

def build_query() -> str:
    parts = []
    if USE_STARS_FILTER:
        parts.append(f"stars:{MIN_STARS}..{MAX_STARS}")
    if LANGUAGE:
        parts.append(f"language:{LANGUAGE}")
    if PUSHED_WITHIN_DAYS is not None and PUSHED_WITHIN_DAYS > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=PUSHED_WITHIN_DAYS))
        parts.append(f"pushed:>={cutoff.strftime('%Y-%m-%d')}")
    parts.append("is:public")
    parts.append("archived:false")
    parts.append("fork:false")
    if EXTRA_QUERY:
        parts.append(EXTRA_QUERY)
    return " ".join(parts)


def search_repositories(
    session: requests.Session,
    query: str,
    want: int,
    scanned: ScannedRepos,
) -> list[dict]:
    chosen: list[dict] = []
    seen: set[str] = set()
    per_page = 50

    for page in range(1, 21):
        params = {
            "q": query,
            "per_page": per_page,
            "page": page,
            "sort": "updated",
            "order": "desc",
        }
        r = session.get(f"{GITHUB_API}/search/repositories",
                        params=params, timeout=30)
        if r.status_code in (403, 429):
            wait = int(r.headers.get("Retry-After") or 30)
            log(f"  search rate-limited, sleeping {wait}s")
            time.sleep(wait)
            continue
        if r.status_code != 200:
            log(f"  search HTTP {r.status_code}, stopping")
            break
        items = r.json().get("items", [])
        if not items:
            break
        for it in items:
            full = it["full_name"]
            if scanned.contains(full) or full in seen:
                continue
            seen.add(full)
            chosen.append(it)
            if len(chosen) >= want:
                return chosen
    return chosen


# --------------------------------------------------------------------------
# download + extract
# --------------------------------------------------------------------------

def download_tarball(session: requests.Session, full_name: str,
                     branch: str) -> bytes | None:
    tried: set[str] = set()
    for ref in (branch, "main", "master", "develop"):
        if not ref or ref in tried:
            continue
        tried.add(ref)
        url = f"{CODELOAD}/{full_name}/tar.gz/refs/heads/{ref}"
        try:
            r = session.get(url, timeout=180, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code == 200 and r.content:
            return r.content
    return None


def extract_tarball(blob: bytes, dest: Path) -> Path | None:
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            dest_resolved = dest.resolve()
            for m in tf.getmembers():
                if not (m.isfile() or m.isdir()):
                    continue
                target = (dest / m.name).resolve()
                if not str(target).startswith(str(dest_resolved)):
                    continue
                tf.extract(m, dest)
    except (tarfile.TarError, OSError):
        return None
    children = [c for c in dest.iterdir() if c.is_dir()]
    return children[0] if children else dest


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    description: str
    category: str
    risk: str
    repo: str
    repo_url: str
    file: str
    line: int
    secret_masked: str
    entropy: float
    snippet: str
    occurrences: int = 1


def iter_candidate_files(root: Path, settings: Settings) -> Iterator[Path]:
    root_res = root.resolve()
    for p in root_res.rglob("*"):
        if not p.is_file():
            continue
        rel = "/" + p.relative_to(root_res).as_posix()
        if any(skip in rel for skip in settings.skip_paths):
            continue
        if p.suffix.lower() in settings.skip_extensions:
            continue
        # Exact-filename match (case-insensitive) for extension-less docs
        if p.name.lower() in settings.skip_filenames:
            continue
        # Also catch "README" without extension via stem comparison
        if p.stem.lower() in settings.skip_filenames:
            continue
        try:
            if p.stat().st_size > settings.max_file_size_kb * 1024:
                continue
        except OSError:
            continue
        yield p


def read_text_file(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if is_probably_binary(raw):
        return None
    if is_mostly_non_ascii(raw):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError:
            return None


def scan_file(file_path: Path, rel_path: str, repo_full_name: str,
              repo_url: str, rules: list[Rule],
              settings: Settings) -> tuple[list[Finding], bool]:
    text = read_text_file(file_path)
    if text is None:
        return [], False

    lower = text.lower()
    out: list[Finding] = []
    bip39_triggered = False

    for rule in rules:
        if rule.keywords and not any(kw in lower for kw in rule.keywords):
            continue
        try:
            matches = list(rule.pattern.finditer(text))
        except (re.error, RuntimeError):
            continue
        if not matches:
            continue

        if rule.id == BIP39_TRIGGER_RULE:
            bip39_triggered = True
            continue

        for m in matches:
            try:
                secret = m.group(rule.secret_group)
            except (IndexError, re.error):
                continue
            if not secret:
                continue
            if any(a.search(secret) for a in rule.allowlist):
                continue
            ent = shannon_entropy(secret)
            if rule.entropy > 0 and ent < rule.entropy:
                continue

            line_no = text.count("\n", 0, m.start()) + 1
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.end())
            if le == -1:
                le = len(text)
            snippet = text[ls:le].strip()[:280]

            out.append(Finding(
                rule_id=rule.id,
                description=rule.description,
                category=rule.category,
                risk=rule.risk,
                repo=repo_full_name,
                repo_url=repo_url,
                file=rel_path,
                line=line_no,
                secret_masked=mask_secret(secret),
                entropy=round(ent, 3),
                snippet=snippet,
            ))
    return out, bip39_triggered


def bip39_phrase_findings(root: Path, settings: Settings, wordlist: set[str],
                          repo_full_name: str, repo_url: str) -> list[Finding]:
    if not wordlist:
        return []
    out: list[Finding] = []
    for f in iter_candidate_files(root, settings):
        text = read_text_file(f)
        if not text:
            continue
        rel = f.relative_to(root).as_posix()
        for start_pos, words in _iter_bip39_runs(text, wordlist):
            line_no = text.count("\n", 0, start_pos) + 1
            head = " ".join(words[:3])
            out.append(Finding(
                rule_id=BIP39_REPORT_RULE,
                description=f"BIP39 seed phrase ({len(words)} words)",
                category="crypto_wallet_secrets",
                risk="critical",
                repo=repo_full_name,
                repo_url=repo_url,
                file=rel,
                line=line_no,
                secret_masked=f"{head}…",
                entropy=0.0,
                snippet=f"{len(words)}-word BIP39 sequence",
            ))
    return out


def _iter_bip39_runs(text: str,
                     wordlist: set[str]) -> Iterator[tuple[int, list[str]]]:
    run: list[tuple[str, int]] = []
    for m in re.finditer(r"[a-z]+", text.lower()):
        w = m.group()
        if w in wordlist:
            run.append((w, m.start()))
        else:
            if len(run) in BIP39_LENGTHS:
                yield run[0][1], [w for w, _ in run]
            run = []
    if len(run) in BIP39_LENGTHS:
        yield run[0][1], [w for w, _ in run]


def scan_repo(root: Path, repo_full_name: str, repo_url: str,
              rules: list[Rule], settings: Settings,
              wordlist: set[str]) -> list[Finding]:
    dedup: dict[tuple[str, str], Finding] = {}
    trigger_bip39 = False

    def add_finding(finding: Finding) -> None:
        key = (finding.rule_id, finding.secret_masked)
        existing = dedup.get(key)
        if existing is None:
            dedup[key] = finding
        else:
            existing.occurrences += 1

    for f in iter_candidate_files(root, settings):
        rel = f.relative_to(root).as_posix()
        file_findings, triggered = scan_file(
            f, rel, repo_full_name, repo_url, rules, settings
        )
        trigger_bip39 = trigger_bip39 or triggered
        for finding in file_findings:
            add_finding(finding)

    if trigger_bip39 and wordlist:
        for finding in bip39_phrase_findings(
            root, settings, wordlist, repo_full_name, repo_url
        ):
            add_finding(finding)

    return list(dedup.values())


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def build_payload(findings: list[Finding], repos_scanned: int) -> dict:
    sorted_findings = sorted(findings, key=lambda f: (
        RISK_RANK.get(f.risk, 9), f.repo, f.file, f.line
    ))
    return {
        "scanned_at": now_iso(),
        "repos_scanned": repos_scanned,
        "total_findings": len(sorted_findings),
        "findings": [asdict(f) for f in sorted_findings],
    }


def write_findings(payload: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------
# worker (thread-local session)
# --------------------------------------------------------------------------

_thread_local = threading.local()


def get_session(token: str) -> requests.Session:
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "repo-secret-scanner/3.9",
        })
        _thread_local.session = s
    return s


def scan_one_repo(meta: dict, token: str, workdir: Path,
                  rules: list[Rule], settings: Settings,
                  wordlist: set[str]) -> dict:
    full_name = meta["full_name"]
    repo_url = meta["html_url"]
    stars = meta.get("stargazers_count", 0)
    branch = meta.get("default_branch") or "main"

    result = {
        "full_name": full_name,
        "repo_url": repo_url,
        "stars": stars,
        "findings": [],
        "error": None,
    }

    session = get_session(token)

    try:
        blob = download_tarball(session, full_name, branch)
    except Exception as e:
        result["error"] = f"download error: {e}"
        return result

    if blob is None:
        result["error"] = "download failed"
        return result

    try:
        with tempfile.TemporaryDirectory(dir=workdir) as tmp:
            root = extract_tarball(blob, Path(tmp))
            if root is None:
                result["error"] = "extract failed"
                return result
            result["findings"] = scan_repo(
                root, full_name, repo_url, rules, settings, wordlist
            )
    except Exception as e:
        result["error"] = f"scan error: {e}"

    return result


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    settings, rules = load_taxonomy(DEFAULT_TAXONOMY)
    wordlist = load_bip39()

    try:
        tokens = load_tokens_from_gitbot()
    except Exception as e:
        log(f"error: could not load tokens from Supabase gitbot: {e}")
        return 2

    if not tokens:
        log("error: no GitHub tokens (Supabase gitbot.git_token empty)")
        return 2

    scanned = ScannedRepos(DEFAULT_SCANNED)
    log(f"{len(rules)} rules | {len(wordlist)} BIP39 words | "
        f"{len(tokens)} token(s) | {len(scanned.seen)} repos already scanned")
    log(f"skip extensions: {len(settings.skip_extensions)} | "
        f"skip filenames: {len(settings.skip_filenames)} | "
        f"skip paths: {len(settings.skip_paths)}")

    query = build_query()
    log(f"query: {query}")
    log(f"want: {COUNT} new repo(s), pushed within last "
        f"{PUSHED_WITHIN_DAYS} day(s), {MAX_WORKERS} workers")

    discovery = requests.Session()
    discovery.headers.update({
        "Authorization": f"Bearer {tokens[0]}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "repo-secret-scanner/3.9",
    })

    candidates = search_repositories(discovery, query, COUNT, scanned)
    if not candidates:
        log("no new repos matched the query")
        return 0

    log(f"found {len(candidates)} new repo(s) to scan")
    workdir = Path(tempfile.mkdtemp(prefix="repo_scan_"))

    all_findings: list[Finding] = []
    ok = 0
    failed = 0
    completed = 0

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {}
            for i, meta in enumerate(candidates):
                tok = tokens[i % len(tokens)]
                fut = pool.submit(
                    scan_one_repo, meta, tok, workdir,
                    rules, settings, wordlist
                )
                futures[fut] = meta

            for fut in as_completed(futures):
                completed += 1
                try:
                    result = fut.result()
                except Exception as e:
                    log(f"[{completed}/{len(candidates)}] worker crash: {e}")
                    failed += 1
                    continue

                full_name = result["full_name"]
                stars = result["stars"]
                tag = f"[{completed}/{len(candidates)}] {full_name} (★{stars})"

                if result["error"]:
                    log(f"{tag}: {result['error']}")
                    failed += 1
                    continue

                findings = result["findings"]
                all_findings.extend(findings)
                scanned.add(full_name)
                ok += 1
                log(f"{tag}: {len(findings)} finding(s)")

        payload = build_payload(all_findings, ok)
        write_findings(payload, DEFAULT_OUT)
        log(f"done: {ok} scanned, {failed} failed, "
            f"{len(all_findings)} findings → {DEFAULT_OUT}")

        if UPLOAD_FINDINGS:
            try:
                push_findings_to_gitbot(payload)
                log("findings pushed to Supabase gitbot.findings")
            except Exception as e:
                log(f"warning: Supabase push failed: {e}")

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("shutdown")
        sys.exit(130)