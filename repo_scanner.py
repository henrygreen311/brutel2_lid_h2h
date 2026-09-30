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
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
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

# How many findings to collect before stopping. Primary exit target.
TARGET_FINDINGS = 50

# Safety upper bound on repos scanned.
MAX_REPOS = 5000

# Number of concurrent workers.
MAX_WORKERS = 8

# Star range. Small repos (0..4) leak secrets the most.
MIN_STARS = 0
MAX_STARS = 4

# Skip repos whose README contains real content. Empty/missing README → scan.
SKIP_REPOS_WITH_README_CONTENT = True
README_CONTENT_MIN_CHARS = 50

# Push findings to Supabase gitbot.findings after the run completes.
UPLOAD_FINDINGS = True

# Extra GitHub search qualifiers applied to every query (None to disable).
EXTRA_QUERY = None

# ---------------------------------------------------------------------------
# QUERY ROTATION
#
# Every query below uses stars:0..4 (hard limit, per requirement).
# Rotation varies only the time window and language so each query returns
# a different set of repos. When one query hits GitHub's 1000-result cap,
# the script moves to the next. Repos already attempted are never retried.
#
# Order matters: tightest time window first, then widen.
# ---------------------------------------------------------------------------
QUERY_ROTATION = [
    # Time-window sweeps (no language filter — broadest reach)
    {"days": 1,   "language": None},
    {"days": 3,   "language": None},
    {"days": 7,   "language": None},
    {"days": 14,  "language": None},
    {"days": 21,  "language": None},
    {"days": 30,  "language": None},
    {"days": 45,  "language": None},
    {"days": 60,  "language": None},
    {"days": 90,  "language": None},

    # Language sweeps on the 30-day window
    {"days": 30,  "language": "python"},
    {"days": 30,  "language": "javascript"},
    {"days": 30,  "language": "typescript"},
    {"days": 30,  "language": "go"},
    {"days": 30,  "language": "java"},
    {"days": 30,  "language": "php"},
    {"days": 30,  "language": "ruby"},
    {"days": 30,  "language": "csharp"},
    {"days": 30,  "language": "kotlin"},
    {"days": 30,  "language": "swift"},
    {"days": 30,  "language": "rust"},
    {"days": 30,  "language": "dart"},

    # Language sweeps on the 90-day window (last resort)
    {"days": 90,  "language": "python"},
    {"days": 90,  "language": "javascript"},
    {"days": 90,  "language": "typescript"},
    {"days": 90,  "language": "go"},
    {"days": 90,  "language": "java"},
    {"days": 90,  "language": "php"},
]

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

README_NAMES = (
    "readme.md", "readme.markdown", "readme.rst", "readme.txt",
    "readme", "readme.adoc",
)


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


def repo_has_readme_content(root: Path, min_chars: int) -> bool:
    try:
        entries = list(root.iterdir())
    except OSError:
        return False
    for p in entries:
        if not p.is_file():
            continue
        if p.name.lower() not in README_NAMES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if len("".join(text.split())) >= min_chars:
            return True
    return False


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
# candidate source with query rotation
# --------------------------------------------------------------------------

def build_query_from_spec(spec: dict) -> str:
    parts = [f"stars:{MIN_STARS}..{MAX_STARS}"]
    days = spec.get("days")
    if days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        parts.append(f"pushed:>={cutoff.strftime('%Y-%m-%d')}")
    lang = spec.get("language")
    if lang:
        parts.append(f"language:{lang}")
    parts.append("is:public")
    parts.append("archived:false")
    parts.append("fork:false")
    if EXTRA_QUERY:
        parts.append(EXTRA_QUERY)
    return " ".join(parts)


class CandidateSource:
    """Fetches fresh candidates from GitHub search across a rotation of
    queries. When one query hits the 1000-result cap, moves to the next.
    Repos already attempted (in this process or in the scanned ledger) are
    never returned twice."""

    MAX_PAGE = 20  # GitHub hard cap

    def __init__(self, session: requests.Session, rotation: list[dict],
                 scanned: ScannedRepos) -> None:
        self.session = session
        self.rotation = rotation
        self.scanned = scanned
        self.attempted: set[str] = set()
        self.buffer: list[dict] = []
        self.rot_index = 0
        self.page = 1
        self.current_query = ""
        self._start_query()

    def _start_query(self) -> bool:
        while self.rot_index < len(self.rotation):
            spec = self.rotation[self.rot_index]
            self.current_query = build_query_from_spec(spec)
            self.page = 1
            log(f"  [query {self.rot_index + 1}/{len(self.rotation)}] "
                f"{self.current_query}")
            return True
        return False

    def _fetch_page(self) -> list[dict]:
        if self.page > self.MAX_PAGE:
            return []
        params = {
            "q": self.current_query,
            "per_page": 50,
            "page": self.page,
            "sort": "updated",
            "order": "desc",
        }
        r = self.session.get(f"{GITHUB_API}/search/repositories",
                             params=params, timeout=30)
        if r.status_code in (403, 429):
            wait_s = int(r.headers.get("Retry-After") or 30)
            log(f"  search rate-limited, sleeping {wait_s}s")
            time.sleep(wait_s)
            return self._fetch_page()
        if r.status_code == 422:
            log(f"  search unprocessable, rotating")
            self.page = self.MAX_PAGE + 1
            return []
        if r.status_code != 200:
            log(f"  search HTTP {r.status_code}, rotating")
            self.page = self.MAX_PAGE + 1
            return []
        self.page += 1
        return r.json().get("items", [])

    def fetch_more(self, want: int) -> list[dict]:
        while len(self.buffer) < want:
            items = self._fetch_page()

            if not items:
                self.rot_index += 1
                if not self._start_query():
                    break
                continue

            for it in items:
                full = it["full_name"]
                if full.lower() in self.attempted:
                    continue
                if self.scanned.contains(full):
                    continue
                self.attempted.add(full.lower())
                self.buffer.append(it)

        out = self.buffer[:want]
        del self.buffer[:want]
        return out


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
        if p.name.lower() in settings.skip_filenames:
            continue
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
            "User-Agent": "repo-secret-scanner/4.4",
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
        "skipped": False,
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

            if SKIP_REPOS_WITH_README_CONTENT:
                if repo_has_readme_content(root, README_CONTENT_MIN_CHARS):
                    result["skipped"] = True
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
    if SKIP_REPOS_WITH_README_CONTENT:
        log(f"skip repos with README content >= {README_CONTENT_MIN_CHARS} chars")
    log(f"star range: {MIN_STARS}..{MAX_STARS} (fixed) | "
        f"target: {TARGET_FINDINGS} finding(s) | "
        f"safety cap {MAX_REPOS} repos | "
        f"{MAX_WORKERS} workers | "
        f"{len(QUERY_ROTATION)} queries in rotation")

    discovery = requests.Session()
    discovery.headers.update({
        "Authorization": f"Bearer {tokens[0]}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "repo-secret-scanner/4.4",
    })

    source = CandidateSource(discovery, QUERY_ROTATION, scanned)
    workdir = Path(tempfile.mkdtemp(prefix="repo_scan_"))

    all_findings: list[Finding] = []
    ok = 0
    failed = 0
    skipped = 0
    target_reached = False

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures: dict = {}

            def stop_condition() -> bool:
                return target_reached or ok >= MAX_REPOS

            def submit_one() -> bool:
                if stop_condition():
                    return False
                batch = source.fetch_more(1)
                if not batch:
                    return False
                meta = batch[0]
                tok = tokens[len(futures) % len(tokens)]
                fut = pool.submit(
                    scan_one_repo, meta, tok, workdir,
                    rules, settings, wordlist
                )
                futures[fut] = meta
                return True

            for _ in range(MAX_WORKERS):
                if not submit_one():
                    break

            while futures:
                done, _ = wait(list(futures.keys()),
                               return_when=FIRST_COMPLETED)

                for fut in done:
                    meta = futures.pop(fut)

                    try:
                        result = fut.result()
                    except Exception as e:
                        log(f"[fail] {meta.get('full_name')}: worker crash: {e}")
                        failed += 1
                        if not stop_condition():
                            submit_one()
                        continue

                    full_name = result["full_name"]
                    stars = result["stars"]

                    if result.get("skipped"):
                        skipped += 1
                    elif result["error"]:
                        failed += 1
                    else:
                        findings = result["findings"]
                        all_findings.extend(findings)
                        scanned.add(full_name)
                        ok += 1
                        new_total = len(all_findings)
                        log(f"[{new_total}/{TARGET_FINDINGS} findings] "
                            f"{full_name} (★{stars}): +{len(findings)}")

                        if new_total >= TARGET_FINDINGS:
                            target_reached = True

                    if not stop_condition():
                        submit_one()

        payload = build_payload(all_findings, ok)
        write_findings(payload, DEFAULT_OUT)

        if target_reached:
            log(f"done: hit target {len(all_findings)}/{TARGET_FINDINGS} "
                f"findings across {ok} scanned, {skipped} skipped (README), "
                f"{failed} failed → {DEFAULT_OUT}")
        else:
            log(f"done: all queries exhausted at {len(all_findings)}/"
                f"{TARGET_FINDINGS} findings, {ok} scanned, "
                f"{skipped} skipped (README), {failed} failed → {DEFAULT_OUT}")

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