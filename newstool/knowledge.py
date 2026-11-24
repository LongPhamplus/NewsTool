"""Local full-text index of public security knowledge bases (markdown only).

Each repo is downloaded as a tarball (a few MB each, HackTricks ~150 MB) and its .md files go into a SQLite FTS5
table. Searches run locally: no API rate limits, and every word can be required. The index lives in the user cache
directory (public documentation, not news) and is rebuilt once a week."""
import asyncio
import os
import re
import sqlite3
import tarfile
import tempfile
import time
from pathlib import Path

import httpx

from .fetcher import HEADERS

# (repo, branch). Only documentation/markdown is indexed; the tarballs are read once and discarded.
REPOS = [
    ("swisskyrepo/PayloadsAllTheThings", "master"),
    ("HackTricks-wiki/hacktricks", "master"),
    ("OWASP/wstg", "master"),
    ("OWASP/CheatSheetSeries", "master"),
    ("swisskyrepo/InternalAllTheThings", "main"),
    ("Hack-with-Github/Awesome-Hacking", "master"),
    ("enaqx/awesome-pentest", "master"),
]
MAX_AGE = 7 * 86400
MAX_DOC = 300_000  # characters per file; the biggest files are long lists


def db_path() -> Path:
    env = os.environ.get("NEWSTOOL_KB_PATH", "").strip()
    return Path(env) if env else Path.home() / ".cache" / "newstool" / "knowledge.db"


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS docs USING fts5("
                 "repo UNINDEXED, path UNINDEXED, url UNINDEXED, body, tokenize='unicode61')")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (repo TEXT PRIMARY KEY, synced REAL, files INTEGER)")
    return conn


def _extract(tar_path: str, repo: str, branch: str) -> list[tuple[str, str, str, str]]:
    """Read all .md files from the tarball (blocking; run in a thread)."""
    rows = []
    with tarfile.open(tar_path, "r:gz") as tar:
        for m in tar:
            if not m.isfile() or not m.name.lower().endswith(".md"):
                continue
            # the tarball's top folder is "<repo name>-<branch>/"; drop it to get the path inside the repo
            rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if rel.startswith((".github/", "node_modules/")):
                continue
            data = tar.extractfile(m)
            if data is None:
                continue
            body = data.read().decode("utf-8", errors="ignore")[:MAX_DOC]
            url = f"https://github.com/{repo}/blob/{branch}/{rel}"
            rows.append((repo, rel, url, body))
    return rows


async def sync_repo(repo: str, branch: str) -> int:
    """Download one repo and replace its rows. Returns the number of markdown files indexed."""
    fd, tmp = tempfile.mkstemp(suffix=".tgz")
    os.close(fd)
    try:
        async with httpx.AsyncClient(headers=HEADERS, timeout=httpx.Timeout(300, connect=20),
                                     follow_redirects=True) as c:
            async with c.stream("GET", f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}") as r:
                r.raise_for_status()
                with open(tmp, "wb") as f:
                    async for chunk in r.aiter_bytes(1 << 16):
                        f.write(chunk)
        rows = await asyncio.to_thread(_extract, tmp, repo, branch)
    finally:
        os.unlink(tmp)

    def store() -> None:
        conn = _connect()
        with conn:  # one transaction: readers never see a half-replaced repo
            conn.execute("DELETE FROM docs WHERE repo = ?", (repo,))
            conn.executemany("INSERT INTO docs(repo, path, url, body) VALUES (?, ?, ?, ?)", rows)
            conn.execute("INSERT OR REPLACE INTO meta(repo, synced, files) VALUES (?, ?, ?)",
                         (repo, time.time(), len(rows)))
        conn.close()

    await asyncio.to_thread(store)
    return len(rows)


async def sync_due() -> dict[str, str]:
    """Re-download repos older than a week (or never synced). Returns {repo: "ok" | error text}."""
    conn = _connect()
    synced = dict(conn.execute("SELECT repo, synced FROM meta").fetchall())
    conn.close()
    out = {}
    for repo, branch in REPOS:
        if time.time() - synced.get(repo, 0) < MAX_AGE:
            continue
        try:
            out[repo] = f"{await sync_repo(repo, branch)} file"
        except Exception as e:  # one broken repo must not stop the others
            out[repo] = f"lỗi: {type(e).__name__}"
    return out


def status() -> dict[str, int]:
    conn = _connect()
    rows = dict((r, n) for r, n in conn.execute("SELECT repo, files FROM meta"))
    conn.close()
    return rows


def _match_expr(groups: list[set[str]]) -> str:
    """FTS query: every group must match; a group is an OR of synonyms ("403" or "forbidden")."""
    def term(w: str) -> str:
        return '"' + w.replace('"', "") + '"'
    return " AND ".join("(" + " OR ".join(term(w) for w in sorted(g)) + ")" for g in groups)


def _is_link_list(para: str) -> bool:
    lines = [ln for ln in para.splitlines() if ln.strip()]
    links = sum(ln.count("](") + ln.count("](#") for ln in lines)
    bullets = sum(1 for ln in lines if re.match(r"\s*[-*] ", ln))
    return links >= 3 or (bullets and links >= bullets)


def search(groups: list[set[str]], core: list[set[str]], limit: int = 6) -> list[dict]:
    """Best paragraph per file. `core` must all appear in the same paragraph (codes may be optional)."""
    if not groups or not db_path().exists():
        return []
    conn = _connect()
    try:
        # short queries need every word; longer ones may skip the code ("403") since docs write "4xx" too
        fts = groups if len(groups) <= 2 else core
        rows = conn.execute("SELECT repo, path, url, body FROM docs WHERE docs MATCH ? "
                            "ORDER BY bm25(docs) LIMIT 80", (_match_expr(fts),)).fetchall()
    finally:
        conn.close()
    from .deep import group_hits  # local import: deep imports this module
    out = []
    for repo, path, url, body in rows:
        best, best_hits = None, 0
        for para in re.split(r"\n\s*\n", body):
            if _is_link_list(para):  # table of contents and link lists match words but explain nothing
                continue
            hits = group_hits(para, core)
            if hits == len(core) and len(para) > 20:
                full = group_hits(para, groups)
                if best is None or full > best_hits:
                    best, best_hits = para, full
        if best is not None:
            out.append({"repo": repo, "path": path, "url": url, "paragraph": best})
        if len(out) >= limit:
            break
    return out
