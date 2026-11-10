"""Threat-intel & news lookups from free public APIs (metadata only, no leaked data)."""
import asyncio
import calendar
import html
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, quote_plus

import feedparser
import httpx

from .fetcher import HEADERS, clean_text

RL_API = "https://api.ransomware.live/v2"
HIBP_API = "https://haveibeenpwned.com/api/v3/breaches"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
HN_API = "https://hn.algolia.com/api/v1/search"


class RateLimited(Exception):
    pass


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(headers=HEADERS, timeout=30, follow_redirects=True)


async def _get_json(url: str, **params):
    async with _client() as c:
        r = await c.get(url, params=params or None)
    if r.status_code in (403, 429):
        raise RateLimited(f"{httpx.URL(url).host} đang giới hạn truy cập, thử lại sau")
    r.raise_for_status()
    return r.json()


def _ts(s: str | None) -> int:
    if not s:
        return int(time.time())
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())
    except ValueError:
        return int(time.time())


def word_re(query: str) -> re.Pattern:
    return re.compile(r"(?<![a-z0-9])" + re.escape(query.lower()) + r"(?![a-z0-9])", re.IGNORECASE)


class _Cache:
    """Tiny in-memory TTL cache for big, slow-changing datasets (HIBP list, KEV)."""

    def __init__(self, ttl: int):
        self.ttl, self.value, self.at, self.lock = ttl, None, 0.0, asyncio.Lock()

    async def get(self, loader, max_age: int | None = None):
        async with self.lock:
            if self.value is None or time.time() - self.at > (self.ttl if max_age is None else max_age):
                self.value, self.at = await loader(), time.time()
            return self.value


# ---------- Google News ----------
async def search_news(query: str, lang: str = "vi", limit: int = 8) -> list[dict]:
    hl, gl, ceid = {"vi": ("vi", "VN", "VN:vi"), "en": ("en-US", "US", "US:en")}[lang]
    url = f"https://news.google.com/rss/search?q={quote_plus(query)}&hl={hl}&gl={gl}&ceid={ceid}"
    async with _client() as c:
        r = await c.get(url)
        r.raise_for_status()
    items = []
    for e in feedparser.parse(r.content).entries[:20]:
        title = clean_text(e.get("title", ""))
        source = e.get("source", {}).get("title", "Google News")
        if title.endswith(f" - {source}"):
            title = title[: -len(source) - 3]
        ts = e.get("published_parsed")
        items.append({"title": title, "url": e.get("link", ""), "source": source,
                      "published": calendar.timegm(ts) if ts else int(time.time())})
    # Google ranks by relevance; keep its top 20 but show the newest first.
    return sorted(items, key=lambda n: n["published"], reverse=True)[:limit]


# ---------- ransomware.live (leak-site tracker) ----------
async def _rl_get(path: str) -> list[dict]:
    data = await _get_json(f"{RL_API}/{path}")
    if isinstance(data, dict):  # e.g. {"message": "1 per 1 minute"}
        raise RateLimited(f"ransomware.live: {data.get('message', data)}")
    return data


def _victim(v: dict) -> dict:
    return {
        "victim": v.get("victim") or v.get("post_title") or "?",
        "domain": "" if (v.get("domain") or "").lower() in ("", "not found", "n/a") else v["domain"],
        "group": v.get("group") or v.get("group_name") or "?",
        "country": v.get("country") or "",
        "activity": v.get("activity") or "",
        "description": (v.get("description") or "").removeprefix("[AI generated]").strip(),
        "discovered": _ts(v.get("discovered")),
        "url": v.get("url") or "",
    }


async def search_ransomware(query: str) -> list[dict]:
    """Victims whose name/domain contains `query` as a whole word (the API does substring matching)."""
    word = word_re(query)
    victims = [_victim(v) for v in await _rl_get(f"searchvictims/{quote(query)}")]
    victims = [v for v in victims if word.search(f"{v['victim']} {v['domain']}")]
    return sorted(victims, key=lambda v: v["discovered"], reverse=True)


async def recent_ransomware() -> list[dict]:
    return [_victim(v) for v in await _rl_get("recentvictims")]


# ---------- HaveIBeenPwned (verified data breaches) ----------
_hibp = _Cache(6 * 3600)


def breach(b: dict) -> dict:
    return {
        "name": b["Name"], "title": b.get("Title") or b["Name"], "domain": b.get("Domain") or "",
        "breach_date": b.get("BreachDate") or "", "added": _ts(b.get("AddedDate")),
        "pwn_count": b.get("PwnCount") or 0, "data": b.get("DataClasses") or [],
        "description": clean_text(html.unescape(b.get("Description") or "")),
        "url": f"https://haveibeenpwned.com/PwnedWebsites#{b['Name']}",
    }


async def all_breaches(max_age: int | None = None) -> list[dict]:
    return await _hibp.get(lambda: _get_json(HIBP_API), max_age)


async def search_breaches(query: str) -> list[dict]:
    word = word_re(query)
    hits = [breach(b) for b in await all_breaches()
            if word.search(f"{b['Name']} {b.get('Title', '')} {b.get('Domain', '')}")]
    return sorted(hits, key=lambda b: b["breach_date"], reverse=True)


# ---------- CISA KEV (actively exploited vulnerabilities) ----------
_kev = _Cache(6 * 3600)


async def kev_catalog(max_age: int | None = None) -> dict[str, dict]:
    async def load():
        data = await _get_json(KEV_URL)
        return {v["cveID"]: v for v in data["vulnerabilities"]}
    return await _kev.get(load, max_age)


# ---------- NVD (CVE database) ----------
def _cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            return m["cvssData"]["baseScore"]
    return None


async def search_cves(query: str, days: int = 119) -> list[dict]:
    """CVEs published in the last `days` days whose description mentions `query`."""
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    data = await _get_json(NVD_API, keywordSearch=query, resultsPerPage=2000,
                           pubStartDate=(now - timedelta(days=days)).strftime(fmt), pubEndDate=now.strftime(fmt))
    kev, edb = await asyncio.gather(kev_catalog(), exploits_by_cve(), return_exceptions=True)
    kev = {} if isinstance(kev, Exception) else kev
    edb = {} if isinstance(edb, Exception) else edb
    out = []
    for v in data.get("vulnerabilities", []):
        c = v["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        out.append({"id": c["id"], "published": _ts(c.get("published")), "score": _cvss(c.get("metrics", {})),
                    "description": desc, "kev": c["id"] in kev, "exploits": edb.get(c["id"], []),
                    "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}"})
    # Actively exploited first, then those with a public exploit, then most severe, then newest.
    return sorted(out, key=lambda x: (not x["kev"], not x["exploits"], -(x["score"] or 0), -x["published"]))


# ---------- Hacker News (community discussion) ----------
async def search_hn(query: str, limit: int = 5, days: int = 730) -> list[dict]:
    since = int(time.time()) - days * 86400
    data = await _get_json(HN_API, query=query, tags="story", hitsPerPage=30,
                           typoTolerance="false", numericFilters=f"created_at_i>{since}")
    # Algolia still does prefix/fuzzy matching (FPT -> FPGA); require every word in the title.
    words = [word_re(w) for w in query.split()]
    hits = [h for h in data.get("hits", []) if all(w.search(h.get("title") or "") for w in words)]
    return [{
        "title": h.get("title") or "", "points": h.get("points") or 0, "comments": h.get("num_comments") or 0,
        "published": h.get("created_at_i") or 0, "url": h.get("url") or "",
        "hn_url": f"https://news.ycombinator.com/item?id={h['objectID']}",
    } for h in hits[:limit]]


# ---------- Hudson Rock (infostealer exposure; aggregate stats only) ----------
HR_API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"


async def search_infostealer(domain: str) -> dict | None:
    """How many credentials for `domain` appear in infostealer logs (counts and dates, no secrets)."""
    d = await _get_json(HR_API, domain=domain)
    if not d.get("total"):
        return None
    return {
        "domain": domain, "total": d.get("total", 0), "employees": d.get("employees", 0),
        "users": d.get("users", 0), "third_parties": d.get("third_parties", 0),
        "last_employee": _ts(d["last_employee_compromised"]) if d.get("last_employee_compromised") else None,
        "last_user": _ts(d["last_user_compromised"]) if d.get("last_user_compromised") else None,
        "url": f"https://www.hudsonrock.com/search/domain/{domain}",
    }


# ---------- crt.sh (Certificate Transparency: lookalike / phishing domains) ----------
async def search_lookalikes(keyword: str, days: int = 30) -> list[dict]:
    """Hostnames containing `keyword` that got a TLS certificate in the last `days` days."""
    async with httpx.AsyncClient(headers=HEADERS, timeout=45, follow_redirects=True) as c:
        r = await c.get("https://crt.sh/", params={"q": f"%{keyword}%", "output": "json",
                                                   "exclude": "expired", "deduplicate": "Y"})
    if r.status_code >= 500:
        raise RateLimited("crt.sh quá tải (từ khóa ngắn khớp quá nhiều domain), thử từ khóa dài hơn")
    r.raise_for_status()
    since = time.time() - days * 86400
    hosts: dict[str, int] = {}
    for row in r.json():
        issued = _ts(row.get("not_before"))
        if issued < since:
            continue
        for name in row.get("name_value", "").lower().split("\n"):
            name = name.removeprefix("*.")
            if keyword.lower() in name:
                hosts[name] = max(hosts.get(name, 0), issued)
    return [{"host": h, "issued": t} for h, t in sorted(hosts.items(), key=lambda x: -x[1])]


# ---------- GDELT (global news, 100+ languages) ----------
_gdelt_lock = asyncio.Lock()
_gdelt_last = 0.0


async def search_gdelt(query: str, limit: int = 8) -> list[dict]:
    global _gdelt_last
    async with _gdelt_lock:  # GDELT allows one request every 5 seconds
        await asyncio.sleep(max(0.0, 5.5 - (time.time() - _gdelt_last)))
        _gdelt_last = time.time()
        async with _client() as c:
            r = await c.get("https://api.gdeltproject.org/api/v2/doc/doc", params={
                "query": query, "mode": "artlist", "format": "json", "maxrecords": limit,
                "sort": "datedesc", "timespan": "3m"})
    if r.status_code == 429 or not r.text.lstrip().startswith("{"):
        raise RateLimited("GDELT đang giới hạn tần suất, thử lại sau")
    r.raise_for_status()
    out = []
    for a in r.json().get("articles", []):
        seen = a.get("seendate", "")
        try:
            ts = calendar.timegm(time.strptime(seen, "%Y%m%dT%H%M%SZ"))
        except ValueError:
            ts = int(time.time())
        out.append({"title": a.get("title", ""), "url": a.get("url", ""), "published": ts,
                    "source": f"{a.get('domain', '')} · {a.get('language', '')}"})
    return out


# ---------- GitHub Security Advisories ----------
async def search_ghsa(keyword: str, limit: int = 5) -> list[dict]:
    data = await _get_json("https://api.github.com/advisories", keyword=keyword, per_page=50,
                           sort="published", direction="desc")
    word = word_re(keyword)
    out = []
    for a in data:
        pkgs = [v["package"]["name"] for v in a.get("vulnerabilities") or [] if v.get("package")]
        # GitHub's keyword search is loose; keep advisories that really mention the keyword.
        if not word.search(f"{a.get('summary', '')} {a.get('description', '')} {' '.join(pkgs)}"):
            continue
        out.append({"id": a["ghsa_id"], "cve": a.get("cve_id"), "summary": a.get("summary", ""),
                    "severity": a.get("severity") or "?", "published": _ts(a.get("published_at")),
                    "packages": pkgs, "url": a["html_url"]})
    return out[:limit]


# ---------- Exploit-DB (public exploits) ----------
EDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
_edb = _Cache(24 * 3600)


async def exploitdb() -> list[dict]:
    async def load():
        import csv
        import io
        async with httpx.AsyncClient(headers=HEADERS, timeout=90, follow_redirects=True) as c:
            r = await c.get(EDB_CSV)
            r.raise_for_status()
        return [{"id": row["id"], "title": row["description"], "date": row["date_published"],
                 "type": row["type"], "platform": row["platform"],
                 "cves": [x for x in row["codes"].split(";") if x.startswith("CVE-")],
                 "url": f"https://www.exploit-db.com/exploits/{row['id']}"}
                for row in csv.DictReader(io.StringIO(r.text))]
    return await _edb.get(load)


async def exploits_by_cve() -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for e in await exploitdb():
        for cve in e["cves"]:
            idx.setdefault(cve, []).append(e)
    return idx


async def search_exploits(keyword: str, limit: int = 5) -> list[dict]:
    words = [word_re(w) for w in keyword.split()]
    hits = [e for e in await exploitdb() if all(w.search(e["title"]) for w in words)]
    return sorted(hits, key=lambda e: e["date"], reverse=True)[:limit]
