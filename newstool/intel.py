"""Threat-intel & news lookups from free public APIs (metadata only, no leaked data)."""
import asyncio
import calendar
import collections
import html
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, quote, quote_plus, urlparse

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


async def _get_json(url: str, headers: dict | None = None, **params):
    async with _client() as c:
        r = await c.get(url, params=params or None, headers=headers)
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
_google_lock = asyncio.Lock()
_google_last = 0.0


async def search_news(query: str, lang: str = "vi", limit: int = 8) -> list[dict]:
    global _google_last
    hl, gl, ceid = {"vi": ("vi", "VN", "VN:vi"), "en": ("en-US", "US", "US:en")}[lang]
    url = f"https://news.google.com/rss/search?q={quote_plus(query)}&hl={hl}&gl={gl}&ceid={ceid}"
    async with _google_lock:  # Google News answers 429 to bursts: space requests out a little
        await asyncio.sleep(max(0.0, 1.2 - (time.time() - _google_last)))
        _google_last = time.time()
        async with _client() as c:
            r = await c.get(url)
    if r.status_code in (429, 503):
        raise RateLimited("Google News đang giới hạn tần suất, thử lại sau vài phút")
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


# ---------- Bing News (different index from Google, often faster for niche/tech news) ----------
async def search_bing(query: str, limit: int = 8) -> list[dict]:
    async with _client() as c:
        r = await c.get("https://www.bing.com/news/search", params={"q": query, "format": "rss", "mkt": "en-US"})
        r.raise_for_status()
    items = []
    for e in feedparser.parse(r.content).entries:
        link = e.get("link", "")
        # Bing wraps links in a click tracker; the real article is in the `url` parameter.
        url = parse_qs(urlparse(link).query).get("url", [link])[0]
        ts = e.get("published_parsed")
        items.append({"title": clean_text(e.get("title", "")), "url": url,
                      "source": e.get("news_source") or urlparse(url).netloc or "Bing",
                      "published": calendar.timegm(ts) if ts else int(time.time())})
    return sorted(items, key=lambda n: n["published"], reverse=True)[:limit]


# ---------- general web search (Bing web results as RSS, no key) ----------
async def search_web(query: str, limit: int = 10) -> list[dict]:
    """Web pages (blogs, docs, write-ups), not only news. Uses Brave Search when BRAVE_API_KEY is set
    (free key at brave.com/search/api, real site: operators), otherwise Bing RSS. published = 0 (no date)."""
    key = os.environ.get("BRAVE_API_KEY", "").strip()
    if key:
        async with _client() as c:
            r = await c.get("https://api.search.brave.com/res/v1/web/search",
                            params={"q": query, "count": min(limit, 20)},
                            headers={"X-Subscription-Token": key, "Accept": "application/json"})
        if r.status_code in (401, 403, 429):
            raise RateLimited("Brave Search từ chối (sai khóa hoặc hết lượt)")
        r.raise_for_status()
        items = [{"title": clean_text(x.get("title", "")), "url": x.get("url", ""),
                  "source": urlparse(x.get("url", "")).netloc.removeprefix("www."),
                  "summary": clean_text(x.get("description", ""))[:400], "published": 0}
                 for x in (r.json().get("web") or {}).get("results", [])]
        return [i for i in items if i["url"].startswith("http")][:limit]
    async with _client() as c:
        r = await c.get("https://www.bing.com/search", params={"q": query, "format": "rss", "setlang": "en"})
        r.raise_for_status()
    out = []
    for e in feedparser.parse(r.content).entries:
        link = e.get("link", "")
        host = urlparse(link).netloc.removeprefix("www.")
        if not link.startswith("http") or host.endswith("bing.com"):
            continue
        out.append({"title": clean_text(e.get("title", "")), "url": link, "source": host,
                    "summary": clean_text(e.get("description", ""))[:400], "published": 0})
    return out[:limit]


_DDG_TITLE = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_DDG_SNIPPET = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.S)


async def search_ddg(query: str, limit: int = 10) -> list[dict]:
    """Second web engine (DuckDuckGo HTML). It throttles scripted use quickly, so callers treat errors as optional."""
    async with httpx.AsyncClient(headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                 timeout=20, follow_redirects=True) as c:
        r = await c.get("https://html.duckduckgo.com/html/", params={"q": query})
    if r.status_code != 200 or "result__a" not in r.text:
        raise RateLimited("DuckDuckGo đang giới hạn truy cập, thử lại sau")
    snippets = _DDG_SNIPPET.findall(r.text)
    out = []
    for i, (href, title) in enumerate(_DDG_TITLE.findall(r.text)):
        target = parse_qs(urlparse(html.unescape(href)).query).get("uddg", [""])[0]
        if not target.startswith("http") or "duckduckgo.com" in target:
            continue
        out.append({"title": clean_text(title), "url": target, "source": urlparse(target).netloc.removeprefix("www."),
                    "summary": clean_text(snippets[i])[:400] if i < len(snippets) else "", "published": 0})
        if len(out) >= limit:
            break
    return out


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
        "description": "" if (v.get("description") or "").strip().lower() in ("not found", "n/a") else
        (v.get("description") or "").removeprefix("[AI generated]").strip(),
        "discovered": _ts(v.get("discovered")),
        "url": v.get("url") or "",
    }


async def search_ransomware(query: str) -> list[dict]:
    """Victims whose name/domain contains `query` as a whole word (the API does substring matching)."""
    word = word_re(query)
    try:
        raw = await _rl_get(f"searchvictims/{quote(query)}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:  # the API answers 404 when nothing matches
            return []
        raise
    victims = [_victim(v) for v in raw]
    victims = [v for v in victims if word.search(f"{v['victim']} {v['domain']}")]
    return sorted(victims, key=lambda v: v["discovered"], reverse=True)


async def recent_ransomware() -> list[dict]:
    return [_victim(v) for v in await _rl_get("recentvictims")]


# Ransomware group profiles (ransomware.live). Onion addresses are deliberately never returned.
_rl_groups = _Cache(24 * 3600)


async def ransomware_groups() -> dict[str, dict]:
    async def load():
        return {g["name"].lower(): g for g in await _rl_get("groups") if g.get("name")}
    return await _rl_groups.get(load)


def _listish(v):
    """ransomware.live returns some nested fields as Python-repr strings."""
    if isinstance(v, str) and v[:1] in "[{":
        import ast
        try:
            return ast.literal_eval(v)
        except (ValueError, SyntaxError):
            return []
    return v or []


_rlook_groups = _Cache(24 * 3600)


async def group_names() -> set[str]:
    """Known ransomware group names (ransomware.live, falling back to RansomLook when rate-limited)."""
    try:
        return set(await ransomware_groups())
    except Exception:
        return {g.lower() for g in await _rlook_groups.get(lambda: _get_json(f"{RANSOMLOOK}/groups"))}


async def ransomware_group(name: str) -> dict | None:
    g = (await ransomware_groups()).get(name.lower())
    if not g:
        return None
    tools = {}
    for block in _listish(g.get("tools")):
        if isinstance(block, dict):
            for cat, names in block.items():
                tools.setdefault(cat, []).extend(names if isinstance(names, list) else [names])
    tactics = [t.get("tactic_name") for t in _listish(g.get("ttps")) if isinstance(t, dict) and t.get("tactic_name")]
    sites = [x for x in _listish(g.get("locations")) if isinstance(x, dict)]
    try:
        victims = [_victim(v) for v in await _rl_get(f"groupvictims/{quote(g['name'])}")]
    except Exception:
        victims = []
    victims.sort(key=lambda v: -v["discovered"])
    countries = collections.Counter(v["country"] for v in victims if v["country"])
    desc = clean_text(re.sub(r"<[^>]+>", " ", g.get("description") or ""))
    return {"name": g["name"], "description": desc,
            "first_seen": g.get("added_date") or "", "tools": tools, "tactics": tactics,
            "sites_total": len(sites), "sites_up": sum(1 for x in sites if x.get("available")),
            "victims_total": len(victims), "victims": victims[:5], "countries": countries.most_common(5),
            "vn_victims": [v for v in victims if v["country"] == "VN"][:5],
            "url": g.get("url") or f"https://www.ransomware.live/group/{quote(g['name'])}"}


# ---------- RansomLook (dark-web tracker): index of leaked databases, metadata only ----------
RANSOMLOOK = "https://www.ransomlook.io/api"
_rlook_leaks = _Cache(24 * 3600)


async def search_leak_index(names: list[str], limit: int = 5) -> list[dict]:
    """Leaked databases whose name matches the organisation (size, record count, column names: no data)."""
    index = await _rlook_leaks.get(lambda: _get_json(f"{RANSOMLOOK}/leaks/leaks"))
    pats = [re.compile(rf"(^|[.\-_ ]){re.escape(n.lower())}([.\-_ ]|$)") for n in names if n]
    hits = [x for x in index if any(p.search(x["name"].lower()) for p in pats)][:limit]
    details = await asyncio.gather(*(_get_json(f"{RANSOMLOOK}/leaks/leaks/{x['id']}") for x in hits),
                                   return_exceptions=True)
    out = []
    for x, d in zip(hits, details):
        d = d if isinstance(d, dict) else {}
        out.append({"name": x["name"], "size": d.get("size") or "?", "records": d.get("records") or "?",
                    "columns": d.get("columns") or [], "indexed": d.get("indexed") or "",
                    "url": f"https://www.ransomlook.io/leak/{x['id']}"})
    return out


# ---------- Dark-web reporting sites (news about leak sites, forums, markets) via Google News ----------
DARKWEB_SITES = ["darkwebinformer.com", "dailydarkweb.net", "databreaches.net", "hackread.com", "cybernews.com",
                 "ransomware.live", "dexpose.io", "hackmanac.com"]


async def search_darkweb_news(query: str, limit: int = 10) -> list[dict]:
    sites = " OR ".join(f"site:{s}" for s in DARKWEB_SITES)
    return await search_news(f"{query} ({sites})", "en", limit)


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


# ---------- GitHub (advisories, repositories) ----------
def gh_headers() -> dict:
    """Optional GITHUB_TOKEN (no scopes needed) raises the API limit from 60 to 5000 requests/hour."""
    token = (os.environ.get("GITHUB_TOKEN") or "").strip()
    h = {"Accept": "application/vnd.github+json"}
    return h | {"Authorization": f"Bearer {token}"} if token else h


def _ghsa(a: dict) -> dict:
    vulns = [v for v in a.get("vulnerabilities") or [] if v.get("package")]
    return {"id": a["ghsa_id"], "cve": a.get("cve_id"), "summary": a.get("summary", ""),
            "severity": a.get("severity") or "?", "published": _ts(a.get("published_at")),
            "packages": [v["package"]["name"] for v in vulns], "url": a["html_url"],
            "fixes": [{"package": f"{v['package'].get('ecosystem', '')}/{v['package']['name']}",
                       "vulnerable": v.get("vulnerable_version_range") or "?",
                       "patched": v.get("first_patched_version") or "chưa có"} for v in vulns],
            "references": a.get("references") or []}


async def ghsa_by_cve(cve: str) -> list[dict]:
    return [_ghsa(a) for a in await _get_json("https://api.github.com/advisories", headers=gh_headers(),
                                              cve_id=cve, per_page=10)]


async def search_repos(query: str, limit: int = 6, sort: str = "stars") -> list[dict]:
    data = await _get_json("https://api.github.com/search/repositories", headers=gh_headers(),
                           q=query, sort=sort, order="desc", per_page=30)
    return [{"name": r["full_name"], "description": (r.get("description") or "")[:160],
             "stars": r.get("stargazers_count", 0), "updated": _ts(r.get("pushed_at")), "url": r["html_url"]}
            for r in data.get("items", [])][:limit]


async def search_ghsa(keyword: str, limit: int = 5) -> list[dict]:
    data = await _get_json("https://api.github.com/advisories", headers=gh_headers(), keyword=keyword,
                           per_page=50, sort="published", direction="desc")
    word = word_re(keyword)
    out = []
    for a in data:
        pkgs = [v["package"]["name"] for v in a.get("vulnerabilities") or [] if v.get("package")]
        # GitHub's keyword search is loose; keep advisories that really mention the keyword.
        if not word.search(f"{a.get('summary', '')} {a.get('description', '')} {' '.join(pkgs)}"):
            continue
        out.append(_ghsa(a))
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
