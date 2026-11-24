"""Lesser-known but very useful free sources (no API key needed).

Vulnerabilities: Shodan CVEDB, nomi-sec PoC-in-GitHub, Metasploit module index, Sploitus, AlienVault OTX.
Threat actors / malware: MISP Galaxy clusters (threat actors, Malpedia families, ransomware), ransomwhe.re payments.
Brand abuse: urlscan.io, OpenPhish.
Big datasets are reduced to small indexes and cached in memory; onion links are never kept.
"""
import asyncio
import collections
import html
import re
import time
from datetime import datetime

import httpx
import yaml

from .fetcher import HEADERS
from .intel import RateLimited, _Cache, _get_json, _ts, kev_catalog
from .query import fold

SHODAN_CVEDB = "https://cvedb.shodan.io"
NOMISEC = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
MSF_META = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
MSF_RANK = {600: "excellent", 500: "great", 400: "good", 300: "normal", 200: "average", 100: "low", 0: "manual"}
MISP = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{name}.json"
OTX = "https://otx.alienvault.com/api/v1/indicators"


def _client(timeout: float = 40) -> httpx.AsyncClient:
    return httpx.AsyncClient(headers=HEADERS, timeout=timeout, follow_redirects=True)


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


# ---------- Shodan CVEDB: EPSS ranking, KEV, ransomware use, CISA action, CPEs; product-wide search ----------
async def shodan_cve(cve: str) -> dict | None:
    async with _client() as c:
        r = await c.get(f"{SHODAN_CVEDB}/cve/{cve}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    d = r.json()
    return {"propose_action": d.get("propose_action") or "", "ransomware": d.get("ransomware_campaign") == "Known",
            "cpes": d.get("cpes") or [], "euvd": (d.get("euvd") or {}).get("id"),
            "ranking_epss": d.get("ranking_epss"), "epss": d.get("epss")}


async def shodan_top_cves(names: list[str], limit: int = 8) -> list[dict]:
    """Most likely exploited CVEs of a vendor/product, all time (EPSS order, KEV flagged)."""
    seen: dict[str, dict] = {}
    async with _client() as c:
        for name in dict.fromkeys(n for n in names if n):
            for key in ("vendor", "product"):
                r = await c.get(f"{SHODAN_CVEDB}/cves", params={key: name, "sort_by_epss": "true", "limit": 40})
                if r.status_code != 200:
                    continue
                for v in r.json().get("cves", []):
                    seen.setdefault(v["cve_id"], {
                        "id": v["cve_id"], "epss": v.get("epss") or 0, "kev": bool(v.get("kev")),
                        "score": v.get("cvss_v3") or v.get("cvss"), "summary": v.get("summary") or "",
                        "published": _ts(v.get("published_time")), "ransomware": v.get("ransomware_campaign") == "Known",
                        "url": f"https://nvd.nist.gov/vuln/detail/{v['cve_id']}"})
            if seen:
                break  # first name that matches is enough (vendor "fortinet", product "exchange_server"...)
    return sorted(seen.values(), key=lambda x: (-x["epss"], not x["kev"]))[:limit]


async def kev_by_vendor(name: str, limit: int = 8) -> dict:
    """A vendor's/product's vulnerabilities confirmed exploited in the wild (CISA KEV) + their EPSS scores."""
    word = re.compile(r"(?<![a-z0-9])" + re.escape(name.lower()) + r"(?![a-z0-9])", re.I)
    hits = [{"id": cve, "product": f"{v['vendorProject']} {v['product']}", "name": v.get("vulnerabilityName", ""),
             "added": v.get("dateAdded", ""), "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
             "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
            for cve, v in (await kev_catalog()).items()
            if word.search(f"{v['vendorProject']} {v['product']}")]
    hits.sort(key=lambda h: h["added"], reverse=True)
    if hits:  # one batched EPSS call for the most recent ones
        try:
            data = await _get_json("https://api.first.org/data/v1/epss", cve=",".join(h["id"] for h in hits[:60]))
            scores = {d["cve"]: float(d["epss"]) for d in data.get("data", [])}
        except Exception:
            scores = {}
        for h in hits:
            h["epss"] = scores.get(h["id"])
    return {"total": len(hits), "ransomware": sum(h["ransomware"] for h in hits), "items": hits[:limit]}


# ---------- nomi-sec PoC-in-GitHub: every public GitHub PoC for a CVE, with stars ----------
async def nomisec_pocs(cve: str) -> list[dict]:
    async with _client(60) as c:
        r = await c.get(NOMISEC.format(year=cve.split("-")[1], cve=cve))
    if r.status_code == 404:
        return []
    r.raise_for_status()
    out = [{"name": p.get("full_name", ""), "url": p.get("html_url", ""), "stars": p.get("stargazers_count") or 0,
            "description": (p.get("description") or "")[:160], "created": _ts(p.get("created_at")),
            "pushed": _ts(p.get("pushed_at"))} for p in r.json()]
    return sorted(out, key=lambda p: -p["stars"])


# ---------- Metasploit: is there a weaponised module? ----------
_msf = _Cache(24 * 3600)


async def _msf_index() -> dict:
    async def load():
        async with _client(120) as c:
            r = await c.get(MSF_META)
            r.raise_for_status()
        by_cve: dict[str, list[dict]] = {}
        modules = []
        for key, m in r.json().items():  # ~11 MB: keep only a compact index
            mod = {"name": m.get("name", ""), "type": m.get("type", ""), "rank": MSF_RANK.get(m.get("rank"), ""),
                   "disclosed": m.get("disclosure_date") or "", "check": bool(m.get("check")),
                   "url": "https://github.com/rapid7/metasploit-framework/blob/master" + (m.get("path") or "")}
            modules.append(mod)
            for ref in m.get("references") or []:
                if ref.startswith("CVE-"):
                    by_cve.setdefault(ref, []).append(mod)
        return {"by_cve": by_cve, "modules": modules}
    return await _msf.get(load)


async def metasploit(cve: str) -> list[dict]:
    return (await _msf_index())["by_cve"].get(cve.upper(), [])


async def metasploit_search(keyword: str, limit: int = 6) -> list[dict]:
    word = re.compile(r"(?<![a-z0-9])" + re.escape(keyword.lower()) + r"(?![a-z0-9])", re.I)
    hits = [m for m in (await _msf_index())["modules"] if m["type"] == "exploit" and word.search(m["name"])]
    return sorted(hits, key=lambda m: m["disclosed"], reverse=True)[:limit]


# ---------- Sploitus: exploit search engine (GitHub, Packet Storm, Exploit-DB, Kitploit, 0day sites...) ----------
async def sploitus(query: str, limit: int = 10) -> dict:
    async with _client() as c:
        r = await c.post("https://sploitus.com/search", json={"type": "exploits", "sort": "default", "query": query,
                                                              "title": False, "offset": 0},
                         headers={"Content-Type": "application/json", "Referer": "https://sploitus.com/"})
    if r.status_code in (403, 429, 499):
        raise RateLimited("Sploitus đang giới hạn truy cập")
    r.raise_for_status()
    d = r.json()
    items = [{"title": e.get("title", ""), "url": e.get("href", ""), "type": e.get("type") or "?",
              "published": e.get("published") or "", "score": e.get("score")} for e in d.get("exploits", [])]
    return {"total": d.get("exploits_total") or len(items), "items": items[:limit]}


# ---------- AlienVault OTX: threat-intel reports (pulses) mentioning a CVE or a domain ----------
def _otx(d: dict) -> dict:
    pi = d.get("pulse_info") or {}
    rel = pi.get("related") or {}
    merged = collections.defaultdict(list)
    for src in ("alienvault", "other"):
        for k in ("adversary", "malware_families", "industries"):
            for v in (rel.get(src) or {}).get(k) or []:
                for part in str(v).split(", ") if k == "adversary" else [v]:
                    if part and part not in merged[k]:
                        merged[k].append(part)
    auto = re.compile(r"actively_exploited|^[\w-]+_[\w-]+\s*\|", re.I)  # machine-generated daily lists
    pulses = [{"name": p.get("name", ""), "url": f"https://otx.alienvault.com/pulse/{p['id']}",
               "created": _ts(p.get("created")), "countries": p.get("targeted_countries") or []}
              for p in sorted(pi.get("pulses") or [], key=lambda p: p.get("created") or "", reverse=True)
              if not auto.search(p.get("name", ""))]
    return {"count": pi.get("count") or 0, "adversaries": merged["adversary"], "malware": merged["malware_families"],
            "industries": merged["industries"], "pulses": pulses}


async def otx_cve(cve: str) -> dict:
    return _otx(await _get_json(f"{OTX}/cve/{cve}/general"))


async def otx_domain(domain: str) -> dict:
    return {**_otx(await _get_json(f"{OTX}/domain/{domain}/general")), "domain": domain}


# ---------- MISP Galaxy: threat actors, malware families (Malpedia), ransomware ----------
_misp: dict[str, _Cache] = {n: _Cache(24 * 3600) for n in ("threat-actor", "malpedia", "ransomware")}


async def _cluster(name: str) -> list[dict]:
    async def load():
        data = await _get_json(MISP.format(name=name))
        out = []
        for v in data.get("values", []):
            meta = v.get("meta") or {}
            out.append({"name": v.get("value", ""), "description": v.get("description") or "",
                        "synonyms": meta.get("synonyms") or [], "refs": meta.get("refs") or [],
                        "country": meta.get("country") or meta.get("cfr-suspected-state-sponsor") or "",
                        "victims": meta.get("cfr-suspected-victims") or [],
                        "targets": meta.get("cfr-target-category") or meta.get("targeted-sector") or [],
                        "incident": meta.get("cfr-type-of-incident") or meta.get("motive") or "",
                        "attribution": [a.split(":")[0] for a in meta.get("name-attribution") or []]})
        return out
    return await _misp[name].get(load)


GENERIC = re.compile(r"\b(stealer|infostealer|rat|loader|ransomware|backdoor|botnet|trojan|group|team|apt group|"
                     r"malware|locker|banker|wiper|miner|spyware)\b", re.I)


def _core(name: str) -> str:
    """"Lumma Stealer" -> "lumma", "LockBit Ransomware" -> "lockbit"."""
    name = re.sub(r"\(.*?\)", " ", name)  # "LockBit (Windows)" -> "LockBit"
    return _norm(GENERIC.sub(" ", name)) or _norm(name)


async def find_in_cluster(name: str, query: str) -> dict | None:
    q = _norm(query)
    if len(q) < 3:
        return None
    # Entries with a description first ("LockBit (Windows)" before an empty "LockBit (ELF)").
    entries = sorted(await _cluster(name), key=lambda e: not e["description"])
    for match in (_norm, _core):  # exact name/synonym first, then without generic words
        for entry in entries:
            if any(match(n) == (q if match is _norm else _core(query)) for n in [entry["name"], *entry["synonyms"]] if n):
                return entry
    return None


async def find_actor(query: str) -> dict | None:
    a = await find_in_cluster("threat-actor", query)
    if a:
        mitre = next((x for x in a["attribution"] if re.fullmatch(r"G\d{4}", x)), None)
        a = {**a, "mitre": f"https://attack.mitre.org/groups/{mitre}/" if mitre else "",
             "malpedia": f"https://malpedia.caad.fkie.fraunhofer.de/actor/{_norm(a['name'])}"}
    return a


async def find_malware(query: str) -> dict | None:
    return await find_in_cluster("malpedia", query)


# ---------- ransomwhe.re: ransom payments seen on-chain per family ----------
_payments = _Cache(24 * 3600)


async def ransom_payments(family: str) -> dict | None:
    async def load():
        async with _client(120) as c:
            r = await c.get("https://api.ransomwhe.re/export")
            r.raise_for_status()
        totals: dict[str, dict] = {}
        for addr in r.json().get("result", []):
            t = totals.setdefault(_norm(addr.get("family") or ""), {"family": addr.get("family"), "usd": 0.0,
                                                                     "payments": 0, "addresses": 0, "last": 0})
            t["addresses"] += 1
            for tx in addr.get("transactions") or []:
                t["usd"] += tx.get("amountUSD") or 0
                t["payments"] += 1
                t["last"] = max(t["last"], int(tx.get("time") or 0))
        return totals
    t = (await _payments.get(load)).get(_norm(family))
    return t if t and t["payments"] else None


# ---------- Brand abuse: phishing / scam pages ----------
async def urlscan_brand(brand: str, own: list[str], days: int = 60, limit: int = 8) -> list[dict]:
    """Recently scanned pages whose title or domain uses the brand but are not the organisation's own domains."""
    since = time.time() - days * 86400
    out, seen = [], set()
    async with _client() as c:
        for q in (f"page.title:{brand}", f"domain:{brand}*"):
            r = await c.get("https://urlscan.io/api/v1/search/", params={"q": q, "size": 100})
            if r.status_code in (403, 429):
                if not out and q.startswith("page.title"):
                    raise RateLimited("urlscan.io đang giới hạn truy cập")
                continue
            r.raise_for_status()
            for x in r.json().get("results", []):
                dom = (x.get("page") or {}).get("domain", "").lower()
                at = _ts((x.get("task") or {}).get("time"))
                if not dom or dom in seen or at < since or any(dom == o or dom.endswith("." + o) for o in own):
                    continue
                if brand.lower() not in dom and brand.lower() not in ((x.get("page") or {}).get("title") or "").lower():
                    continue
                seen.add(dom)
                out.append({"domain": dom, "url": (x.get("page") or {}).get("url", ""), "at": at,
                            "result": f"https://urlscan.io/result/{x.get('_id')}/",
                            "verdict": "malicious" if (x.get("verdicts") or {}).get("malicious") else ""})
    return sorted(out, key=lambda x: -x["at"])[:limit]


_openphish = _Cache(3600)


async def openphish_brand(brand: str) -> list[str]:
    """Live phishing URLs (OpenPhish community feed, refreshed hourly) that mention the brand."""
    async def load():
        async with _client() as c:
            r = await c.get("https://openphish.com/feed.txt")
            r.raise_for_status()
        return r.text.split()
    b = brand.lower()
    return [u for u in await _openphish.get(load) if b in u.lower()][:10]


def first_date(items: list[dict], key: str, not_before: int = 0) -> int | None:
    vals = [i[key] for i in items if i.get(key) and i[key] >= not_before]
    return min(vals) if vals else None


def iso_ts(s: str | None) -> int | None:
    if not s:
        return None
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


# ---------- Techniques (red team / blue team): MITRE ATT&CK ids + Atomic Red Team tests, LOLBAS, GTFOBins ----------
ATOMIC_INDEX = ("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/"
                "atomics/Indexes/Indexes-Markdown/index.md")
LOLBAS_YML = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/yml/OSBinaries/{name}.yml"
GTFO_RAW = "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/{name}"
SAFE_NAME = re.compile(r"[a-z0-9_+-]{3,40}")
_atomic = _Cache(24 * 3600)


async def attack_techniques() -> list[dict]:
    """~900 techniques from the Atomic Red Team index (small file, unlike the 55 MB ATT&CK STIX bundle)."""
    async def load():
        async with _client(60) as c:
            r = await c.get(ATOMIC_INDEX)
            r.raise_for_status()
        out, tactic, cur = [], "", None
        for line in r.text.splitlines():
            if line.startswith("# ") and not line.startswith("# All "):
                tactic, cur = line[2:].strip(), None
            elif line.startswith("- "):
                body = line[2:].lstrip("[").strip()
                m = re.match(r"(T\d{4}(?:\.\d{3})?) (.+)", body)
                if not m:
                    continue
                name = re.split(r"\]\(|\s\[CONTRIBUTE", m.group(2))[0].rstrip("] ").strip()
                cur = {"id": m.group(1), "name": name, "tactic": tactic, "tests": 0, "platforms": set(),
                       "url": f"https://attack.mitre.org/techniques/{m.group(1).replace('.', '/')}/",
                       "atomic": f"https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{m.group(1)}"}
                out.append(cur)
            elif line.startswith("  - Atomic Test") and cur:
                cur["tests"] += 1
                pm = re.search(r"\[([a-z, ]+)\]\s*$", line)
                if pm:
                    cur["platforms"].update(x.strip() for x in pm.group(1).split(",") if x.strip())
        for t in out:
            t["platforms"] = sorted(t["platforms"])
        return out
    return await _atomic.get(load)


async def attack_lookup(query: str, limit: int = 3) -> list[dict]:
    """By technique id (T1558.003) or by name words (kerberoasting, lateral movement)."""
    q = query.strip()
    techs = await attack_techniques()
    if re.fullmatch(r"(?i)t\d{4}(\.\d{3})?", q):
        return [t for t in techs if t["id"].lower() == q.lower()][:1]
    if len(q) < 4:
        return []
    word = re.compile(r"(?<![a-z0-9])" + re.escape(q.lower()) + r"(?![a-z0-9])")
    tactic = re.sub(r"\s+", "-", q.lower())  # "lateral movement" -> tactic "lateral-movement"
    if any(t["tactic"] == tactic for t in techs):
        hits = [t for t in techs if t["tactic"] == tactic]
    else:
        hits = [t for t in techs if word.search(t["name"].lower())]
    hits.sort(key=lambda t: (-t["tests"], t["id"]))
    return hits[:limit]


async def lolbas(name: str) -> dict | None:
    """Windows binaries abused by attackers (LOLBAS). Returns functions and categories only, not command lines."""
    stem = name.lower().removesuffix(".exe")
    if not SAFE_NAME.fullmatch(stem):
        return None
    async with _client() as c:
        r = await c.get(LOLBAS_YML.format(name=stem[:1].upper() + stem[1:]))
    if r.status_code == 404:
        return None
    r.raise_for_status()
    d = yaml.safe_load(r.text) or {}
    cmds = [x for x in d.get("Commands") or [] if isinstance(x, dict)]
    cats = list(dict.fromkeys(x.get("Category") for x in cmds if x.get("Category")))
    mitre = sorted({x.get("MitreID") for x in cmds if x.get("MitreID")})
    page = stem[:1].upper() + stem[1:]
    return {"name": d.get("Name") or name, "description": (d.get("Description") or "").strip(),
            "categories": cats, "mitre": mitre, "commands": len(cmds),
            "url": f"https://lolbas-project.github.io/lolbas/OSBinaries/{page}/"}


async def gtfobins(name: str) -> dict | None:
    """Linux binaries that allow shell/file read/write/privilege escalation (GTFOBins). Functions only."""
    stem = name.lower()
    if not SAFE_NAME.fullmatch(stem):
        return None
    async with _client() as c:
        r = await c.get(GTFO_RAW.format(name=stem))
    if r.status_code == 404:
        return None
    r.raise_for_status()
    m = re.match(r"---\s*\n(.*?)\n(?:---|\.\.\.)\s*(?:\n|$)", r.text, re.S)  # front matter ends with --- or ...
    funcs = ((yaml.safe_load(m.group(1)) if m else None) or {}).get("functions") or {}
    contexts = sorted({ctx for entries in funcs.values() for e in entries or [] for ctx in (e.get("contexts") or {})})
    return {"name": stem, "functions": sorted(funcs), "contexts": contexts,
            "url": f"https://gtfobins.org/gtfobins/{stem}/"}


# ---------- Technique explanations: paragraphs from the local knowledge index (see knowledge.py) ----------
TERM_STOP = {"the", "and", "how", "what", "with", "for", "cua", "la", "gi", "cach", "khong", "cac", "nhung",
             "ky", "thuat", "technique", "method", "tan", "cong", "khai", "thac", "vuot", "qua", "attack"}  # folded
# An HTTP status code also matches what it means, so "403 bypass" finds "access control bypass" pages.
CODE_SYNONYMS = {"301": ["301", "redirect"], "302": ["302", "redirect"], "307": ["307", "redirect"],
                 "401": ["401", "unauthorized", "authentication"], "403": ["403", "forbidden", "access control"],
                 "404": ["404", "not found"], "429": ["429", "rate limit"]}


def query_words(text: str) -> list[str]:
    """Core words of a technique query, accents removed; numbers stay (403 matters)."""
    words = re.findall(r"[\w+.-]+", fold(text).lower())
    return [w for w in words if len(w) >= 2 and w not in TERM_STOP] or words


def query_groups(text: str) -> list[set[str]]:
    """One group per core word: a text must hit most groups, so every word counts."""
    return [set(CODE_SYNONYMS.get(w, [w])) for w in query_words(text)]


def group_hits(text: str, groups: list[set[str]]) -> int:
    t = text.lower()
    return sum(1 for g in groups if any(re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", t) for w in g))


def matches_groups(text: str, groups: list[set[str]]) -> bool:
    """Most groups must appear (all of them for up to 3), so "403 bypass" never matches "XSS filter bypass"."""
    return bool(groups) and group_hits(text, groups) >= max(1, -(-len(groups) * 7 // 10))


def _window(text: str, terms: list[str], width: int = 170) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    pos = min((m.start() for w in terms for m in [re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", text.lower())] if m), default=0)
    start = max(0, pos - 60)
    snippet = text[start:start + width * 2].strip()
    return ("…" if start else "") + snippet + ("…" if start + width * 2 < len(text) else "")


async def knowledge_snippets(query: str, limit: int = 6) -> list[dict] | None:
    """Paragraphs from HackTricks, PayloadsAllTheThings, OWASP and others. None = index not built yet."""
    from . import knowledge
    if not knowledge.status():
        return None
    words = query_words(query)
    groups = query_groups(query)
    core = groups if len(groups) <= 2 else ([g for g in groups if not any(w.isdigit() for w in g)] or groups)
    hits = await asyncio.to_thread(knowledge.search, groups, core, limit)
    return [{"repo": h["repo"], "path": h["path"], "url": h["url"],
             "snippet": _window(h["paragraph"], words)} for h in hits]


async def stackexchange(query: str, limit: int = 3) -> list[dict]:
    """Security Stack Exchange questions (no key; ~300 requests/day per IP)."""
    async with _client() as c:
        r = await c.get("https://api.stackexchange.com/2.3/search/advanced",
                        params={"q": query, "site": "security", "sort": "relevance", "order": "desc",
                                "pagesize": 10, "filter": "withbody", "accepted": "True"})
    if r.status_code in (400, 402, 429, 502):
        raise RateLimited("Stack Exchange đang giới hạn truy cập")
    r.raise_for_status()
    out = []
    for it in r.json().get("items", [])[:limit]:
        body = re.sub(r"<[^>]+>", " ", it.get("body", ""))
        out.append({"title": html.unescape(it.get("title", "")), "url": it.get("link", ""),
                    "score": it.get("score", 0), "published": it.get("creation_date", 0),
                    "snippet": re.sub(r"\s+", " ", html.unescape(body)).strip()[:220]})
    return out
