"""Deep research on a vulnerability (CVE id or nickname: React2Shell, Log4Shell...), a threat actor (APT32),
a malware family (Lumma) or a ransomware group (Akira).

Every source is a free public API or public file; nothing is downloaded or executed, only linked.
"""
import asyncio
import collections
import html
import re
from urllib.parse import quote_plus, urlparse

import httpx

from . import deep
from .pipeline import RECENT
from .classify import CVE_RE, cves as find_cves
from .formatter import (SEV, ago, _date, format_exploit, format_gtfo, format_hn, format_item, format_lolbas,
                        format_news_line, format_technique)
from .intel import (NVD_API, RateLimited, _client, _get_json, exploits_by_cve, ghsa_by_cve, group_names, kev_catalog,
                    ransomware_group, search_bing, search_darkweb_news, search_exploits, search_ghsa, search_hn,
                    search_news, search_repos, search_web)
from .fetcher import clean_text
from .query import SEC_RE, Query, fold, rank

MITRE_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss"
CIRCL_SIGHTINGS = "https://vulnerability.circl.lu/api/sighting/"
TRICKEST = "https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve}.md"
NUCLEI_RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/{kind}/cves/{year}/{cve}.yaml"
NUCLEI_WEB = "https://github.com/projectdiscovery/nuclei-templates/blob/main/{kind}/cves/{year}/{cve}.yaml"

PATCH_TAGS = {"Patch", "Vendor Advisory", "Mitigation", "Release Notes"}
WRITEUP_TAGS = {"Exploit", "Technical Description", "Third Party Advisory", "Issue Tracking", "Press/Media Coverage"}
SIGHTING_TYPES = {"exploited": "bị khai thác", "published-proof-of-concept": "PoC công bố", "seen": "được nhắc tới"}


def is_cve(query: str) -> bool:
    return bool(CVE_RE.fullmatch(query.strip()))


# ---------- per-CVE sources ----------
def _severity(score: float | None) -> str:
    return "⚪" if score is None else "🔴" if score >= 9 else "🟠" if score >= 7 else "🟡" if score >= 4 else "🟢"


async def nvd_cve(cve: str) -> dict | None:
    data = await _get_json(NVD_API, cveId=cve)
    if not data.get("vulnerabilities"):
        return None
    c = data["vulnerabilities"][0]["cve"]
    metric = next((m for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
                   for m in c.get("metrics", {}).get(key, [])), None)
    cvss = metric["cvssData"] if metric else {}
    return {
        "description": next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), ""),
        "published": c.get("published"), "score": cvss.get("baseScore"), "vector": cvss.get("vectorString"),
        "severity": cvss.get("baseSeverity") or (metric or {}).get("baseSeverity"),
        "cwes": sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                        if d["value"].startswith("CWE-")}),
        "references": [{"url": r["url"], "tags": set(r.get("tags", []))} for r in c.get("references", [])],
    }


def _version(v: dict) -> str:
    start = v.get("version", "")
    start = "" if start in ("0", "*", "n/a", "unspecified") else start
    if v.get("lessThan"):
        return f"{start} → &lt;{v['lessThan']}" if start else f"&lt;{v['lessThan']}"
    if v.get("lessThanOrEqual") and v["lessThanOrEqual"] != start:
        return f"{start} → ≤{v['lessThanOrEqual']}" if start else f"≤{v['lessThanOrEqual']}"
    return start or "?"


async def mitre_cve(cve: str) -> dict | None:
    """The official CVE record: available before NVD enrichment, has affected versions from the vendor (CNA)."""
    async with _client() as c:
        r = await c.get(MITRE_API + cve)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    d = r.json()
    cna = d["containers"]["cna"]
    metric = next((m[k] for m in cna.get("metrics", []) + [m for a in d["containers"].get("adp", [])
                                                            for m in a.get("metrics", [])]
                   for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0") if k in m), {})
    ssvc = {k: v for a in d["containers"].get("adp", []) for m in a.get("metrics", [])
            if m.get("other", {}).get("type") == "ssvc" for o in m["other"]["content"].get("options", [])
            for k, v in o.items()}
    affected = []
    for a in cna.get("affected", []):
        versions = [_version(v) for v in a.get("versions", []) if v.get("status") == "affected"]
        name = " ".join(x for x in (a.get("vendor"), a.get("product")) if x and x != "n/a")
        affected.append(f"{html.escape(name or '?')}: {', '.join(versions[:6]) or 'xem advisory'}")
    return {
        "title": cna.get("title") or "",
        "description": next((x["value"] for x in cna.get("descriptions", []) if x.get("lang", "").startswith("en")), ""),
        "cna": d["cveMetadata"].get("assignerShortName", ""), "published": d["cveMetadata"].get("datePublished"),
        "state": d["cveMetadata"].get("state"), "score": metric.get("baseScore"), "vector": metric.get("vectorString"),
        "severity": metric.get("baseSeverity"), "ssvc": ssvc, "affected": affected,
        "cwes": sorted({x.get("cweId") or x.get("description", "") for p in cna.get("problemTypes", [])
                        for x in p.get("descriptions", []) if (x.get("cweId") or "CWE-" in x.get("description", ""))}),
        "references": [r["url"] for r in cna.get("references", [])],
    }


async def epss(cve: str) -> dict | None:
    data = (await _get_json(EPSS_API, cve=cve)).get("data") or []
    return {"epss": float(data[0]["epss"]), "percentile": float(data[0]["percentile"])} if data else None


async def circl_sightings(cve: str) -> dict:
    """Counts from CIRCL Vulnerability-Lookup (honeypots, Mastodon, Bluesky, Telegram, GitHub...) + recent posts."""
    async def count(kind: str) -> int:
        return (await _get_json(CIRCL_SIGHTINGS, vuln_id=cve, type=kind, per_page=1))["metadata"]["count"]

    kinds = list(SIGHTING_TYPES)
    # Some sightings carry whole articles (100 recent ones can weigh ~10 MB): fetch a small page, separately.
    *counts, recent = await asyncio.gather(*(count(k) for k in kinds),
                                           _get_json(CIRCL_SIGHTINGS, vuln_id=cve, per_page=20),
                                           return_exceptions=True)
    if any(isinstance(c, Exception) for c in counts):
        raise next(c for c in counts if isinstance(c, Exception))
    links, seen = [], set()
    for s in ([] if isinstance(recent, Exception) else recent.get("data", [])):
        src = s.get("source") or ""
        if src.startswith("http") and src not in seen and "shadowserver" not in src:
            seen.add(src)
            links.append({"url": src, "type": s.get("type", ""), "at": s.get("creation_timestamp", "")[:10],
                          "text": " ".join((s.get("content") or "").split())[:120]})
    return {"counts": dict(zip(kinds, counts)), "links": links, "url": f"https://vulnerability.circl.lu/vuln/{cve}"}


async def trickest(cve: str) -> dict:
    """Community-curated PoC/write-up index (github.com/trickest/cve)."""
    async with _client() as c:
        r = await c.get(TRICKEST.format(year=cve.split("-")[1], cve=cve))
    if r.status_code == 404:
        return {"references": [], "github": []}
    r.raise_for_status()
    out, section = {"references": [], "github": []}, None
    for line in r.text.splitlines():
        if line.startswith("#### "):
            section = {"#### Reference": "references", "#### Github": "github"}.get(line.strip())
        elif section and line.startswith("- http"):
            out[section].append(line[2:].strip())
    return out


async def nuclei(cve: str) -> str | None:
    """Link to the ProjectDiscovery Nuclei detection template, if one exists."""
    year = cve.split("-")[1]
    async with _client() as c:
        for kind in ("http", "network", "javascript"):
            r = await c.head(NUCLEI_RAW.format(kind=kind, year=year, cve=cve))
            if r.status_code == 200:
                return NUCLEI_WEB.format(kind=kind, year=year, cve=cve)
    return None


async def _kev(cve: str) -> dict | None:
    return (await kev_catalog()).get(cve)


async def _edb(cve: str) -> list[dict]:
    return (await exploits_by_cve()).get(cve, [])


# ---------- orchestration ----------
LOOKUP_TIMEOUT = 35  # seconds: one slow source must not hold the whole answer


async def _run(lookups: dict) -> dict:
    lookups = {k: asyncio.wait_for(v, LOOKUP_TIMEOUT) for k, v in lookups.items() if v is not None}
    return dict(zip(lookups, await asyncio.gather(*lookups.values(), return_exceptions=True)))


def _ok(res: dict, key: str, default=None):
    v = res.get(key)
    return default if isinstance(v, Exception) or v is None else v


def _texts(res: dict) -> list[str]:
    """One text per discovered item, to count which CVE ids a nickname is talked about with."""
    out = []
    for key in ("en", "bing", "vi", "hn", "tg", "repos", "ghsa", "exploits"):
        for x in _ok(res, key, []):
            out.append(" ".join(str(x.get(f, "")) for f in ("title", "summary", "description", "name", "cve", "url"))
                       + " " + " ".join(x.get("cves", []) if isinstance(x.get("cves"), list) else []))
    return out


def resolve(res: dict) -> list[tuple[str, int]]:
    """CVE ids ranked by how many independent results mention them (document frequency)."""
    freq = collections.Counter(c for t in _texts(res) for c in find_cves(t))
    if not freq:
        return []
    top = freq.most_common(1)[0][1]
    return [(c, n) for c, n in freq.most_common(6) if n >= max(2, top * 0.25)] or freq.most_common(1)


def _merge(*lists, limit: int = 8) -> list[dict]:
    seen, out = set(), []
    for x in sorted((x for lst in lists for x in lst), key=lambda n: -n["published"]):
        if x["url"] not in seen:
            seen.add(x["url"])
            out.append(x)
    return out[:limit]


async def profile_kind(name: str) -> tuple[str, dict | None] | None:
    """Is `name` a ransomware group, a threat actor or a malware family? (in that order of preference)"""
    groups, actor, malware = await asyncio.gather(*(asyncio.wait_for(c, 20) for c in (
        group_names(), deep.find_actor(name), deep.find_malware(name))), return_exceptions=True)
    if isinstance(groups, set) and name.lower() in groups:
        return "group", None
    if isinstance(actor, dict):
        return "actor", actor
    if isinstance(malware, dict):
        return "malware", malware
    return None


async def research(query: str, watcher=None) -> list[str]:
    """Return HTML blocks describing everything public about a vulnerability, actor, malware or group."""
    query = query.strip()
    if not is_cve(query) and (prof := await profile_kind(query)):
        return await research_profile(query, *prof, watcher=watcher)
    if not is_cve(query) and is_concept(query):
        return await research_concept(query)
    if not is_cve(query):
        skill = await _run({"attack": deep.attack_lookup(query),
                            "lolbas": deep.lolbas(query) if " " not in query else None,
                            "gtfo": deep.gtfobins(query) if " " not in query else None})
        if any(_ok(skill, k) for k in ("attack", "lolbas", "gtfo")):
            return await research_skill(query, skill)
    nickname = None if is_cve(query) else query
    disc: dict = {}
    if nickname:
        disc = await _run({
            "en": search_news(query, "en", 10), "bing": search_bing(query, 10), "vi": search_news(query, "vi", 6),
            "hn": search_hn(query, 6), "tg": watcher.search(query, per_channel=5, days=3650) if watcher else None,
            "repos": search_repos(query, 8), "ghsa": search_ghsa(query, 8), "exploits": search_exploits(query, 8),
        })
        ranked = resolve(disc)
    else:
        ranked = [(query.upper(), 0)]
    blocks = [f"🔬 <b>Research: {html.escape(query)}</b>"]
    if not ranked:
        blocks.append("<i>Không xác định được CVE nào gắn với tên này. Kết quả tìm kiếm chung:</i>")
        blocks += _sections(disc, {}, None)
        return blocks

    cve = ranked[0][0]
    if nickname:
        blocks.append(f"Gắn với <b>{cve}</b> (nhắc tới trong {ranked[0][1]} kết quả)")
    res = await _run({
        "nvd": nvd_cve(cve), "mitre": mitre_cve(cve), "epss": epss(cve), "kev": _kev(cve), "edb": _edb(cve),
        "ghsa_cve": ghsa_by_cve(cve), "trickest": trickest(cve), "nuclei": nuclei(cve), "circl": circl_sightings(cve),
        "poc": search_repos(cve, 6), "en_cve": search_news(cve, "en", 8), "bing_cve": search_bing(cve, 8),
        "shodan": deep.shodan_cve(cve), "nomisec": deep.nomisec_pocs(cve), "msf": deep.metasploit(cve),
        "sploitus": deep.sploitus(cve, 25), "otx": deep.otx_cve(cve),
        "hn_cve": search_hn(cve, 5, days=3650),
        "tg_cve": watcher.search(cve, per_channel=5, days=3650) if watcher else None,
        "vi_cve": None if nickname else search_news(cve, "vi", 6),
    })
    nvd, mitre = _ok(res, "nvd"), _ok(res, "mitre")
    if not nvd and not mitre:
        errs = [f"{k}: {_err(res[k])}" for k in ("nvd", "mitre") if isinstance(res.get(k), Exception)]
        blocks.append(f"<i>Không tìm thấy {cve} trên NVD/MITRE.</i>" + ("\n" + html.escape("; ".join(errs)) if errs else ""))
        return blocks
    blocks += _overview(cve, nickname, nvd or {}, mitre or {}, res)
    blocks += _sections(disc, res, cve)
    if len(ranked) > 1:
        blocks.append("🧩 <b>CVE khác cũng được nhắc cùng</b>\n" + "\n".join(
            f"• <code>{c}</code> ({n} kết quả)" for c, n in ranked[1:]) + "\n<i>Tra tiếp: /research CVE-…</i>")
    blocks.append(_more_links(cve))
    return blocks


CONCEPT_WORDS = {"bypass", "injection", "inject", "smuggling", "hijack", "hijacking", "poisoning", "spoofing",
                 "traversal", "escalation", "deserialization", "takeover", "enumeration", "persistence", "pivoting",
                 "pivot", "exfiltration", "evasion", "evade", "obfuscation", "technique", "method", "desync",
                 "forgery", "xss", "sqli", "ssrf", "csrf", "idor", "xxe", "ssti", "crlf", "race", "kỹ", "thuật",
                 "tấn", "công", "khai", "thác", "vượt", "qua"}


def is_concept(query: str) -> bool:
    """A technique described in words ("301 status code bypass", "jwt none algorithm attack")."""
    words = [fold(w).lower().strip(".,?!") for w in query.split()]
    return len(words) >= 2 and any(w in CONCEPT_WORDS for w in words)


# Security-only sources: research and write-up sites, vendor research, KBs, CERTs, exploit DBs.
SECURITY_SITES = [
    "portswigger.net", "book.hacktricks.wiki", "hacktricks.wiki", "owasp.org", "hackingarticles.in",
    "intigriti.com", "detectify.com", "assetnote.io", "specterops.io", "trailofbits.com", "googleprojectzero.blogspot.com",
    "blog.orange.tw", "projectdiscovery.io", "0xdf.gitlab.io", "zerodayinitiative.com", "labs.watchtowr.com",
    "horizon3.ai", "synacktiv.com", "doyensec.com", "positive.security", "bishopfox.com", "nccgroup.com",
    "cobalt.io", "hackerone.com", "bugcrowd.com", "infosecwriteups.com", "ired.team", "pentesterlab.com",
    "root-me.org", "ctftime.org", "exploit-db.com", "cve.org", "nvd.nist.gov", "attack.mitre.org", "cisa.gov",
    "security.stackexchange.com", "gtfobins.github.io", "lolbas-project.github.io",
    "atomicredteam.io", "sigmahq.io", "redcanary.com", "elastic.co", "sans.org", "isc.sans.edu", "rapid7.com",
    "talosintelligence.com", "unit42.paloaltonetworks.com", "securelist.com", "welivesecurity.com",
    "krebsonsecurity.com", "bleepingcomputer.com", "thehackernews.com", "darkreading.com", "schneier.com",
    "sploitus.com", "packetstormsecurity.com", "huntress.com", "dfir.report", "velocidex.com",
]
# Words that only appear in security writing; a page outside SECURITY_SITES needs one of them.
STRONG_SEC = re.compile(r"pentest|penetration test|exploit|vulnerab|payload|bug bounty|red team|blue team|malware|"
                        r"threat actor|\bctf\b|\bcve-\d|\bxss\b|\bsqli\b|\bssrf\b|\brce\b|privilege escalation|"
                        r"infosec|appsec|hacker|hacking|mitre att|\bdetection\b|\bsigma\b|ransomware|"
                        r"lỗ hổng|tấn công|mã độc", re.IGNORECASE)
SEC_TAGS = {"skill", "security", "redteam", "blueteam", "vuln", "malware", "ransomware", "kev", "breach",
            "incident", "watch"}


def _security_host(url: str) -> bool:
    host = urlparse(url).netloc.lower().removeprefix("www.")
    return any(host == s or host.endswith("." + s) for s in SECURITY_SITES)


def _is_security(n: dict) -> bool:
    """Keep web results only when the site is a security source or the text is clearly about security."""
    if n.get("tags") is not None:  # our own feed items: the classifier already tagged them
        return bool(SEC_TAGS & set(n["tags"]))
    return _security_host(n["url"]) or bool(STRONG_SEC.search(f"{n.get('title', '')} {n.get('summary', '')}"))


def _score(n: dict, groups: list[set[str]]) -> int:
    """Title matches count double; a page that has every word (codes included) ranks first."""
    title = deep.group_hits(fold(n.get("title", "")), groups)
    body = deep.group_hits(fold(f"{n.get('title', '')} {n.get('summary', '')}"), groups)
    return 2 * title + body + (3 if body == len(groups) else 0)


async def research_concept(query: str) -> list[str]:
    """How a technique works: explanations from knowledge bases, write-ups from security blogs and the web,
    tools on GitHub, Q&A."""
    groups = deep.query_groups(query)
    words = deep.query_words(query)
    res = await _run({
        "kb": deep.knowledge_snippets(query, 6),
        "web": search_web(query, 15),
        "guides": search_web(f"{query} (writeup OR pentest OR exploit)", 15),
        "exploits": search_exploits(" ".join(words), 6),
        "tools": search_repos(f"{' '.join(words)} in:name,description,readme", 6),
        "se": deep.stackexchange(query, 6),
    })
    blocks = [f"🔬 <b>Research kỹ thuật: {html.escape(query)}</b>"]
    kb = res.get("kb")
    if isinstance(kb, Exception):
        blocks.append(f"📖 Kho kiến thức: <i>{html.escape(_err(kb))}</i>")
    elif kb is None:
        blocks.append("<i>Kho tài liệu (HackTricks, PayloadsAllTheThings, OWASP…) đang được tải về lần đầu, "
                      "thử lại sau vài phút.</i>")
    elif kb:
        blocks.append("📖 <b>Giải thích kỹ thuật</b> <i>(HackTricks, PayloadsAllTheThings, OWASP)</i>\n" + "\n".join(
            f'• <a href="{html.escape(k["url"])}">{html.escape(k["repo"])}</a> · '
            f'<code>{html.escape(k["path"])}</code>\n<i>{html.escape(k["snippet"])}</i>' for k in kb))
    pool = [n for n in (_ok(res, "web", []) + _ok(res, "guides", []))
            if _is_security(n)]
    pool += [n for n in RECENT.values() if _is_security(n)]  # feed items already tagged as security/skill
    seen, scored = set(), []
    for n in pool:
        text = f"{n.get('title', '')} {n.get('summary', '')}"
        if n["url"] in seen or not deep.matches_groups(fold(text), groups):
            continue
        seen.add(n["url"])
        scored.append((_score(n, groups), n.get("published", 0), n))
    scored.sort(key=lambda x: (-x[0], -x[1]))
    articles = [n for _, _, n in scored]
    if articles:
        lines = []
        for n in articles[:7]:
            summary = clean_text(n.get("summary") or "")
            summary = "" if summary.lower().startswith(n["title"].lower()[:30]) else summary[:200]
            when = ago(n["published"]) if n.get("published") else "web"
            lines.append(f'• <a href="{html.escape(n["url"])}">{html.escape(n["title"][:120])}</a> — '
                         f'<i>{html.escape(n.get("source") or "")}</i>, {when}'
                         + (f"\n  <i>{html.escape(summary)}</i>" if summary else ""))
        blocks.append("📰 <b>Bài viết &amp; nghiên cứu</b>\n" + "\n".join(lines))
    exploits = _ok(res, "exploits", [])
    if exploits:
        blocks.append("💣 <b>Exploit-DB</b>\n" + "\n".join(format_exploit(e) for e in exploits[:5]))
    tools = [t for t in _ok(res, "tools", []) if deep.matches_groups(fold(f"{t['name']} {t['description']}"), groups)]
    if tools:
        blocks.append("🧰 <b>Công cụ &amp; PoC trên GitHub</b>\n" + "\n".join(
            f'• <a href="{html.escape(t["url"])}">{html.escape(t["name"])}</a> ({t["stars"]}★)'
            + (f"\n  <i>{html.escape(t['description'])}</i>" if t["description"] else "") for t in tools[:5]))
    se = [q for q in _ok(res, "se", []) if deep.matches_groups(fold(f"{q['title']} {q['snippet']}"), groups)]
    if se:
        blocks.append("💬 <b>Hỏi đáp (Information Security Stack Exchange)</b>\n" + "\n".join(
            f'• <a href="{html.escape(q["url"])}">{html.escape(q["title"][:110])}</a> ({q["score"]}▲)'
            + (f"\n  <i>{html.escape(q['snippet'][:160])}</i>" if q["snippet"] else "") for q in se[:4]))
    if not articles and not kb and not isinstance(kb, Exception):
        blocks.append("<i>Chưa tìm thấy bài viết khớp đủ từ khóa. Thử cách diễn đạt khác hoặc tên kỹ thuật tiếng Anh.</i>")
    blocks.append(f'🔗 <b>Tra cứu thêm</b>: <a href="https://www.google.com/search?q={quote_plus(query + " site:book.hacktricks.wiki OR site:portswigger.net")}">Google (HackTricks, PortSwigger)</a>'
                  f' · <a href="https://github.com/search?q={quote_plus(chr(34) + query + chr(34))}&type=code">GitHub code</a>')
    failed = [k for k in ("web", "guides", "exploits", "tools", "se") if isinstance(res.get(k), Exception)]
    if failed:
        blocks.append("<i>Nguồn lỗi/giới hạn: " + html.escape(", ".join(f"{k} ({_err(res[k])})" for k in failed)) + "</i>")
    return blocks


async def research_skill(query: str, res: dict) -> list[str]:
    """A technique (T1558.003, kerberoasting), a Windows or Linux binary abused by attackers (certutil, find)."""
    techs = _ok(res, "attack", [])
    name = techs[0]["name"].split(": ")[-1] if techs else query
    blocks = [f"🔬 <b>Research: {html.escape(query)}</b> — 🧰 Kỹ thuật"]
    for t in techs:
        blocks.append(format_technique(t))
    if l := _ok(res, "lolbas"):
        blocks.append(format_lolbas(l))
    if g := _ok(res, "gtfo"):
        blocks.append(format_gtfo(g))
    blocks.append("<i>Cách học: chạy mã test Atomic trong phòng lab có snapshot, rồi kiểm tra xem luật Sigma/EDR có báo không.</i>")
    news = await _run({"en": search_news(name, "en", 20), "bing": search_bing(name, 15),
                       "hn": search_hn(name, 6, days=3650)})
    pool = _ok(news, "en", []) + _ok(news, "bing", [])
    pool += [{"title": h["title"], "url": h["hn_url"], "published": h["published"], "summary": h["url"],
              "source": f"Hacker News · {h['points']}▲"} for h in _ok(news, "hn", [])]
    pool += list(RECENT.values())
    ranked = rank(Query(raw=query, entity=name, kind="org"), pool, 10)
    if ranked:
        blocks.append("📰 <b>Bài viết kỹ thuật &amp; tin liên quan</b>\n" + "\n".join(format_news_line(n) for n in ranked))
    return blocks


KIND_LABEL = {"group": "🏴‍☠️ Nhóm ransomware", "actor": "🕵️ Nhóm tấn công (APT)", "malware": "🦠 Malware"}


async def research_profile(query: str, kind: str, entry: dict | None, watcher=None) -> list[str]:
    from .search import format_group, format_ranked  # local import: search.py does not import research
    names = [query] if entry is None else [entry["name"], *[s for s in entry["synonyms"] if len(s) >= 3]]
    names = list(dict.fromkeys(names))
    q = Query(raw=query, entity=names[0], kind="org", aliases=names[1:6],
              topics=["ransomware"] if kind == "group" else [])
    search_q = " OR ".join(f'"{n}"' for n in names[:3])
    is_ransom = kind == "group" or "ransom" in (entry or {}).get("description", "").lower()
    res = await _run({
        "group": ransomware_group(query) if kind == "group" else None,
        "pay": deep.ransom_payments(names[0]) if is_ransom else None,
        "en": search_news(search_q, "en", 25), "bing": search_bing(search_q, 20), "vi": search_news(search_q, "vi", 10),
        "dark": search_darkweb_news(names[0], 10), "hn": search_hn(names[0], 6, days=3650),
        "tg": watcher.search(names[0], per_channel=5, days=3650) if watcher else None,
    })
    blocks = [f"🔬 <b>Research: {html.escape(query)}</b> — {KIND_LABEL[kind]}"]
    if isinstance(res.get("group"), dict):
        blocks.append(format_group(res["group"]))
    if entry:
        lines = [f"{KIND_LABEL[kind]} <b>{html.escape(entry['name'])}</b>"]
        if len(names) > 1:
            lines.append("Tên khác: " + html.escape(", ".join(names[1:12])))
        facts = [f"quốc gia: <b>{html.escape(entry['country'])}</b>" if entry["country"] else "",
                 f"mục đích: {html.escape(str(entry['incident']))}" if entry["incident"] else ""]
        if any(facts):
            lines.append(" · ".join(f for f in facts if f))
        if entry["victims"]:
            vn = " 🇻🇳 <b>có Việt Nam</b>" if any("viet" in v.lower() for v in entry["victims"]) else ""
            lines.append("Nạn nhân: " + html.escape(", ".join(entry["victims"][:10])) + vn)
        if entry["targets"]:
            lines.append("Lĩnh vực: " + html.escape(", ".join(entry["targets"][:8])))
        if entry["description"]:
            lines.append(f"<i>{html.escape(entry['description'][:900])}</i>")
        blocks.append("\n".join(lines))
    if p := _ok(res, "pay"):
        blocks.append(f"💰 <b>Tiền chuộc ghi nhận on-chain</b> (ransomwhe.re): <b>${p['usd']:,.0f}</b> qua "
                      f"{p['payments']} giao dịch, {p['addresses']} ví" + (f", gần nhất {_date(p['last'])}" if p["last"] else "")
                      + "\n<i>Chỉ là phần được cộng đồng báo cáo, con số thật lớn hơn nhiều.</i>")
    pool = _ok(res, "en", []) + _ok(res, "bing", []) + _ok(res, "vi", [])
    pool += [{"title": h["title"], "url": h["hn_url"], "published": h["published"], "summary": h["url"],
              "source": f"Hacker News · {h['points']}▲"} for h in _ok(res, "hn", [])]
    pool += [{"title": i["title"], "url": i["url"], "published": i["published"], "summary": i["summary"],
              "source": i["source"]} for i in _ok(res, "tg", [])]
    security = [n for n in pool if SEC_RE.search(f"{n['title']} {n.get('summary', '')}")]
    news = rank(q, security, 12)
    if news:
        blocks.append("📰 <b>Tin & phân tích mới nhất</b>\n" + "\n".join(format_ranked(n) for n in news))
    dark = rank(q, _ok(res, "dark", []), 6)
    if dark:
        blocks.append("🌑 <b>Tin dark web</b>\n" + "\n".join(format_ranked(n) for n in dark))
    if entry and entry["refs"]:
        blocks.append(f"📚 <b>Báo cáo kỹ thuật</b> ({len(entry['refs'])} tài liệu, mới thêm gần nhất)\n"
                      + _links(list(reversed(entry["refs"])), 10))
    links = {}
    if entry and entry.get("mitre"):
        links["MITRE ATT&amp;CK"] = entry["mitre"]
    if kind == "actor":
        links["Malpedia"] = entry["malpedia"]
    if kind == "group":
        links["ransomware.live"] = f"https://www.ransomware.live/group/{quote_plus(query.lower())}"
        links["RansomLook"] = f"https://www.ransomlook.io/group/{quote_plus(query.lower())}"
    links["OTX"] = f"https://otx.alienvault.com/browse/global/pulses?q={quote_plus(names[0])}"
    blocks.append("🔗 <b>Tra cứu thêm</b>: " + " · ".join(f'<a href="{html.escape(u)}">{k}</a>' for k, u in links.items()))
    failed = [k for k, v in res.items() if isinstance(v, Exception)]
    if failed:
        blocks.append("<i>Nguồn lỗi/giới hạn: " + html.escape(", ".join(f"{k} ({_err(res[k])})" for k in failed)) + "</i>")
    return blocks


def _err(e: Exception) -> str:
    if isinstance(e, RateLimited):
        return str(e)
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return "quá thời gian chờ"
    if isinstance(e, httpx.HTTPStatusError):
        return f"HTTP {e.response.status_code}"
    return type(e).__name__


def _overview(cve: str, nickname: str | None, nvd: dict, mitre: dict, res: dict) -> list[str]:
    score = nvd.get("score") if nvd.get("score") is not None else mitre.get("score")
    sev = (nvd.get("severity") or mitre.get("severity") or "").upper()
    vector = nvd.get("vector") or mitre.get("vector")
    title = mitre.get("title") or nickname or ""
    desc = nvd.get("description") or mitre.get("description")
    cwes = sorted(set(nvd.get("cwes", [])) | {c.split()[0] for c in mitre.get("cwes", []) if c.startswith("CWE-")})
    published = nvd.get("published") or mitre.get("published")
    head = [f'🧬 <a href="https://nvd.nist.gov/vuln/detail/{cve}"><b>{cve}</b></a>'
            + (f" — {html.escape(title)}" if title else ""),
            f"{_severity(score)} CVSS <b>{score if score is not None else '?'}</b> {sev}"
            + (f" · <code>{html.escape(vector)}</code>" if vector else ""),
            " · ".join(x for x in (", ".join(cwes), f"công bố {published[:10]}" if published else "",
                                   f"CNA: {html.escape(mitre['cna'])}" if mitre.get("cna") else "") if x)]
    if desc:
        head.append(f"<i>{html.escape(desc[:700])}</i>")
    blocks = ["\n".join(head), _verdict(score, mitre, res)]
    if tl := _timeline(published, res):
        blocks.append(tl)

    risk = []
    kev = _ok(res, "kev")
    if kev:
        ransom = " · <b>dùng trong ransomware</b>" if kev.get("knownRansomwareCampaignUse") == "Known" else ""
        risk.append(f"⚠️ <b>CISA KEV: đang bị khai thác thực tế</b> (thêm {kev['dateAdded']}, hạn vá {kev['dueDate']}){ransom}")
    elif isinstance(res.get("kev"), Exception):
        risk.append(f"CISA KEV: <i>{_err(res['kev'])}</i>")
    else:
        risk.append("CISA KEV: chưa có trong danh sách")
    e = _ok(res, "epss")
    sh = _ok(res, "shodan") or {}
    if not e and sh.get("epss") is not None:  # FIRST down: Shodan CVEDB carries the same EPSS
        e = {"epss": sh["epss"], "percentile": sh.get("ranking_epss") or 0}
    if e:
        risk.append(f"🎯 EPSS: <b>{e['epss'] * 100:.2f}%</b> khả năng bị khai thác trong 30 ngày "
                    f"(nằm trong top {max((1 - e['percentile']) * 100, 0.01):.2f}% CVE nguy hiểm nhất)")
    if sh.get("ransomware") and not (kev and kev.get("knownRansomwareCampaignUse") == "Known"):
        risk.append("💀 <b>Được dùng trong chiến dịch ransomware</b> (Shodan CVEDB)")
    if ssvc := mitre.get("ssvc"):
        risk.append("🏛 CISA SSVC: " + " · ".join(f"{k}: <b>{html.escape(str(v))}</b>" for k, v in ssvc.items()))
    if c := _ok(res, "circl"):
        counts = " · ".join(f"{label} {c['counts'][k]:,}" for k, label in SIGHTING_TYPES.items() if c["counts"][k])
        if counts:
            risk.append(f'👁 <a href="{html.escape(c["url"])}">CIRCL</a> ghi nhận: {counts}')
    blocks.append("📊 <b>Mức độ nguy hiểm</b>\n" + "\n".join(risk))

    scope = list(mitre.get("affected", []))[:8]
    fixes = [f"• {html.escape(f['package'])} <code>{html.escape(f['vulnerable'])}</code> → vá "
             f"<b>{html.escape(f['patched'])}</b>" for a in _ok(res, "ghsa_cve", []) for f in a["fixes"]]
    if scope or fixes:
        blocks.append("📦 <b>Phạm vi ảnh hưởng</b>\n" + "\n".join(f"• {s}" for s in scope)
                      + ("\n<b>Bản vá (GitHub Advisory)</b>\n" + "\n".join(dict.fromkeys(fixes[:10])) if fixes else ""))

    refs = nvd.get("references") or [{"url": u, "tags": set()} for u in mitre.get("references", [])]
    patches = [r["url"] for r in refs if r["tags"] & PATCH_TAGS]
    ghsa_links = [a["url"] for a in _ok(res, "ghsa_cve", [])]
    if patches or ghsa_links:
        blocks.append("🩹 <b>Advisory &amp; bản vá</b>\n" + _links(ghsa_links + patches, 8))

    blocks.append(_exploits(cve, res))
    blocks.extend(_threat_context(res))
    t = _ok(res, "trickest", {"references": [], "github": []})

    writeups = [r["url"] for r in refs if r["tags"] & WRITEUP_TAGS and r["url"] not in patches]
    writeups += [u for u in t["references"] if "github.com" not in u]
    if writeups:
        blocks.append("🔬 <b>Phân tích kỹ thuật &amp; tham khảo</b>\n" + _links(writeups, 10))
    return blocks


def _verdict(score, mitre: dict, res: dict) -> str:
    """One-line patch priority, derived from exploitation evidence rather than CVSS alone."""
    kev, sh, e = _ok(res, "kev"), _ok(res, "shodan") or {}, _ok(res, "epss")
    epss_v = (e or {}).get("epss", sh.get("epss") or 0) or 0
    msf, edb, pocs = _ok(res, "msf", []), _ok(res, "edb", []), _ok(res, "nomisec", []) or _ok(res, "poc", [])
    circl = (_ok(res, "circl") or {}).get("counts", {})
    active = bool(kev) or str(mitre.get("ssvc", {}).get("Exploitation", "")).lower() == "active"
    why = []
    if kev:
        why.append("đang bị khai thác thực tế (CISA KEV)")
    elif active:
        why.append("CISA SSVC: Exploitation active")
    if circl.get("exploited"):
        why.append(f"honeypot/CIRCL ghi nhận {circl['exploited']:,} lần khai thác")
    if sh.get("ransomware") or (kev and kev.get("knownRansomwareCampaignUse") == "Known"):
        why.append("dùng trong ransomware")
    if msf:
        why.append("đã có module Metasploit")
    if pocs or edb:
        why.append(f"{len(pocs) + len(edb)} PoC/exploit công khai")
    if epss_v >= 0.01:
        why.append(f"EPSS {epss_v * 100:.1f}%")
    if active or (msf and epss_v >= 0.1):
        level = "🔥 <b>VÁ NGAY</b> (ưu tiên cao nhất)"
    elif (score or 0) >= 7 and (pocs or edb or msf or epss_v >= 0.05):
        level = "⚠️ <b>Vá sớm</b> (trong vài ngày)"
    elif (score or 0) >= 9:
        level = "🟠 <b>Vá theo kế hoạch gần</b> (nghiêm trọng nhưng chưa thấy khai thác)"
    else:
        level = "📋 <b>Theo dõi</b>, vá theo chu kỳ"
    action = (kev or {}).get("requiredAction") or sh.get("propose_action") or ""
    return (f"🧭 <b>Đánh giá</b>: {level}" + (f"\nVì: {', '.join(why)}" if why else "")
            + (f"\n<i>Khuyến nghị (CISA): {html.escape(action[:300])}</i>" if action and kev else ""))


def _timeline(published: str | None, res: dict) -> str | None:
    """Disclosure -> first PoC -> KEV -> first news, with day offsets: how fast it went from paper to weapon."""
    start = deep.iso_ts(published)
    if not start:
        return None
    events = [(start, "công bố CVE")]
    pocs = _ok(res, "nomisec", [])
    if p := deep.first_date(pocs, "created", not_before=start - 7 * 86400):  # older repos were renamed/reused
        events.append((p, "PoC đầu tiên trên GitHub"))
    edb_dates = [deep.iso_ts(x["date"]) for x in _ok(res, "edb", []) if x.get("date")]
    if edb_dates := [d for d in edb_dates if d]:
        events.append((min(edb_dates), "lên Exploit-DB"))
    msf = _ok(res, "msf", [])
    if kev := _ok(res, "kev"):
        events.append((deep.iso_ts(kev["dateAdded"]) or start, "vào CISA KEV (xác nhận bị khai thác)"))
    news = _ok(res, "en_cve", []) + _ok(res, "bing_cve", [])
    if n := deep.first_date(news, "published", not_before=start - 30 * 86400):
        events.append((n, "tin tức đầu tiên"))
    if len(events) < 2:
        return None
    events.sort()
    def offset(ts: int) -> str:
        days = (ts - start) // 86400
        return "" if ts <= start + 3600 else " <i>(trong 24 giờ)</i>" if days < 1 else f" <i>(+{days} ngày)</i>"
    lines = [f"• {_date(ts)} {label}{offset(ts)}" for ts, label in events]
    if msf:
        lines.append(f"• Metasploit: {len(msf)} module ({html.escape(msf[0]['rank'])})")
    return "⏱ <b>Dòng thời gian</b>\n" + "\n".join(lines)


def _exploits(cve: str, res: dict) -> str:
    expl = []
    for m in _ok(res, "msf", [])[:3]:
        expl.append(f'• 🎯 <b>Metasploit</b>: <a href="{html.escape(m["url"])}">{html.escape(m["name"])}</a>'
                    f" · rank {html.escape(m['rank'])}" + (" · có lệnh check" if m["check"] else ""))
    for e in _ok(res, "edb", [])[:4]:
        expl.append(format_exploit(e))
    if n := _ok(res, "nuclei"):
        expl.append(f'• <a href="{html.escape(n)}">Nuclei template</a> — phát hiện/kiểm tra hệ thống bị ảnh hưởng')
    pocs = _ok(res, "nomisec", [])
    source = "nomi-sec/PoC-in-GitHub"
    if not pocs:
        pocs, source = _ok(res, "poc", []), "GitHub search"
    if pocs:
        expl.append(f"<b>{len(pocs)} repo PoC trên GitHub</b> ({source}), nhiều sao nhất:")
        for r in pocs[:6]:
            expl.append(f'  ⭐{r["stars"]} <a href="{html.escape(r["url"])}">{html.escape(r["name"])}</a>'
                        + (f" — {html.escape(r['description'][:80])}" if r["description"] else ""))
    sp = _ok(res, "sploitus")
    if sp:
        others = [x for x in sp["items"] if "github.com" not in x["url"]][:4]
        if others:
            expl.append(f'<b>Sploitus</b> ({sp["total"]} kết quả), ngoài GitHub:')
            expl.extend(f'  • <a href="{html.escape(x["url"])}">{html.escape(x["title"][:90])}</a> · '
                        f'{html.escape(x["type"])} · {html.escape(x["published"])}' for x in others)
    t = _ok(res, "trickest", {"references": [], "github": []})
    known = {r["url"].lower() for r in pocs}
    extra = [u for u in t["github"] if u.lower() not in known]
    if extra:
        year = cve.split("-")[1]
        expl.append(f'• <a href="https://github.com/trickest/cve/blob/main/{year}/{cve}.md">trickest/cve</a> '
                    f"có thêm {len(extra)} repo")
    if not expl:
        return "💣 <b>Exploit / PoC công khai</b>: <i>chưa thấy</i>"
    return ("💣 <b>Exploit / PoC công khai</b>\n" + "\n".join(expl)
            + "\n<i>⚠️ PoC chưa được kiểm chứng, nhiều repo giả chứa mã độc: chỉ đọc, chạy trong máy ảo/lab.</i>")


def _threat_context(res: dict) -> list[str]:
    o = _ok(res, "otx")
    if not o or not o["count"]:
        return []
    lines = [f"🕸 <b>Threat intel</b> (AlienVault OTX: {o['count']} báo cáo nhắc tới)"]
    if o["adversaries"]:
        lines.append("Nhóm/chiến dịch: " + html.escape(", ".join(o["adversaries"][:8])))
    if o["malware"]:
        lines.append("Malware đi kèm: " + html.escape(", ".join(o["malware"][:8])))
    if o["industries"]:
        lines.append("Ngành bị nhắm: " + html.escape(", ".join(o["industries"][:6])))
    lines += [f'• <a href="{html.escape(p["url"])}">{html.escape(p["name"][:110])}</a> — {_date(p["created"])}'
              for p in o["pulses"][:4]]
    return ["\n".join(lines)]


def _links(urls: list[str], limit: int) -> str:
    out = []
    for u in dict.fromkeys(urls):
        p = urlparse(u)
        label = (p.netloc.removeprefix("www.") + p.path)[:70]
        out.append(f'• <a href="{html.escape(u)}">{html.escape(label)}</a>')
    return "\n".join(out[:limit])


def _sections(disc: dict, res: dict, cve: str | None) -> list[str]:
    blocks = []

    def add(title: str, items: list, fmt, joined: bool = True):
        if items:
            if joined:
                blocks.append(f"{title}\n" + "\n".join(fmt(x) for x in items))
            else:
                blocks.append(title)
                blocks.extend(fmt(x) for x in items)

    add("📰 <b>Tin tức (EN: Google + Bing)</b>",
        _merge(_ok(disc, "en", []), _ok(disc, "bing", []), _ok(res, "en_cve", []), _ok(res, "bing_cve", []), limit=10),
        format_news_line)
    add("📰 <b>Tin tức (VI)</b>", _merge(_ok(disc, "vi", []), _ok(res, "vi_cve", []), limit=6), format_news_line)
    hn = {h["hn_url"]: h for h in _ok(disc, "hn", []) + _ok(res, "hn_cve", [])}
    add("💬 <b>Hacker News</b>", sorted(hn.values(), key=lambda h: -h["points"])[:6], format_hn)
    tg = {i["url"]: i for i in _ok(disc, "tg", []) + _ok(res, "tg_cve", [])}
    add("📢 <b>Telegram channels đang theo dõi</b>", sorted(tg.values(), key=lambda i: -i["published"])[:5],
        format_item, joined=False)
    if c := _ok(res, "circl"):
        add("🗣 <b>Mạng xã hội / cộng đồng (qua CIRCL)</b>", c["links"][:6],
            lambda s: f'• <a href="{html.escape(s["url"])}">{html.escape(urlparse(s["url"]).netloc)}</a> '
                      f'{s["at"]} · {html.escape(SIGHTING_TYPES.get(s["type"], s["type"]))}'
                      + (f" — <i>{html.escape(s['text'])}</i>" if s["text"] else ""))
    if not cve:  # nickname not resolved: still show what the searches found
        add("📦 <b>GitHub Advisories</b>", _ok(disc, "ghsa", [])[:5],
            lambda a: f'{SEV.get(a["severity"], "⚪")} <a href="{html.escape(a["url"])}">{a["id"]}</a> {html.escape(a["summary"][:120])}')
        add("🧰 <b>GitHub repos</b>", _ok(disc, "repos", [])[:6],
            lambda r: f'• ⭐{r["stars"]} <a href="{html.escape(r["url"])}">{html.escape(r["name"])}</a> — {html.escape(r["description"][:90])}')
        add("💣 <b>Exploit-DB</b>", _ok(disc, "exploits", [])[:5], format_exploit)
    if any(isinstance(v, Exception) for d in (disc, res) for v in d.values()):
        blocks.append("<i>Nguồn lỗi/giới hạn: " + html.escape(", ".join(
            f"{k} ({_err(d[k])})" for d in (disc, res) for k in d if isinstance(d[k], Exception))) + "</i>")
    return blocks


def _more_links(cve: str) -> str:
    q = quote_plus(cve)
    links = {"NVD": f"https://nvd.nist.gov/vuln/detail/{cve}", "CVE.org": f"https://www.cve.org/CVERecord?id={cve}",
             "CIRCL": f"https://vulnerability.circl.lu/vuln/{cve}", "AttackerKB": f"https://attackerkb.com/search?q={q}",
             "Vulners": f"https://vulners.com/search?query={q}", "GitHub code": f"https://github.com/search?q={q}&type=code"}
    return "🔗 <b>Tra cứu thêm</b>: " + " · ".join(f'<a href="{html.escape(u)}">{k}</a>' for k, u in links.items())
