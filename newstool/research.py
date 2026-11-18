"""Deep research on one vulnerability: a CVE id or a nickname (React2Shell, Log4Shell, Spring4Shell...).

Every source is a free public API or public file; nothing is downloaded or executed, only linked.
"""
import asyncio
import collections
import html
from urllib.parse import quote_plus, urlparse

import httpx

from .classify import CVE_RE, cves as find_cves
from .formatter import SEV, format_exploit, format_hn, format_item, format_news_line
from .intel import (NVD_API, RateLimited, _client, _get_json, exploits_by_cve, ghsa_by_cve, kev_catalog,
                    search_bing, search_exploits, search_ghsa, search_hn, search_news, search_repos)

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
async def _run(lookups: dict) -> dict:
    lookups = {k: v for k, v in lookups.items() if v is not None}
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


async def research(query: str, watcher=None) -> list[str]:
    """Return HTML blocks describing everything public about a vulnerability."""
    query = query.strip()
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


def _err(e: Exception) -> str:
    if isinstance(e, RateLimited):
        return str(e)
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
    blocks = ["\n".join(head)]

    risk = []
    kev = _ok(res, "kev")
    if kev:
        ransom = " · <b>dùng trong ransomware</b>" if kev.get("knownRansomwareCampaignUse") == "Known" else ""
        risk.append(f"⚠️ <b>CISA KEV: đang bị khai thác thực tế</b> (thêm {kev['dateAdded']}, hạn vá {kev['dueDate']}){ransom}")
    elif isinstance(res.get("kev"), Exception):
        risk.append(f"CISA KEV: <i>{_err(res['kev'])}</i>")
    else:
        risk.append("CISA KEV: chưa có trong danh sách")
    if e := _ok(res, "epss"):
        risk.append(f"🎯 EPSS: <b>{e['epss'] * 100:.2f}%</b> khả năng bị khai thác trong 30 ngày "
                    f"(nằm trong top {max((1 - e['percentile']) * 100, 0.01):.2f}% CVE nguy hiểm nhất)")
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

    expl = []
    for e in _ok(res, "edb", [])[:5]:
        expl.append(format_exploit(e))
    if n := _ok(res, "nuclei"):
        expl.append(f'• <a href="{html.escape(n)}">Nuclei template</a> — phát hiện/kiểm tra hệ thống bị ảnh hưởng')
    t = _ok(res, "trickest", {"references": [], "github": []})
    poc_repos = _ok(res, "poc", [])
    known = {r["url"].lower() for r in poc_repos}
    for r in poc_repos:
        expl.append(f'• ⭐{r["stars"]} <a href="{html.escape(r["url"])}">{html.escape(r["name"])}</a>'
                    + (f" — {html.escape(r['description'][:90])}" if r["description"] else ""))
    extra = [u for u in t["github"] if u.lower() not in known]
    if extra:
        year = cve.split("-")[1]
        expl.append(f'• <a href="https://github.com/trickest/cve/blob/main/{year}/{cve}.md">trickest/cve</a> '
                    f"tổng hợp thêm {len(extra)} repo PoC khác")
    if expl:
        blocks.append("💣 <b>Exploit / PoC công khai</b>\n" + "\n".join(expl)
                      + "\n<i>⚠️ PoC trên GitHub chưa được kiểm chứng, nhiều repo giả chứa mã độc: chỉ đọc, "
                        "chạy thử trong máy ảo/lab.</i>")
    else:
        blocks.append("💣 <b>Exploit / PoC công khai</b>: <i>chưa thấy</i>")

    writeups = [r["url"] for r in refs if r["tags"] & WRITEUP_TAGS and r["url"] not in patches]
    writeups += [u for u in t["references"] if "github.com" not in u]
    if writeups:
        blocks.append("🔬 <b>Phân tích kỹ thuật &amp; tham khảo</b>\n" + _links(writeups, 10))
    return blocks


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
