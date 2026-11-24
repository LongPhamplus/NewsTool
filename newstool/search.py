"""/search: understand the question, query the right sources, rank and de-duplicate the results."""
import asyncio
import collections
import html
import time


from .classify import cves as find_cves
from .config import Config
from .formatter import (_date, ago, format_breach, format_cve, format_exploit, format_ghsa, format_gtfo,
                        format_infostealer, format_lolbas, format_technique,
                        format_lookalike, format_victim)
from .intel import (RateLimited, group_names, ransomware_group, recent_ransomware, search_bing,
                    search_breaches, search_cves, search_darkweb_news, search_exploits, search_gdelt, search_ghsa,
                    search_hn, search_infostealer, search_leak_index, search_lookalikes, search_news,
                    search_ransomware)
from . import deep
from .pipeline import RECENT
from .query import SECURITY_EN, Query, parse, rank

DARKWEB_FEEDS = {"Dark Web Informer", "Daily Dark Web", "DataBreaches.net", "HackRead"}


def _err(e: Exception) -> str:
    if isinstance(e, RateLimited):
        return str(e)
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return "quá thời gian chờ"
    status = getattr(getattr(e, "response", None), "status_code", None)
    return f"HTTP {status}" if status else type(e).__name__


LOOKUP_TIMEOUT = 35  # seconds: one slow source must not hold the whole answer


async def _run(lookups: dict) -> dict:
    lookups = {k: asyncio.wait_for(v, LOOKUP_TIMEOUT) for k, v in lookups.items() if v is not None}
    return dict(zip(lookups, await asyncio.gather(*lookups.values(), return_exceptions=True)))


def _ok(res: dict, key: str) -> list:
    v = res.get(key)
    return v if isinstance(v, list) else []


def _hn_news(h: dict) -> dict:
    return {"title": h["title"], "url": h["hn_url"], "published": h["published"], "summary": h.get("url", ""),
            "source": f"Hacker News · {h['points']}▲ {h['comments']}💬"}


def _feed_news(i: dict) -> dict:
    return {"title": i["title"], "url": i["url"], "published": i["published"], "summary": i.get("summary", ""),
            "source": i["source"]}


def format_ranked(n: dict) -> str:
    also = f" <i>(+{len(n['also'])} nguồn)</i>" if n.get("also") else ""
    return (f'• <a href="{html.escape(n["url"])}">{html.escape(n["title"][:140])}</a>'
            f" — <i>{html.escape(n.get('source') or '')}</i>, {_when(n['published'])}{also}")


def _when(ts: int) -> str:
    return ago(ts) if time.time() - ts < 30 * 86400 else _date(ts)


def defang(s: str) -> str:
    """Make a malicious URL/domain non-clickable: hxxps://evil[.]com."""
    return s.replace("http", "hxxp", 1).replace(".", "[.]")


def format_urlscan(x: dict) -> str:
    flag = " 🔴 <b>urlscan đánh giá độc hại</b>" if x["verdict"] else ""
    return (f'• <code>{html.escape(defang(x["domain"]))}</code> — quét {_date(x["at"])} · '
            f'<a href="{html.escape(x["result"])}">xem ảnh chụp</a>{flag}')


def format_phish_url(u: str) -> str:
    return f"• <code>{html.escape(defang(u)[:150])}</code>"


def format_otx_domain(o: dict) -> str:
    lines = [f"🕸 <b>{html.escape(o['domain'])}</b>: {o['count']} báo cáo"]
    if o["adversaries"] or o["malware"]:
        lines.append(html.escape(", ".join(o["adversaries"][:4] + o["malware"][:4])))
    lines += [f'• <a href="{html.escape(p["url"])}">{html.escape(p["name"][:100])}</a> — {_date(p["created"])}'
              for p in o["pulses"][:3]]
    return "\n".join(lines)


def format_kev_item(c: dict) -> str:
    epss = f" · EPSS {c['epss'] * 100:.1f}%" if c.get("epss") is not None else ""
    return (f'• <a href="{html.escape(c["url"])}"><b>{c["id"]}</b></a> {html.escape(c["product"])} — '
            f"{html.escape(c['name'][:80])} · KEV {html.escape(c['added'])}{epss}"
            + (" 💀 ransomware" if c["ransomware"] else ""))


def format_msf(m: dict) -> str:
    return (f'• <a href="{html.escape(m["url"])}">{html.escape(m["name"])}</a> · {html.escape(m["rank"])}'
            f" · {html.escape(m['disclosed'])}")


def format_leak(x: dict) -> str:
    cols = ", ".join(x["columns"][:10]) + (f" (+{len(x['columns']) - 10})" if len(x["columns"]) > 10 else "")
    return (f'💾 <b>{html.escape(x["name"])}</b> — {html.escape(str(x["records"]))} bản ghi · {html.escape(str(x["size"]))}'
            f' · lập chỉ mục {html.escape(x["indexed"] or "?")} · <a href="{html.escape(x["url"])}">RansomLook</a>'
            + (f"\nTrường dữ liệu: <code>{html.escape(cols)}</code>" if cols else ""))


def format_group(g: dict) -> str:
    lines = [f'🏴‍☠️ <b>Nhóm ransomware {html.escape(g["name"])}</b> — <a href="{html.escape(g["url"])}">ransomware.live</a>',
             f"Xuất hiện từ {html.escape(g['first_seen'] or '?')} · <b>{g['victims_total']:,}</b> nạn nhân"
             + (f" · leak site {g['sites_up']}/{g['sites_total']} đang online" if g["sites_total"] else "")]
    if g["description"]:
        lines.append(f"<i>{html.escape(g['description'][:450])}</i>")
    if g["countries"]:
        lines.append("Quốc gia bị nhắm nhiều nhất: " + ", ".join(f"{c} {n:,}" for c, n in g["countries"]))
    if g["vn_victims"]:
        lines.append("🇻🇳 <b>Nạn nhân Việt Nam</b>: " + "; ".join(
            f"{html.escape(v['victim'])} ({_date(v['discovered'])})" for v in g["vn_victims"]))
    else:
        lines.append("🇻🇳 Chưa ghi nhận nạn nhân Việt Nam")
    if g["tools"]:
        lines.append("🧰 Công cụ: " + " · ".join(
            f"{html.escape(cat)}: {html.escape(', '.join(names[:4]))}" for cat, names in list(g["tools"].items())[:6]))
    if g["tactics"]:
        lines.append("🎯 ATT&amp;CK: " + html.escape(", ".join(g["tactics"])))
    if g["victims"]:
        lines.append("Nạn nhân gần nhất:\n" + "\n".join(
            f"• {html.escape(v['victim'])} · {html.escape(v['country'] or '?')} · {_date(v['discovered'])}"
            for v in g["victims"]))
    return "\n".join(lines)


async def smart_search(text: str, cfg: Config, watcher=None) -> tuple[Query, list[str]]:
    q = parse(text)
    try:
        groups = await group_names()
    except Exception:
        groups = set()
    if q.kind == "org" and q.entity.lower() in groups:
        q.kind = "group"
        if "ransomware" not in q.topics:  # "akira" alone also means Akira Kurosawa: keep the ransomware context
            q.topics.append("ransomware")

    is_org = q.kind in ("org", "domain", "group")
    want_vuln = "vuln" in q.topics or (q.kind in ("org", "domain") and not q.topics)
    want_brand = q.kind in ("org", "domain") and (not q.topics or {"phishing", "attack"} & set(q.topics))
    news_en = q.engine_query("en")
    bing_q = news_en if q.topics or not is_org else f"{news_en} ({' OR '.join(SECURITY_EN)})"
    ent = q.entity if q.kind != "country" else "Vietnam"
    res = await _run({
        "group": ransomware_group(q.entity) if q.kind == "group" else None,
        "victims": search_ransomware(q.folded) if cfg.ransomware and q.kind in ("org", "domain") else None,
        "recent": recent_ransomware() if cfg.ransomware and (q.kind == "country" or (
            q.kind == "topic" and "ransomware" in q.topics)) else None,
        "breaches": search_breaches(q.brand) if cfg.breaches and q.kind in ("org", "domain") else None,
        "leaks": search_leak_index([q.brand] + [d.split(".")[0] for d in q.domains]) if q.kind in ("org", "domain") else None,
        "lookalike": search_lookalikes(q.brand) if want_brand and len(q.brand) >= 4 else None,
        **({f"hr:{d}": search_infostealer(d) for d in q.domains} if q.kind in ("org", "domain") else {}),
        "cves": search_cves(q.entity) if want_vuln and q.entity else None,
        "ghsa": search_ghsa(q.entity) if want_vuln and q.entity else None,
        "exploits": search_exploits(q.entity) if want_vuln and q.entity else None,
        "g_vi": search_news(q.engine_query("vi"), "vi", 20),
        "g_en": search_news(news_en, "en", 20),
        "bing": search_bing(bing_q, 20),
        "gdelt": search_gdelt(news_en, 15),
        "dark": search_darkweb_news(ent or news_en, 15),
        "hn": search_hn(ent, 8) if ent else None,
        "tg": watcher.search(ent, per_channel=5) if watcher and ent else None,
        # Lesser-known sources
        "pay": deep.ransom_payments(q.entity) if q.kind == "group" else None,
        "phish": deep.urlscan_brand(q.brand, q.domains) if want_brand and len(q.brand) >= 4 else None,
        "openphish": deep.openphish_brand(q.brand) if want_brand and len(q.brand) >= 4 else None,
        **({f"otx:{d}": deep.otx_domain(d) for d in q.domains[:3]} if q.kind in ("org", "domain") else {}),
        "kev_vendor": deep.kev_by_vendor(q.entity) if want_vuln and q.entity else None,
        "msf": deep.metasploit_search(q.entity) if want_vuln and q.entity else None,
        # Techniques, red/blue team
        "attack": deep.attack_lookup(q.entity) if q.kind in ("org", "vuln") and len(q.entity) >= 4 else None,
        "lolbas": deep.lolbas(q.entity) if q.kind == "org" and " " not in q.entity else None,
        "gtfo": deep.gtfobins(q.entity) if q.kind == "org" and " " not in q.entity else None,
    })
    # Leak sites / HIBP reveal the organisation's real domains (e.g. fptsoftware.com): check those too.
    found = {x["domain"].lower() for key in ("victims", "breaches") for x in _ok(res, key) if x.get("domain")}
    extra = sorted(found - set(q.domains))[:2]
    if extra:
        res.update(await _run({f"hr:{d}": search_infostealer(d) for d in extra}))

    local = [_feed_news(i) for i in list(RECENT.values())]
    dark_local = [n for n in local if n["source"] in DARKWEB_FEEDS]
    dark = rank(q, _ok(res, "dark") + dark_local, 6)
    dark_urls = {n["url"] for n in dark}
    pool = (_ok(res, "g_vi") + _ok(res, "g_en") + _ok(res, "bing") + _ok(res, "gdelt") + local
            + [_hn_news(h) for h in _ok(res, "hn")] + [_feed_news(i) for i in _ok(res, "tg")])
    news = [n for n in rank(q, pool, 14) if n["url"] not in dark_urls][:12]

    blocks = [f"🔎 <b>{html.escape(q.raw)}</b>\n🧠 Hiểu là: {q.describe() or html.escape(q.raw)}"]

    def section(title: str, items, fmt, limit: int, empty: str | None = None, joined: bool = False):
        if items is None:
            return
        if isinstance(items, Exception):
            blocks.append(f"{title}: <i>{html.escape(_err(items))}</i>")
        elif items:
            more = f" ({len(items)})" if len(items) > 1 else ""
            body = [fmt(x) for x in items[:limit]]
            blocks.extend([title + more + "\n" + "\n".join(body)] if joined else [title + more, *body])
        elif empty:
            blocks.append(f"{title}: <i>{empty}</i>")

    e = html.escape(q.brand or q.entity)
    if isinstance(res.get("group"), dict):
        blocks.append(format_group(res["group"]))
    elif isinstance(res.get("group"), Exception):
        blocks.append(f"🏴‍☠️ <b>Nhóm ransomware {html.escape(q.entity)}</b>: hồ sơ tạm không tải được "
                      f"({html.escape(_err(res['group']))}) · "
                      f'<a href="https://www.ransomware.live/group/{html.escape(q.entity.lower())}">xem trên ransomware.live</a>')

    def vuln_sections():
        kv = res.get("kev_vendor")
        if isinstance(kv, dict) and kv["total"]:
            ransom = f", {kv['ransomware']} được dùng trong ransomware" if kv["ransomware"] else ""
            blocks.append(f"🎯 <b>{kv['total']} lỗ hổng của '{html.escape(q.entity)}' đã bị khai thác thực tế</b> "
                          f"<i>(CISA KEV{ransom}; mới nhất trước)</i>\n" + "\n".join(format_kev_item(x) for x in kv["items"]))
        section("🛠 <b>Module Metasploit</b> <i>(đã vũ khí hóa)</i>", res.get("msf"), format_msf, 5, joined=True)
        section("🐞 <b>CVE 120 ngày qua (NVD)</b>", res.get("cves"), format_cve, 5)
        section("📦 <b>GitHub Advisories</b>", res.get("ghsa"), format_ghsa, 4)
        section("💣 <b>Exploit công khai (Exploit-DB)</b>", res.get("exploits"), format_exploit, 5, joined=True)

    for key, title, fmt in (("attack", "🎯 <b>Kỹ thuật tấn công &amp; phòng thủ (MITRE ATT&amp;CK + Atomic Red Team)</b>",
                             format_technique),
                            ("lolbas", "🦾 <b>LOLBAS (công cụ Windows bị lạm dụng)</b>", format_lolbas),
                            ("gtfo", "🐧 <b>GTFOBins (công cụ Linux bị lạm dụng)</b>", format_gtfo)):
        v = res.get(key)
        section(title, [v] if isinstance(v, dict) else v, fmt, 3, joined=True)
    if "vuln" in q.topics:
        vuln_sections()
    if q.kind in ("org", "domain"):
        hr = [v for k, v in res.items() if k.startswith("hr:")]
        hr_hits = sorted((v for v in hr if isinstance(v, dict)), key=lambda h: -h["total"])
        hr_items = hr_hits if hr_hits or not hr or not all(isinstance(v, Exception) for v in hr) else hr[0]
        own = set(q.domains) | found
        look = res.get("lookalike")
        if isinstance(look, list):  # hide the organisation's own (sub)domains
            look = [d for d in look if not any(d["host"] == o or d["host"].endswith("." + o) for o in own)]
        section("🏴‍☠️ <b>Leak site ransomware</b>", res.get("victims"), format_victim, 5, f"không thấy '{e}'")
        section("🕵️ <b>Infostealer (Hudson Rock)</b>", hr_items, format_infostealer, 4,
                "không thấy " + ", ".join(q.domains + extra))
        section("💧 <b>Rò rỉ dữ liệu (HIBP)</b>", res.get("breaches"), format_breach, 5, f"không thấy '{e}'")
        section("💾 <b>CSDL bị lộ trên dark web (RansomLook, chỉ metadata)</b>", res.get("leaks"), format_leak, 5,
                f"không thấy '{e}'")
        section(f"🎣 <b>Domain mới chứa '{e}' (30 ngày, có thể giả mạo)</b>", look, format_lookalike, 12,
                "không có", joined=True)
        section(f"🪝 <b>Trang web dùng tên '{e}' vừa bị quét</b> <i>(urlscan.io, 60 ngày; kiểm tra trước khi tin)</i>",
                res.get("phish"), format_urlscan, 8, joined=True)
        section("🚨 <b>URL lừa đảo đang hoạt động</b> <i>(OpenPhish)</i>", res.get("openphish"), format_phish_url, 8,
                joined=True)
        otx = [v for k, v in res.items() if k.startswith("otx:") and isinstance(v, dict) and v["count"]]
        section("🕸 <b>Báo cáo threat intel nhắc tới domain</b> <i>(AlienVault OTX)</i>", otx, format_otx_domain, 3)
    if p := res.get("pay"):
        if isinstance(p, dict):
            blocks.append(f"💰 <b>Tiền chuộc ghi nhận on-chain</b> (ransomwhe.re): <b>${p['usd']:,.0f}</b> qua "
                          f"{p['payments']} giao dịch, {p['addresses']} ví")
    recent = res.get("recent")
    if isinstance(recent, list):
        recent = [v for v in recent if q.kind != "country" or v["country"] == "VN"]
        section("🏴‍☠️ <b>Nạn nhân ransomware mới nhất" + (" tại Việt Nam" if q.kind == "country" else "") + "</b>",
                recent, format_victim, 5, "không có trong 100 bài mới nhất")
    total = sum(len(_ok(res, k)) for k in ("g_vi", "g_en", "bing", "gdelt", "hn", "tg", "dark"))
    section(f"📰 <b>Tin liên quan nhất</b> <i>(lọc từ {total} kết quả + {len(local)} tin RSS gần đây)</i>",
            news, format_ranked, 12, "không có tin nào thật sự nói về chủ đề này", joined=True)
    section("🌑 <b>Tin dark web (leak site, forum, chợ đen)</b>", dark, format_ranked, 6, joined=True)
    if "vuln" not in q.topics:
        vuln_sections()

    mentioned = collections.Counter(c for n in news + dark for c in find_cves(f"{n['title']} {n.get('summary', '')}"))
    if mentioned:
        blocks.append("🧬 CVE được nhắc trong kết quả: " + ", ".join(
            f"<code>{c}</code> ({n})" for c, n in mentioned.most_common(4)) + "\n<i>Tra sâu: /research CVE-…</i>")
    failed = [f"{k} ({_err(v)})" for k, v in res.items() if isinstance(v, Exception)
              and not k.startswith("hr:") and k not in ("victims", "breaches", "leaks", "lookalike", "cves", "ghsa",
                                                        "exploits", "group", "gdelt", "pay", "phish",
                                                        "openphish", "kev_vendor", "msf")
              and not k.startswith("otx:")]
    if failed:
        blocks.append("<i>Nguồn lỗi/giới hạn: " + html.escape(", ".join(failed)) + "</i>")
    return q, blocks
