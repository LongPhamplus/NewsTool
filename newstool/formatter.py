import html
import time

from .classify import cves

EMOJI = {
    "watch": "🔔", "incident": "🔥", "vuln": "🐞", "malware": "🦠",
    "ai": "🤖", "security": "🛡", "tech": "💻", "vn": "🇻🇳",
    "ransomware": "🏴‍☠️", "breach": "💧", "kev": "⚠️",
}
PRIORITY = ["watch", "ransomware", "kev", "breach", "incident", "vuln", "malware"]
MAX_LEN = 3900  # Telegram limit is 4096


def ago(ts: int) -> str:
    d = max(0, int(time.time()) - ts)
    if d < 3600:
        return f"{d // 60} phút trước"
    if d < 86400:
        return f"{d // 3600} giờ trước"
    return f"{d // 86400} ngày trước"


def rank(item: dict) -> tuple:
    tags = item["tags"]
    pri = next((i for i, t in enumerate(PRIORITY) if t in tags), len(PRIORITY))
    return (pri, -item["published"])


def format_item(item: dict) -> str:
    icons = "".join(EMOJI.get(t, "") for t in item["tags"] if t in EMOJI)
    tags = " ".join(f"#{t}" for t in item["tags"])
    lines = [
        f'{icons} <a href="{html.escape(item["url"])}"><b>{html.escape(item["title"])}</b></a>',
        f"<i>{html.escape(item['source'])}</i> · {ago(item['published'])} · {tags}",
    ]
    ids = cves(item["title"] + " " + item["summary"])
    if ids:
        lines.append("<code>" + ", ".join(ids[:5]) + "</code>")
    return "\n".join(lines)


def format_messages(items: list[dict], header: str | None = None) -> list[str]:
    head = [f"<b>{html.escape(header)}</b>"] if header else []
    return pack(head + [format_item(i) for i in items])


def format_news_line(n: dict) -> str:
    return (f'• <a href="{html.escape(n["url"])}">{html.escape(n["title"])}</a>'
            f" — <i>{html.escape(n['source'])}</i>, {ago(n['published'])}")


def format_victim(v: dict) -> str:
    lines = [f"🏴‍☠️ <b>{html.escape(v['victim'])}</b> ← nhóm <b>{html.escape(v['group'])}</b>"]
    meta = " · ".join(x for x in (v["domain"], v["country"], v["activity"]) if x)
    if meta:
        lines.append(html.escape(meta))
    lines.append(f"Phát hiện: {time.strftime('%d/%m/%Y', time.localtime(v['discovered']))}"
                 + (f' · <a href="{html.escape(v["url"])}">chi tiết</a>' if v["url"] else ""))
    if v["description"]:
        lines.append(f"<i>{html.escape(v['description'][:250])}</i>")
    return "\n".join(lines)


def pack(blocks: list[str]) -> list[str]:
    """Join blocks into as few Telegram messages as possible."""
    messages, buf = [], ""
    for block in blocks:
        if buf and len(buf) + len(block) + 2 > MAX_LEN:
            messages.append(buf)
            buf = ""
        buf = f"{buf}\n\n{block}" if buf else block
    if buf:
        messages.append(buf)
    return messages


def _date(ts: int) -> str:
    return time.strftime("%d/%m/%Y", time.localtime(ts))


def format_breach(b: dict) -> str:
    lines = [f"💧 <b>{html.escape(b['title'])}</b> – {b['pwn_count']:,} tài khoản",
             f"{html.escape(b['domain'] or '?')} · xảy ra {html.escape(b['breach_date'])}"
             f' · <a href="{html.escape(b["url"])}">HIBP</a>']
    if b["data"]:
        lines.append("Lộ: " + html.escape(", ".join(b["data"][:8])))
    return "\n".join(lines)


def format_cve(c: dict) -> str:
    score = c["score"]
    sev = "⚪" if score is None else "🔴" if score >= 9 else "🟠" if score >= 7 else "🟡" if score >= 4 else "🟢"
    kev = " ⚠️ <b>đang bị khai thác</b>" if c["kev"] else ""
    if c.get("exploits"):
        e = c["exploits"][0]
        kev += f' 💣 <a href="{html.escape(e["url"])}">exploit công khai</a>'
    return (f'{sev} <a href="{html.escape(c["url"])}"><b>{c["id"]}</b></a> '
            f"({score if score is not None else '?'}) · {_date(c['published'])}{kev}\n"
            f"<i>{html.escape(c['description'][:200])}</i>")


def format_hn(h: dict) -> str:
    link = f' · <a href="{html.escape(h["url"])}">bài gốc</a>' if h["url"] else ""
    return (f'• <a href="{html.escape(h["hn_url"])}">{html.escape(h["title"])}</a>'
            f" — {h['points']}▲ {h['comments']}💬, {_date(h['published'])}{link}")


def format_infostealer(h: dict) -> str:
    last = [f"{label} {_date(t)}" for label, t in (("nhân viên", h["last_employee"]), ("người dùng", h["last_user"])) if t]
    return (f'🕵️ <b>{html.escape(h["domain"])}</b>: {h["total"]:,} thông tin đăng nhập bị infostealer lấy cắp\n'
            f"Nhân viên {h['employees']:,} · người dùng {h['users']:,} · bên thứ ba {h['third_parties']:,}\n"
            + (f"Lần lộ gần nhất: {', '.join(last)} · " if last else "")
            + f'<a href="{html.escape(h["url"])}">Hudson Rock</a>')


def format_lookalike(d: dict) -> str:
    return f"• <code>{html.escape(d['host'])}</code> — cert {_date(d['issued'])}"


SEV = {"critical": "🔴", "high": "🟠", "moderate": "🟡", "medium": "🟡", "low": "🟢"}


def format_ghsa(a: dict) -> str:
    pkgs = f" · {html.escape(', '.join(a['packages'][:3]))}" if a["packages"] else ""
    cve = f" ({a['cve']})" if a["cve"] else ""
    return (f'{SEV.get(a["severity"], "⚪")} <a href="{html.escape(a["url"])}">{a["id"]}</a>{cve}{pkgs} · '
            f"{_date(a['published'])}\n<i>{html.escape(a['summary'][:160])}</i>")


def format_exploit(e: dict) -> str:
    cves = f" · {', '.join(e['cves'][:2])}" if e["cves"] else ""
    return (f'• <a href="{html.escape(e["url"])}">{html.escape(e["title"][:110])}</a>'
            f" — {e['date']} · {html.escape(e['type'])}/{html.escape(e['platform'])}{cves}")
