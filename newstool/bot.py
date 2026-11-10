import asyncio
import html
import logging

from telegram import LinkPreviewOptions, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, filters

from .classify import Classifier
from .config import Config
from .formatter import (EMOJI, ago, format_breach, format_cve, format_exploit, format_ghsa, format_hn,
                        format_infostealer, format_item, format_lookalike, format_messages, format_news_line, format_victim,
                        pack, rank)
from .intel import (RateLimited, search_breaches, search_cves, search_exploits, search_gdelt, search_ghsa,
                    search_hn, search_infostealer, search_lookalikes, search_news, search_ransomware)
from .pipeline import STATUS, fetch_feeds, fetch_intel, muted, select, subscribed
from .state import State

log = logging.getLogger(__name__)
NO_PREVIEW = LinkPreviewOptions(is_disabled=True)

HELP = """<b>NewsTool</b> – tin công nghệ &amp; bảo mật
/search &lt;từ khóa&gt; – tra cứu tổng hợp: leak site ransomware, rò rỉ dữ liệu (HIBP), CVE (NVD + CISA KEV), Google News VI/EN, Hacker News
/topics – xem các topic đang bật
/sub &lt;tag&gt; · /unsub &lt;tag&gt; – bật/tắt topic
/fetch – lấy tin ngay
/digest – gửi ngay bản tóm tắt tin thường đang chờ
/sources – trạng thái các nguồn"""


def _ctx(context: ContextTypes.DEFAULT_TYPE) -> tuple[Config, State]:
    return context.bot_data["cfg"], context.bot_data["state"]


async def _send(bot, chat_id: int, messages: list[str], silent: bool = False) -> None:
    for msg in messages:
        await bot.send_message(chat_id, msg, parse_mode=ParseMode.HTML, link_preview_options=NO_PREVIEW,
                               disable_notification=silent)


async def push(app: Application, feeds: bool = True, intel: bool = True) -> int:
    """Fetch sources and send whatever is new right away. Nothing is stored except seen-fingerprints."""
    cfg, state, clf = app.bot_data["cfg"], app.bot_data["state"], app.bot_data["clf"]
    async with app.bot_data["lock"]:
        items = (await fetch_feeds(cfg, state, clf) if feeds else []) + \
                (await fetch_intel(cfg, state, clf) if intel else [])
        return await deliver(app, items)


async def deliver(app: Application, items: list[dict], header: str | None = None) -> int:
    """Send new items: important ones now (with sound), the rest into the silent digest."""
    cfg, state = app.bot_data["cfg"], app.bot_data["state"]
    wanted = select(cfg, state, items)
    if cfg.digest_minutes > 0:
        urgent = [i for i in wanted if cfg.important_tags.intersection(i["tags"])]
        app.bot_data["digest"].extend(i for i in wanted if i not in urgent)
    else:
        urgent = wanted
    to_send = urgent[: cfg.max_per_push]
    if to_send:
        if header is None:
            header = f"🚨 {len(to_send)} tin quan trọng" if cfg.digest_minutes > 0 else f"📰 {len(to_send)} tin mới"
        if len(urgent) > len(to_send):
            header += f" (bỏ qua {len(urgent) - len(to_send)} tin ít quan trọng hơn)"
        await _send(app.bot, cfg.chat_id, format_messages(to_send, header))
    return len(to_send)


async def on_telegram_items(app: Application, items: list[dict]) -> None:
    """Called by the Telegram watcher the moment a monitored channel posts."""
    state = app.bot_data["state"]
    async with app.bot_data["lock"]:
        new = [i for i in items if state.mark(i["uid"], i["title_key"])]
        state.commit()
        if new:
            await deliver(app, new, header=f"📢 Telegram {new[0]['source']}")


async def flush_digest(app: Application) -> int:
    """Send the buffered non-urgent items silently. The buffer lives only in memory."""
    cfg, buf = app.bot_data["cfg"], app.bot_data["digest"]
    items, buf[:] = sorted(buf, key=lambda i: -i["published"]), []
    if not items:
        return 0
    shown = items[:cfg.max_per_push]
    header = f"🗞 Tóm tắt: {len(items)} tin"
    if len(items) > len(shown):
        header += f" (hiện {len(shown)} tin mới nhất)"
    await _send(app.bot, cfg.chat_id, format_messages(shown, header), silent=True)
    return len(items)


async def digest_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        log.info("digest: %d tin", await flush_digest(context.application))
    except Exception:
        log.exception("digest thất bại")


async def feeds_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        n = await push(context.application, intel=False)
        log.info("RSS: gửi ngay %d tin, %d tin chờ tóm tắt", n, len(context.application.bot_data["digest"]))
    except Exception:
        log.exception("poll RSS thất bại")


async def intel_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        n = await push(context.application, feeds=False)
        log.info("intel: gửi ngay %d tin, %d tin chờ tóm tắt", n, len(context.application.bot_data["digest"]))
    except Exception:
        log.exception("poll intel thất bại")


# ---- commands ----
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg, _ = _ctx(context)
    chat_id = update.effective_chat.id
    if not cfg.chat_id:
        await update.message.reply_html(
            f"Chat id của bạn: <code>{chat_id}</code>\n"
            "Đặt <code>TELEGRAM_CHAT_ID</code> trong file .env rồi khởi động lại bot.")
    elif chat_id == cfg.chat_id:
        await update.message.reply_html(HELP)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_html(HELP)


def _err(e: Exception) -> str:
    return str(e) if isinstance(e, RateLimited) else f"lỗi: {type(e).__name__}"


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg, _ = _ctx(context)
    kw = " ".join(context.args).strip()
    if not kw:
        await update.message.reply_html(
            "Dùng: /search &lt;từ khóa&gt;\nVD: <code>/search FPT</code>, <code>/search vietcombank.com.vn</code>, "
            "<code>/search fortinet</code>, <code>/search Vietcombank lừa đảo</code>\n"
            "Từ đầu tiên là tên tổ chức/sản phẩm (hoặc domain) để tra leak site, infostealer, rò rỉ, domain giả mạo.")
        return
    watcher = context.bot_data.get("tg")
    n_src = 13 + (1 if watcher else 0)
    await update.message.reply_text(f"🔎 Đang tìm '{kw}' trên {n_src} nguồn, có thể mất 20–40 giây...")
    entity = kw.split()[0].lower()
    brand = entity.split(".")[0]
    guesses = [entity] if "." in entity else [f"{entity}.{tld}" for tld in ("com", "vn", "com.vn")]

    async def run(lookups: dict) -> dict:
        lookups = {k: v for k, v in lookups.items() if v is not None}
        return dict(zip(lookups, await asyncio.gather(*lookups.values(), return_exceptions=True)))

    res = await run({
        "victims": search_ransomware(brand) if cfg.ransomware else None,
        "breaches": search_breaches(brand) if cfg.breaches else None,
        "lookalike": search_lookalikes(brand),
        "cves": search_cves(kw), "ghsa": search_ghsa(kw), "exploits": search_exploits(kw),
        "vi": search_news(kw, "vi", 6), "en": search_news(kw, "en", 6), "gdelt": search_gdelt(kw),
        "hn": search_hn(kw),
        "tg": watcher.search(kw) if watcher else None,
        **{f"hr:{d}": search_infostealer(d) for d in guesses},
    })
    # Leak sites / HIBP reveal the organisation's real domains (e.g. fptsoftware.com): check those too.
    found = {x["domain"].lower() for key in ("victims", "breaches") if isinstance(res.get(key), list)
             for x in res[key] if x.get("domain")}
    extra = sorted(found - set(guesses))[:2]
    res.update(await run({f"hr:{d}": search_infostealer(d) for d in extra}))

    blocks = [f"🔎 <b>{html.escape(kw)}</b>"]

    def section(key: str, title: str, fmt, limit: int, empty: str | None = None, joined: bool = False,
                items=None):
        r = res.get(key) if items is None else items
        if r is None:
            return
        if isinstance(r, Exception):
            blocks.append(f"{title}: <i>{html.escape(_err(r))}</i>")
        elif r:
            more = f" ({len(r)})" if len(r) > 1 else ""
            if joined:
                blocks.append(f"{title}{more}\n" + "\n".join(fmt(x) for x in r[:limit]))
            else:
                blocks.append(title + more)
                blocks.extend(fmt(x) for x in r[:limit])
        elif empty:
            blocks.append(f"{title}: <i>{empty}</i>")

    e = html.escape(brand)
    hr = [v for k, v in res.items() if k.startswith("hr:")]
    hr_hits = sorted((v for v in hr if isinstance(v, dict)), key=lambda h: -h["total"])
    hr_items = hr_hits if hr_hits or not all(isinstance(v, Exception) for v in hr) else hr[0]
    own = set(guesses) | found
    look = res.get("lookalike")
    if isinstance(look, list):  # hide the organisation's own (sub)domains
        look = [d for d in look if not any(d["host"] == o or d["host"].endswith("." + o) for o in own)]

    section("victims", "🏴‍☠️ <b>Leak site ransomware</b>", format_victim, 5, f"không thấy '{e}'")
    section("hr", "🕵️ <b>Infostealer (Hudson Rock)</b>", format_infostealer, 4,
            "không thấy " + ", ".join(guesses + extra), items=hr_items)
    section("breaches", "💧 <b>Rò rỉ dữ liệu (HIBP)</b>", format_breach, 5, f"không thấy '{e}'")
    section("lookalike", f"🎣 <b>Domain mới chứa '{e}' (30 ngày, có thể giả mạo)</b>", format_lookalike, 12,
            "không có", joined=True, items=look)
    section("cves", "🐞 <b>CVE 120 ngày qua (NVD)</b>", format_cve, 5)
    section("ghsa", "📦 <b>GitHub Advisories</b>", format_ghsa, 4)
    section("exploits", "💣 <b>Exploit công khai (Exploit-DB)</b>", format_exploit, 5, joined=True)
    section("vi", "📰 <b>Tin tức (VI)</b>", format_news_line, 6, joined=True)
    section("en", "📰 <b>News (EN)</b>", format_news_line, 6, joined=True)
    section("gdelt", "🌍 <b>Báo chí quốc tế (GDELT)</b>", format_news_line, 6, joined=True)
    section("hn", "💬 <b>Thảo luận Hacker News</b>", format_hn, 5, joined=True)
    section("tg", "📢 <b>Telegram channels</b>", format_item, 6)
    await _send(context.bot, update.effective_chat.id, pack(blocks))


async def cmd_topics(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg, state = _ctx(context)
    subs = subscribed(cfg, state)
    lines = [f"{'✅' if t in subs else '❌'} {EMOJI.get(t, '')} <code>{t}</code>" for t in cfg.all_tags]
    lines.append("🔔 <code>watch</code> – luôn bật: " + html.escape(", ".join(cfg.watch) or "(trống)"))
    await update.message.reply_html("\n".join(lines))


async def _toggle(update: Update, context: ContextTypes.DEFAULT_TYPE, on: bool) -> None:
    cfg, state = _ctx(context)
    if not context.args:
        await update.message.reply_html("Tag: " + ", ".join(f"<code>{t}</code>" for t in cfg.all_tags))
        return
    mute = muted(state)
    for tag in (a.lower().lstrip("#") for a in context.args):
        if tag not in cfg.all_tags:
            await update.message.reply_text(f"Không có tag '{tag}'.")
            return
        mute.discard(tag) if on else mute.add(tag)
    state.set("muted", sorted(mute))
    await cmd_topics(update, context)


async def cmd_sub(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle(update, context, True)


async def cmd_unsub(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle(update, context, False)


async def cmd_digest(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await flush_digest(context.application) == 0:
        await update.message.reply_text("Chưa có tin nào trong hàng chờ tóm tắt.")


async def cmd_fetch(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("⏳ Đang lấy tin...")
    n = await push(context.application)
    waiting = len(context.application.bot_data["digest"])
    if n == 0:
        await update.message.reply_text("Không có tin quan trọng mới."
                                        + (f" {waiting} tin thường đang chờ tóm tắt (/digest)." if waiting else ""))


async def cmd_sources(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg, _ = _ctx(context)
    lines = []
    intel = [n for n, on in (("ransomware.live", cfg.ransomware), ("HaveIBeenPwned", cfg.breaches),
                             ("CISA KEV", cfg.kev)) if on]
    names = [f.name for f in cfg.feeds] + intel + [f"tg:@{c.username}" for c in cfg.tg_channels]
    for name in names:
        s = STATUS.get(name)
        if s is None:
            lines.append(f"⏳ {html.escape(name)}")
        elif s["error"]:
            lines.append(f"❌ {html.escape(name)} – <i>{html.escape(s['error'][:80])}</i>")
        else:
            note = "không đổi" if s.get("unchanged") else f"{s['count']} mục"
            lines.append(f"✅ {html.escape(name)} – {note}, {ago(s['at'])}")
    await update.message.reply_html("\n".join(lines))


async def _start_telegram(app: Application) -> None:
    cfg = app.bot_data["cfg"]
    if not cfg.chat_id or not cfg.telegram_ready:
        if cfg.tg_channels and not cfg.tg_api_id:
            log.warning("Telegram channel: thiếu TG_API_ID/TG_API_HASH trong .env, bỏ qua")
        return
    from .tgwatch import ChannelWatcher

    async def on_items(items):
        await on_telegram_items(app, items)

    watcher = ChannelWatcher(cfg, app.bot_data["clf"], on_items)
    try:
        await watcher.start()
    except Exception as e:  # never let Telegram problems stop the RSS bot
        log.error("Telegram channel: không khởi động được: %s", e)
        await watcher.stop()
        return
    app.bot_data["tg"] = watcher


async def _stop_telegram(app: Application) -> None:
    # The digest buffer lives in memory only: send it before shutting down instead of losing it.
    try:
        if app.bot_data.get("cfg") and app.bot_data["cfg"].chat_id and app.bot_data.get("digest"):
            await flush_digest(app)
    except Exception:
        log.exception("gửi tóm tắt khi tắt bot thất bại")
    if watcher := app.bot_data.get("tg"):
        await watcher.stop()


def build(cfg: Config) -> Application:
    app = Application.builder().token(cfg.token).post_init(_start_telegram).post_shutdown(_stop_telegram).build()
    app.bot_data.update(
        cfg=cfg, state=State(cfg.state_path), clf=Classifier(cfg.rules, cfg.watch), lock=asyncio.Lock(), digest=[])
    app.add_handler(CommandHandler("start", cmd_start))
    if not cfg.chat_id:
        log.warning("TELEGRAM_CHAT_ID chưa đặt: gửi /start cho bot để lấy chat id.")
        return app
    owner = filters.Chat(chat_id=cfg.chat_id)  # bot chỉ trả lời bạn
    for name, fn in [("help", cmd_help), ("search", cmd_search),
                     ("topics", cmd_topics), ("sub", cmd_sub), ("unsub", cmd_unsub),
                     ("fetch", cmd_fetch), ("digest", cmd_digest), ("sources", cmd_sources)]:
        app.add_handler(CommandHandler(name, fn, filters=owner))
    # Telegram start-up (joining channels) can delay the scheduler; run late jobs instead of skipping them.
    late_ok = {"misfire_grace_time": 120, "coalesce": True}
    app.job_queue.run_repeating(feeds_job, interval=cfg.poll_minutes * 60, first=5, job_kwargs=late_ok)
    app.job_queue.run_repeating(intel_job, interval=cfg.intel_poll_minutes * 60, first=20, job_kwargs=late_ok)
    if cfg.digest_minutes > 0:
        app.job_queue.run_repeating(digest_job, interval=cfg.digest_minutes * 60, first=cfg.digest_minutes * 60,
                                    job_kwargs=late_ok)
    return app
