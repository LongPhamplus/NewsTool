import asyncio
import html
import logging

from telegram import LinkPreviewOptions, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, filters

from .classify import Classifier
from .config import Config
from .formatter import EMOJI, ago, format_messages, pack
from .intel import RateLimited
from .query import parse
from .research import profile_kind, research
from .search import smart_search
from .pipeline import STATUS, remember, fetch_feeds, fetch_intel, muted, select, subscribed
from .state import State

log = logging.getLogger(__name__)
NO_PREVIEW = LinkPreviewOptions(is_disabled=True)

HELP = """<b>NewsTool</b> – tin công nghệ &amp; bảo mật
/search &lt;câu hỏi&gt; – tìm kiếm thông minh về tổ chức/sản phẩm/chủ đề: leak site, infostealer, CSDL bị lộ, trang lừa đảo giả danh, CVE nguy hiểm nhất, tin tức, dark web. VD: <code>/search vụ FPT bị tấn công ransomware</code>
/research &lt;CVE | tên lỗ hổng | nhóm APT | malware | nhóm ransomware | kỹ thuật&gt; – nghiên cứu sâu: đánh giá ưu tiên vá, dòng thời gian, PoC/Metasploit, threat intel, giải thích kỹ thuật. VD: <code>/research react2shell</code>, <code>/research apt32</code>, <code>/research 301 status code bypass</code>, <code>/research kerberoasting</code>
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
        urgent = [i for i in wanted if cfg.important_tags.intersection(i["tags"])
                  and (i.get("alert", "all") == "all" or {"watch", "vn"}.intersection(i["tags"]))]
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
    remember(items)
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


RESEARCH_FLAGS = {"--research", "--reseach", "--reasearch", "-r"}


async def cmd_research(update: Update, context: ContextTypes.DEFAULT_TYPE, query: str | None = None) -> None:
    query = (query if query is not None else " ".join(context.args)).strip()
    if not query:
        await update.message.reply_html(
            "Dùng: /research &lt;CVE hoặc tên lỗ hổng&gt;\nVD: <code>/research CVE-2025-55182</code>, "
            "<code>/research react2shell</code>, <code>/research log4shell</code>, <code>/research spring4shell</code>")
        return
    await update.message.reply_text(f"🔬 Đang nghiên cứu '{query}' trên ~25 nguồn, thường mất 10–40 giây...")
    blocks = await research(query, context.bot_data.get("tg"))
    await _send(context.bot, update.effective_chat.id, pack(blocks))


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg, _ = _ctx(context)
    args = list(context.args)
    if args and args[0].lower() in RESEARCH_FLAGS:
        await cmd_research(update, context, " ".join(args[1:]))
        return
    text = " ".join(args).strip()
    if not text:
        await update.message.reply_html(
            "Dùng: /search &lt;câu hỏi tự nhiên&gt; [--days N]\nVD: <code>/search vụ FPT bị tấn công ransomware</code>, "
            "<code>/search Vietcombank lừa đảo</code>, <code>/search vietcombank.com.vn</code>, "
            "<code>/search akira</code> (nhóm ransomware), <code>/search rò rỉ dữ liệu Việt Nam --days 30</code>, "
            "<code>/search fortinet lỗ hổng</code>\nTên lỗ hổng/CVE (react2shell, CVE-…) tự chuyển sang /research.")
        return
    q = parse(text)
    if q.kind in ("cve", "vuln"):  # a vulnerability is best served by the research view
        await cmd_research(update, context, q.entity)
        return
    if q.kind == "org" and not q.topics and len(q.entity.split()) <= 3:
        prof = await profile_kind(q.entity)  # APT group / malware family -> profile view
        if prof and prof[0] in ("actor", "malware"):
            await cmd_research(update, context, q.entity)
            return
    await update.message.reply_html(f"🔎 Đang tìm… {q.describe() or html.escape(text)} (20–40 giây)")
    _, blocks = await smart_search(text, cfg, context.bot_data.get("tg"))
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


async def warmup_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Pre-load the big reference datasets so the first /search or /research of the day is fast."""
    from . import deep
    from .intel import exploitdb, group_names, kev_catalog
    jobs = {"ransomware groups": group_names(), "KEV": kev_catalog(), "Exploit-DB": exploitdb(),
            "Metasploit": deep._msf_index(), "ransomwhe.re": deep.ransom_payments("_"),
            **{f"MISP {n}": deep._cluster(n) for n in ("threat-actor", "malpedia", "ransomware")}}
    results = await asyncio.gather(*jobs.values(), return_exceptions=True)
    failed = [f"{k} ({type(r).__name__})" for k, r in zip(jobs, results) if isinstance(r, Exception)]
    log.info("Đã nạp sẵn dữ liệu tra cứu%s", f", lỗi: {', '.join(failed)}" if failed else "")


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


async def _flush_on_stop(app: Application) -> None:
    # The digest buffer lives in memory only: send it before shutting down instead of losing it.
    # Runs in post_stop, while the bot's HTTP client is still open (post_shutdown is too late).
    try:
        if app.bot_data.get("cfg") and app.bot_data["cfg"].chat_id and app.bot_data.get("digest"):
            await flush_digest(app)
    except Exception:
        log.exception("gửi tóm tắt khi tắt bot thất bại")


async def _stop_telegram(app: Application) -> None:
    if watcher := app.bot_data.get("tg"):
        await watcher.stop()


def build(cfg: Config) -> Application:
    app = (Application.builder().token(cfg.token).post_init(_start_telegram)
           .post_stop(_flush_on_stop).post_shutdown(_stop_telegram).build())
    app.bot_data.update(
        cfg=cfg, state=State(cfg.state_path), clf=Classifier(cfg.rules, cfg.watch), lock=asyncio.Lock(), digest=[])
    app.add_handler(CommandHandler("start", cmd_start))
    if not cfg.chat_id:
        log.warning("TELEGRAM_CHAT_ID chưa đặt: gửi /start cho bot để lấy chat id.")
        return app
    owner = filters.Chat(chat_id=cfg.chat_id)  # bot chỉ trả lời bạn
    for name, fn in [("help", cmd_help), ("search", cmd_search), ("research", cmd_research),
                     ("topics", cmd_topics), ("sub", cmd_sub), ("unsub", cmd_unsub),
                     ("fetch", cmd_fetch), ("digest", cmd_digest), ("sources", cmd_sources)]:
        app.add_handler(CommandHandler(name, fn, filters=owner))
    # Telegram start-up (joining channels) can delay the scheduler; run late jobs instead of skipping them.
    late_ok = {"misfire_grace_time": 120, "coalesce": True}
    app.job_queue.run_repeating(feeds_job, interval=cfg.poll_minutes * 60, first=5, job_kwargs=late_ok)
    app.job_queue.run_repeating(intel_job, interval=cfg.intel_poll_minutes * 60, first=20, job_kwargs=late_ok)
    app.job_queue.run_repeating(warmup_job, interval=12 * 3600, first=60, job_kwargs=late_ok)
    if cfg.digest_minutes > 0:
        app.job_queue.run_repeating(digest_job, interval=cfg.digest_minutes * 60, first=cfg.digest_minutes * 60,
                                    job_kwargs=late_ok)
    return app
