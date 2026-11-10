"""Real-time Telegram channel monitoring through the user's own account (Telethon / MTProto)."""
import asyncio
import logging
import re
import time

from telethon import TelegramClient, events, functions, types, utils

from .classify import Classifier, _compile
from .config import Config, TgChannel
from .fetcher import title_key
from .pipeline import STATUS, _status

log = logging.getLogger(__name__)
MUTE_FOREVER = 2**31 - 1
ARCHIVE_FOLDER = 1


def make_client(cfg: Config) -> TelegramClient:
    return TelegramClient(cfg.tg_session, cfg.tg_api_id, cfg.tg_api_hash)


async def login(cfg: Config) -> None:
    """Interactive one-time login (phone number, code, 2FA password). Creates the .session file."""
    def ask_phone() -> str:
        raw = input("Số điện thoại Telegram (vd 0912345678 hoặc +84912345678): ").strip().replace(" ", "")
        # Telegram needs the international format; assume Vietnam for local numbers starting with 0.
        return "+84" + raw[1:] if raw.startswith("0") else raw if raw.startswith("+") else "+" + raw

    client = make_client(cfg)
    await client.start(phone=ask_phone,
                       code_callback=lambda: input("Mã xác nhận Telegram vừa gửi (trong app Telegram): ").strip())
    me = await client.get_me()
    print(f"Đã đăng nhập: {me.first_name} (@{me.username or '-'}). Session: {cfg.tg_session}.session")
    await client.disconnect()


class ChannelWatcher:
    def __init__(self, cfg: Config, clf: Classifier, on_items):
        self.cfg, self.clf, self.on_items = cfg, clf, on_items
        self.client = make_client(cfg)
        self.by_peer: dict[int, tuple[TgChannel, object, re.Pattern | None]] = {}

    async def start(self) -> None:
        await self.client.connect()
        if not await self.client.is_user_authorized():
            raise RuntimeError("Telegram chưa đăng nhập: chạy `uv run newstool tg-login` trong terminal")
        for ch in self.cfg.tg_channels:
            name = f"tg:@{ch.username}"
            try:
                ent = await self.client.get_entity(ch.username)
                if self.cfg.tg_auto_join and getattr(ent, "left", False):
                    await self._join_quietly(ent)
                    await asyncio.sleep(2)  # joining is flood-limited
            except Exception as e:
                log.warning("%s lỗi: %r", name, e)
                _status(name, error=repr(e))
                continue
            keywords = ch.filter if isinstance(ch.filter, list) else []
            self.by_peer[utils.get_peer_id(ent)] = (ch, ent, _compile([str(k).lower() for k in keywords]))
            _status(name, count=0)
        self.client.add_event_handler(self._on_message, events.NewMessage(chats=list(self.by_peer)))
        me = await self.client.get_me()
        log.info("Telegram: theo dõi %d channel bằng tài khoản %s", len(self.by_peer),
                 f"@{me.username}" if me.username else me.first_name)

    async def stop(self) -> None:
        await self.client.disconnect()

    async def _join_quietly(self, ent) -> None:
        """Join so we receive real-time updates, then mute and archive so the phone stays quiet."""
        await self.client(functions.channels.JoinChannelRequest(ent))
        peer = await self.client.get_input_entity(ent)
        await self.client(functions.account.UpdateNotifySettingsRequest(
            peer=types.InputNotifyPeer(peer), settings=types.InputPeerNotifySettings(mute_until=MUTE_FOREVER)))
        await self.client.edit_folder(ent, ARCHIVE_FOLDER)
        log.info("Telegram: đã tham gia (tắt tiếng, lưu trữ) @%s", getattr(ent, "username", ent.id))

    def to_item(self, ch: TgChannel, msg) -> dict | None:
        text = (msg.raw_text or "").strip()
        if not text:
            return None
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        title = lines[0][:160]
        summary = " ".join(lines[1:])[:600]
        url = f"https://t.me/{ch.username}/{msg.id}"
        tags = self.clf.tags(title, summary, ch.category, ch.lang) + [t for t in ch.tags]
        return {"uid": url, "url": url, "title": title, "title_key": title_key(title), "summary": summary,
                "source": f"@{ch.username}", "published": int(msg.date.timestamp()),
                "tags": list(dict.fromkeys(tags))}

    def wanted(self, ch: TgChannel, kw: re.Pattern | None, item: dict) -> bool:
        """Apply the per-channel filter: none = everything, 'watch' = watchlist only, list = keywords or watchlist."""
        if ch.filter is None:
            return True
        if "watch" in item["tags"]:
            return True
        return bool(kw and kw.search(f"{item['title']}\n{item['summary']}"))

    async def _on_message(self, event) -> None:
        entry = self.by_peer.get(event.chat_id)
        if not entry:
            return
        ch, _, kw = entry
        st = STATUS.setdefault(f"tg:@{ch.username}", {"count": 0, "error": None})
        st.update(at=int(time.time()), count=st.get("count", 0) + 1)
        item = self.to_item(ch, event.message)
        if item and self.wanted(ch, kw, item):
            try:
                await self.on_items([item])
            except Exception:
                log.exception("Telegram: xử lý tin @%s thất bại", ch.username)

    async def search(self, query: str, per_channel: int = 3, days: int = 180) -> list[dict]:
        """Server-side full-text search in every monitored channel."""
        since = time.time() - days * 86400

        async def one(ch, ent):
            out = []
            async for msg in self.client.iter_messages(ent, search=query, limit=per_channel):
                if msg.date.timestamp() >= since and (item := self.to_item(ch, msg)):
                    out.append(item)
            return out

        results = await asyncio.gather(*(one(ch, ent) for ch, ent, _ in self.by_peer.values()),
                                       return_exceptions=True)
        items = [i for r in results if isinstance(r, list) for i in r]
        return sorted(items, key=lambda i: -i["published"])
