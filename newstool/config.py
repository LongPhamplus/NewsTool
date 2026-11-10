import os
from dataclasses import dataclass, field

import yaml
from dotenv import load_dotenv


IMPORTANT_DEFAULT = ["watch", "ransomware", "kev", "breach", "incident", "vuln", "malware"]


@dataclass
class Feed:
    name: str
    url: str
    category: str
    lang: str = "en"
    every_minutes: int = 0  # 0 = every poll; >0 = poll this feed less often


@dataclass
class TgChannel:
    username: str
    category: str = "security"
    lang: str = "en"
    tags: list[str] = field(default_factory=list)
    filter: str | list | None = None  # None = all, "watch" = watchlist only, [keywords] = keywords or watchlist


@dataclass
class Config:
    token: str
    chat_id: int
    poll_minutes: int
    intel_poll_minutes: int
    max_age_hours: int
    max_per_push: int
    state_path: str
    feeds: list[Feed]
    rules: dict[str, list[str]]
    watch: list[str] = field(default_factory=list)
    ransomware: bool = True
    ransomware_countries: list[str] = field(default_factory=list)
    kev: bool = True
    important_tags: set[str] = field(default_factory=set)
    digest_minutes: int = 60
    tg_api_id: int = 0
    tg_api_hash: str = ""
    tg_session: str = "newstool"
    tg_auto_join: bool = True
    tg_channels: list[TgChannel] = field(default_factory=list)

    @property
    def telegram_ready(self) -> bool:
        return bool(self.tg_api_id and self.tg_api_hash and self.tg_channels)
    breaches: bool = True

    @property
    def all_tags(self) -> list[str]:
        cats = sorted({f.category for f in self.feeds})
        extra = ["vn"] if any(f.lang == "vi" for f in self.feeds) else []
        extra += [tag for tag, on in (("ransomware", self.ransomware), ("breach", self.breaches),
                                      ("kev", self.kev)) if on]
        return cats + list(self.rules) + extra


def load(path: str = "config.yaml") -> Config:
    load_dotenv()
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    intel = raw.get("intel") or {}
    notify = raw.get("notify") or {}
    tg = raw.get("telegram") or {}
    chat = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    return Config(
        token=(os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip(),
        chat_id=int(chat) if chat else 0,
        poll_minutes=int(raw.get("poll_minutes", 3)),
        intel_poll_minutes=int(raw.get("intel_poll_minutes", 15)),
        max_age_hours=int(raw.get("max_age_hours", 48)),
        max_per_push=int(raw.get("max_per_push", 40)),
        state_path=raw.get("state_path", "state.db"),
        feeds=[Feed(**f) for f in raw.get("feeds", [])],
        rules={k: [str(x).lower() for x in v] for k, v in (raw.get("rules") or {}).items()},
        watch=[str(x).lower() for x in raw.get("watch") or []],
        ransomware=bool(intel.get("ransomware", True)),
        ransomware_countries=[str(c).upper() for c in intel.get("ransomware_countries", ["VN"])],
        kev=bool(intel.get("kev", True)),
        breaches=bool(intel.get("breaches", True)),
        important_tags=set(notify.get("important", IMPORTANT_DEFAULT)),
        digest_minutes=int(notify.get("digest_minutes", 60)),
        tg_api_id=int((os.environ.get("TG_API_ID") or "0").strip() or 0),
        tg_api_hash=(os.environ.get("TG_API_HASH") or "").strip(),
        tg_session=tg.get("session", "newstool"),
        tg_auto_join=bool(tg.get("auto_join", True)),
        tg_channels=[TgChannel(**c) for c in tg.get("channels") or []] if tg.get("enabled", True) else [],
    )
