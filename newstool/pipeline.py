import calendar
import logging
import time

from .classify import Classifier
from .config import Config
from .fetcher import fetch_all, title_key
from .formatter import rank
from .intel import all_breaches, breach, kev_catalog, recent_ransomware
from .state import State

log = logging.getLogger(__name__)

# In-memory source health for /sources: name -> {"at", "error", "count", "unchanged"}
STATUS: dict[str, dict] = {}


def _status(name: str, error: str | None = None, count: int = 0, unchanged: bool = False) -> None:
    STATUS[name] = {"at": int(time.time()), "error": error, "count": count, "unchanged": unchanged}


def _accept(cfg: Config, state: State, source: str, items: list[dict]) -> list[dict]:
    """Return items never seen before and recent enough; remember all of them."""
    cutoff = int(time.time()) - cfg.max_age_hours * 3600
    seeding = not state.seeded(source)
    new = [i for i in items if state.mark(i["uid"], i["title_key"]) and not seeding and i["published"] >= cutoff]
    state.set_seeded(source)
    state.commit()
    return new


def _due(feed) -> bool:
    last = STATUS.get(feed.name, {}).get("at", 0)
    return not feed.every_minutes or time.time() - last >= feed.every_minutes * 60 - 30


async def fetch_feeds(cfg: Config, state: State, clf: Classifier, force: bool = False) -> list[dict]:
    new = []
    for feed, res in await fetch_all([f for f in cfg.feeds if force or _due(f)]):
        if isinstance(res, Exception):
            log.warning("feed %s lỗi: %r", feed.name, res)
            _status(feed.name, error=repr(res))
            continue
        if res is None:  # HTTP 304: feed unchanged since last poll
            STATUS.setdefault(feed.name, {"count": 0, "error": None})
            STATUS[feed.name].update(at=int(time.time()), unchanged=True)
            continue
        for item in res:
            item["tags"] = clf.tags(item["title"], item["summary"], feed.category, feed.lang)
        new += _accept(cfg, state, feed.name, res)
        _status(feed.name, count=len(res))
    return new


async def fetch_intel(cfg: Config, state: State, clf: Classifier) -> list[dict]:
    new = []
    for enabled, source, loader in ((cfg.ransomware, "ransomware.live", _ransomware_items),
                                    (cfg.breaches, "HaveIBeenPwned", _breach_items),
                                    (cfg.kev, "CISA KEV", _kev_items)):
        if not enabled:
            continue
        try:
            items = await loader(cfg, clf)
        except Exception as e:
            log.warning("%s lỗi: %r", source, e)
            _status(source, error=repr(e))
            continue
        new += _accept(cfg, state, source, items)
        _status(source, count=len(items))
    return new


def _item(source: str, uid: str, url: str, title: str, summary: str, published: int, tags: list[str]) -> dict:
    return {"uid": uid, "url": url, "title": title, "title_key": title_key(title),
            "summary": summary, "source": source, "published": published, "tags": tags}


def _watched(clf: Classifier, text: str) -> list[str]:
    return ["watch"] if clf.watch and clf.watch.search(text) else []


async def _ransomware_items(cfg: Config, clf: Classifier) -> list[dict]:
    """Leak-site victims in the watched countries or matching the watchlist."""
    out = []
    for v in await recent_ransomware():
        watch = _watched(clf, f"{v['victim']} {v['domain']}")
        if v["country"] not in cfg.ransomware_countries and not watch:
            continue
        title = f"{v['victim']} bị nhóm {v['group']} đăng lên leak site"
        summary = " · ".join(x for x in (v["domain"], v["country"], v["activity"], v["description"][:300]) if x)
        tags = ["ransomware", "incident"] + (["vn"] if v["country"] == "VN" else []) + watch
        out.append(_item("ransomware.live", v["url"] or f"rl:{v['group']}:{v['victim']}", v["url"],
                         title, summary, v["discovered"], tags))
    return out


async def _breach_items(cfg: Config, clf: Classifier) -> list[dict]:
    out = []
    for raw in await all_breaches(max_age=0):
        b = breach(raw)
        title = f"Rò rỉ dữ liệu {b['title']}: {b['pwn_count']:,} tài khoản ({b['breach_date']})"
        summary = f"{b['domain']} · Dữ liệu: {', '.join(b['data'][:8])} · {b['description'][:300]}"
        tags = (["breach", "incident"] + (["vn"] if b["domain"].endswith(".vn") else [])
                + _watched(clf, f"{b['title']} {b['domain']}"))
        out.append(_item("HaveIBeenPwned", f"hibp:{b['name']}", b["url"], title, summary, b["added"], tags))
    return out


async def _kev_items(cfg: Config, clf: Classifier) -> list[dict]:
    out = []
    for cve, v in (await kev_catalog(max_age=0)).items():
        title = f"Đang bị khai thác: {cve} – {v['vulnerabilityName']}"
        ransom = " · Được dùng trong ransomware" if v.get("knownRansomwareCampaignUse") == "Known" else ""
        summary = f"{cve} · {v.get('shortDescription', '')}{ransom}"
        added = calendar.timegm(time.strptime(v["dateAdded"], "%Y-%m-%d"))
        tags = ["kev", "vuln", "security"] + _watched(clf, f"{v['vendorProject']} {v['product']}")
        out.append(_item("CISA KEV", f"kev:{cve}", f"https://nvd.nist.gov/vuln/detail/{cve}",
                         title, summary, added, tags))
    return out


def muted(state: State) -> set[str]:
    # Stored as a mute list so tags added later (new feeds/rules) are on by default.
    return set(state.get("muted", []))


def subscribed(cfg: Config, state: State) -> set[str]:
    return set(cfg.all_tags) - muted(state)


def select(cfg: Config, state: State, items: list[dict]) -> list[dict]:
    """Items the user wants, most important first."""
    subs = subscribed(cfg, state)
    return sorted((i for i in items if "watch" in i["tags"] or subs.intersection(i["tags"])), key=rank)
