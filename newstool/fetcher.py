import asyncio
import calendar
import html
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser
import httpx

from .config import Feed

HEADERS = {"User-Agent": "NewsTool/0.1 (personal RSS reader)"}
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_TRACKING = ("utm_", "fbclid", "gclid", "ref", "source")


def clean_text(s: str) -> str:
    return _WS_RE.sub(" ", html.unescape(_TAG_RE.sub(" ", s or ""))).strip()


def normalize_url(url: str) -> str:
    p = urlsplit(url.strip())
    query = [(k, v) for k, v in parse_qsl(p.query) if not k.lower().startswith(_TRACKING)]
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/"), urlencode(query), ""))


_FALLBACK_FORMATS = ("%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S")


def parse_date(entry, feed: Feed) -> int | None:
    ts = entry.get("published_parsed") or entry.get("updated_parsed")
    if ts:
        return calendar.timegm(ts)
    raw = (entry.get("published") or entry.get("updated") or "").strip()
    # Non-standard dates carry no timezone; assume local time of the feed's country.
    tz = timezone(timedelta(hours=7)) if feed.lang == "vi" else timezone.utc
    for fmt in _FALLBACK_FORMATS:
        try:
            return int(datetime.strptime(raw, fmt).replace(tzinfo=tz).timestamp())
        except ValueError:
            continue
    return None


def title_key(title: str) -> str:
    return re.sub(r"\W+", "", title.lower())


# url -> validators from the last response, so unchanged feeds answer 304 with no body.
_VALIDATORS: dict[str, dict[str, str]] = {}


async def fetch_feed(client: httpx.AsyncClient, feed: Feed) -> list[dict] | None:
    """Parsed entries, or None if the feed hasn't changed since the previous fetch."""
    v = _VALIDATORS.get(feed.url, {})
    cond = {k: v[src] for k, src in (("If-None-Match", "etag"), ("If-Modified-Since", "last-modified")) if src in v}
    r = await client.get(feed.url, headers=cond)
    if r.status_code == 304:
        return None
    r.raise_for_status()
    _VALIDATORS[feed.url] = {h: r.headers[h] for h in ("etag", "last-modified") if h in r.headers}
    parsed = feedparser.parse(r.content)
    if parsed.bozo and not parsed.entries:
        raise ValueError(f"không parse được feed: {parsed.bozo_exception}")
    now = int(time.time())
    items = []
    for e in parsed.entries:
        link, title = e.get("link"), clean_text(e.get("title", ""))
        if not link or not title:
            continue
        published = parse_date(e, feed) or now
        items.append({
            "url": link,
            "uid": normalize_url(link),
            "title": title,
            "title_key": title_key(title),
            "summary": clean_text(e.get("summary", ""))[:600],
            "source": feed.name,
            "published": min(published, now),
        })
    return items


HOST_GAP = 2.0  # seconds between requests to the same host (Reddit answers 429 to parallel hits)


async def fetch_all(feeds: list[Feed]) -> list[tuple[Feed, list[dict] | None | Exception]]:
    """Fetch feeds concurrently, but sequentially (with a short gap) for feeds sharing a host."""
    by_host: dict[str, list[Feed]] = {}
    for f in feeds:
        by_host.setdefault(urlsplit(f.url).netloc, []).append(f)
    results: dict[int, list[dict] | None | Exception] = {}

    async def run_host(client: httpx.AsyncClient, group: list[Feed]) -> None:
        for n, f in enumerate(group):
            if n:
                await asyncio.sleep(HOST_GAP)
            try:
                results[id(f)] = await fetch_feed(client, f)
            except Exception as e:
                results[id(f)] = e

    async with httpx.AsyncClient(headers=HEADERS, timeout=20, follow_redirects=True) as client:
        await asyncio.gather(*(run_host(client, g) for g in by_host.values()))
    return [(f, results[id(f)]) for f in feeds]
