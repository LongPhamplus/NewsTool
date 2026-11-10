import argparse
import asyncio
import logging
import os
import sys

from . import config


async def check_feeds(cfg: config.Config) -> None:
    """Fetch every feed and print a sample, without touching the DB or Telegram."""
    from .classify import Classifier
    from .fetcher import fetch_all

    clf = Classifier(cfg.rules, cfg.watch)
    for feed, res in await fetch_all(cfg.feeds):
        if isinstance(res, Exception):
            print(f"❌ {feed.name}: {res!r}")
            continue
        if res is None:
            print(f"✅ {feed.name}: không đổi")
            continue
        print(f"✅ {feed.name}: {len(res)} tin")
        for it in res[:3]:
            tags = clf.tags(it["title"], it["summary"], feed.category, feed.lang)
            print(f"     [{','.join(tags)}] {it['title'][:90]}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="newstool")
    ap.add_argument("command", nargs="?", default="run", choices=["run", "check-feeds", "tg-login"])
    ap.add_argument("-c", "--config", default="config.yaml")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    cfg = config.load(args.config)
    if args.command == "check-feeds":
        asyncio.run(check_feeds(cfg))
        return
    if args.command == "tg-login":
        if not (cfg.tg_api_id and cfg.tg_api_hash):
            sys.exit("Thiếu TG_API_ID / TG_API_HASH trong .env (lấy tại https://my.telegram.org)")
        from .tgwatch import login
        asyncio.run(login(cfg))
        os.chmod(f"{cfg.tg_session}.session", 0o600)
        return
    if not cfg.token:
        sys.exit("Thiếu TELEGRAM_BOT_TOKEN trong .env")
    from .bot import build
    build(cfg).run_polling()


if __name__ == "__main__":
    main()
