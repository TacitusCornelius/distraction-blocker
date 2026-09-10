"""Small offline starter managed lists."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .model import ManagedList

_STARTER_DATA: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "Social media",
        "social-media",
        (
            "facebook.com", "www.facebook.com", "m.facebook.com",
            "instagram.com", "www.instagram.com", "reddit.com",
            "www.reddit.com", "old.reddit.com", "tiktok.com",
            "www.tiktok.com", "x.com", "www.x.com", "twitter.com",
            "www.twitter.com", "threads.net", "www.threads.net",
        ),
    ),
    (
        "Games",
        "games",
        (
            "steampowered.com", "store.steampowered.com", "steamcommunity.com",
            "epicgames.com", "www.epicgames.com", "roblox.com",
            "www.roblox.com", "twitch.tv", "www.twitch.tv",
            "minecraft.net", "www.minecraft.net",
        ),
    ),
    (
        "Shopping",
        "shopping",
        (
            "amazon.com", "www.amazon.com", "ebay.com", "www.ebay.com",
            "etsy.com", "www.etsy.com", "walmart.com", "www.walmart.com",
            "shopify.com", "www.shopify.com",
        ),
    ),
    (
        "Streaming media",
        "streaming-media",
        (
            "youtube.com", "www.youtube.com", "music.youtube.com",
            "netflix.com", "www.netflix.com", "hulu.com", "www.hulu.com",
            "spotify.com", "open.spotify.com", "disneyplus.com",
            "www.disneyplus.com",
        ),
    ),
    (
        "Video",
        "video",
        (
            "youtube.com", "www.youtube.com", "m.youtube.com",
            "music.youtube.com", "gaming.youtube.com", "studio.youtube.com",
            "tv.youtube.com", "kids.youtube.com",
            "creatoracademy.youtube.com", "youtube-nocookie.com",
            "www.youtube-nocookie.com", "youtu.be",
            "youtube.googleapis.com", "googlevideo.com", "ytimg.com",
            "i.ytimg.com", "s.ytimg.com", "yt3.ggpht.com",
            "vimeo.com", "www.vimeo.com", "player.vimeo.com",
            "dailymotion.com", "www.dailymotion.com",
            "twitch.tv", "www.twitch.tv", "kick.com", "www.kick.com",
            "rumble.com", "www.rumble.com", "streamable.com",
            "www.streamable.com", "netflix.com", "www.netflix.com",
            "hulu.com", "www.hulu.com", "disneyplus.com",
            "www.disneyplus.com", "primevideo.com", "www.primevideo.com",
            "max.com", "www.max.com", "peacocktv.com", "www.peacocktv.com",
            "paramountplus.com", "www.paramountplus.com",
            "crunchyroll.com", "www.crunchyroll.com", "tubitv.com",
            "www.tubitv.com", "pluto.tv", "www.pluto.tv", "plex.tv",
            "www.plex.tv", "fubo.tv", "www.fubo.tv",
        ),
    ),
    (
        "YouTube",
        "youtube",
        (
            "youtube.com", "www.youtube.com", "m.youtube.com",
            "music.youtube.com", "gaming.youtube.com", "studio.youtube.com",
            "tv.youtube.com", "kids.youtube.com",
            "creatoracademy.youtube.com", "youtube-nocookie.com",
            "www.youtube-nocookie.com", "youtu.be",
            "youtube.googleapis.com", "googlevideo.com", "ytimg.com",
            "i.ytimg.com", "s.ytimg.com", "yt3.ggpht.com",
        ),
    ),
    (
        "Adult content",
        "adult-content",
        (
            "pornhub.com", "www.pornhub.com", "xvideos.com",
            "www.xvideos.com", "xnxx.com", "www.xnxx.com", "redtube.com",
            "www.redtube.com", "xhamster.com", "www.xhamster.com",
        ),
    ),
)
_STARTER_IDS = (
    "8d2b8c55-29b7-4d2e-94b8-4dbd6a0d0001",
    "8d2b8c55-29b7-4d2e-94b8-4dbd6a0d0002",
    "8d2b8c55-29b7-4d2e-94b8-4dbd6a0d0003",
    "8d2b8c55-29b7-4d2e-94b8-4dbd6a0d0004",
    "8d2b8c55-29b7-4d2e-94b8-4dbd6a0d0005",
    "8d2b8c55-29b7-4d2e-94b8-4dbd6a0d0006",
    "8d2b8c55-29b7-4d2e-94b8-4dbd6a0d0007",
)


def starter_categories(imported_utc: datetime | None = None) -> tuple[ManagedList, ...]:
    """Return the seven built-in categories as normal managed lists."""
    stamp = imported_utc or datetime.now(timezone.utc)
    if stamp.tzinfo is None or stamp.utcoffset() != timezone.utc.utcoffset(stamp):
        raise ValueError("imported_utc must be aware UTC")
    result: list[ManagedList] = []
    for ident, (name, slug, domains) in zip(_STARTER_IDS, _STARTER_DATA):
        result.append(ManagedList.from_dict({
            "id": ident,
            "name": name,
            "source": f"built-in:{slug}",
            "version": "1",
            "license": "Built-in project data; no separate license file.",
            "imported_utc": stamp,
            "domains": list(domains),
        }))
    return tuple(result)


STARTER_CATEGORIES = starter_categories(datetime(2026, 1, 1, tzinfo=timezone.utc))

__all__ = ["STARTER_CATEGORIES", "starter_categories"]
