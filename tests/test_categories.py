from __future__ import annotations

from datetime import datetime, timezone
import unittest

from distraction_blocker.categories import starter_categories


class StarterCategoryTests(unittest.TestCase):
    def test_social_media_roster_has_the_declared_sixteen_hosts(self) -> None:
        categories = starter_categories(
            datetime(2026, 8, 20, tzinfo=timezone.utc)
        )
        social = next(item for item in categories if item.name == "Social media")

        self.assertEqual(
            social.domains,
            (
                "facebook.com", "www.facebook.com", "m.facebook.com",
                "instagram.com", "www.instagram.com", "reddit.com",
                "www.reddit.com", "old.reddit.com", "tiktok.com",
                "www.tiktok.com", "x.com", "www.x.com", "twitter.com",
                "www.twitter.com", "threads.net", "www.threads.net",
            ),
        )

    def test_video_and_youtube_rosters_are_available_and_overlap(self) -> None:
        categories = starter_categories(
            datetime(2026, 8, 20, tzinfo=timezone.utc)
        )
        by_name = {item.name: item for item in categories}

        self.assertIn("Video", by_name)
        self.assertIn("YouTube", by_name)
        self.assertEqual(
            by_name["YouTube"].domains,
            (
                "youtube.com", "www.youtube.com", "m.youtube.com",
                "music.youtube.com", "gaming.youtube.com",
                "studio.youtube.com", "tv.youtube.com", "kids.youtube.com",
                "creatoracademy.youtube.com", "youtube-nocookie.com",
                "www.youtube-nocookie.com", "youtu.be",
                "youtube.googleapis.com", "googlevideo.com", "ytimg.com",
                "i.ytimg.com", "s.ytimg.com", "yt3.ggpht.com",
            ),
        )
        self.assertTrue(
            set(by_name["YouTube"].domains)
            <= set(by_name["Video"].domains)
        )
        self.assertIn("vimeo.com", by_name["Video"].domains)
        self.assertIn("youtube.com", by_name["YouTube"].domains)


if __name__ == "__main__":
    unittest.main()
