import re
import asyncio
import ssl
import certifi
import feedparser
import httpx
from typing import List, Dict, Any
from logger import logger

RSS_FEEDS = [
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "fallback": "https://thehackernews.com/feeds/posts/default",
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "fallback": None,
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "fallback": None,
    },
    {
        "name": "CISA Advisories",
        "url": "https://www.cisa.gov/uscert/ncas/current-activity.xml",
        "fallback": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    },
    {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/securityweek",
        "fallback": None,
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "fallback": None,
    },
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(text: str) -> List[str]:
    return list(set(CVE_PATTERN.findall(text or "")))


def _parse_response(text: str, source_name: str) -> List[Dict[str, Any]]:
    items = []
    parsed = feedparser.parse(text)
    for entry in parsed.entries[:20]:
        title = entry.get("title", "")
        summary = entry.get("summary", "") or entry.get("description", "")
        link = entry.get("link", "")
        published = entry.get("published", "") or entry.get("updated", "")
        cves = extract_cves(title + " " + summary)
        if title:
            items.append({
                "title": title,
                "link": link,
                "source": source_name,
                "published": published,
                "cves": ",".join(cves) if cves else "",
            })
    return items


async def fetch_feed(session: httpx.AsyncClient, feed_info: Dict) -> List[Dict[str, Any]]:
    urls_to_try = [feed_info["url"]]
    if feed_info.get("fallback"):
        urls_to_try.append(feed_info["fallback"])

    for url in urls_to_try:
        try:
            resp = await session.get(url, timeout=20.0, follow_redirects=True)
            resp.raise_for_status()
            items = _parse_response(resp.text, feed_info["name"])
            if items:
                logger.info(f"[RADAR] ✓ {feed_info['name']}: {len(items)} items from {url}")
                return items
        except httpx.HTTPStatusError as e:
            logger.warning(f"[RADAR] HTTP {e.response.status_code} for {feed_info['name']} @ {url}")
        except Exception as e:
            logger.error(f"[RADAR] ✗ {feed_info['name']} @ {url}: {type(e).__name__}: {e}")

    # Last resort: let feedparser try directly (it handles many edge cases)
    try:
        loop = asyncio.get_event_loop()
        parsed = await loop.run_in_executor(None, feedparser.parse, feed_info["url"])
        items = []
        for entry in parsed.entries[:20]:
            title = entry.get("title", "")
            summary = entry.get("summary", "") or entry.get("description", "")
            link = entry.get("link", "")
            published = entry.get("published", "") or entry.get("updated", "")
            cves = extract_cves(title + " " + summary)
            if title:
                items.append({
                    "title": title,
                    "link": link,
                    "source": feed_info["name"],
                    "published": published,
                    "cves": ",".join(cves) if cves else "",
                })
        if items:
            logger.info(f"[RADAR] ✓ {feed_info['name']} via feedparser fallback: {len(items)} items")
        return items
    except Exception as e:
        logger.error(f"[RADAR] ✗ feedparser fallback failed for {feed_info['name']}: {e}")
        return []


async def refresh_radar() -> List[Dict[str, Any]]:
    all_items = []
    ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    async with httpx.AsyncClient(
        headers=HEADERS,
        verify=ssl_ctx,
        timeout=httpx.Timeout(25.0),
    ) as client:
        tasks = [fetch_feed(client, f) for f in RSS_FEEDS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in results:
            if isinstance(batch, list):
                all_items.extend(batch)
    return all_items
