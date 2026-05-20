"""
scheduler.py — Background job scheduler for Threat Command Center
Uses APScheduler to:
  1. Refresh OSINT radar feeds every 6 hours
  2. Re-scan the NVD for all stack items every 12 hours
"""

import asyncio
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
import aiosqlite

from database import DB_PATH
from radar import refresh_radar
from scanner import query_nvd_for_keyword

logger = logging.getLogger("scheduler")

_scheduler: AsyncIOScheduler | None = None


# ─── Jobs ────────────────────────────────────────────────────────────────────

async def _job_radar_refresh():
    """Fetch all RSS feeds and upsert new items into the DB."""
    logger.info("[SCHEDULER] Running scheduled radar refresh…")
    try:
        items = await refresh_radar()
        async with aiosqlite.connect(DB_PATH) as db:
            new_count = 0
            for item in items:
                try:
                    await db.execute(
                        """INSERT OR IGNORE INTO radar_items
                           (title, link, source, published, cves)
                           VALUES (?, ?, ?, ?, ?)""",
                        (item["title"], item["link"], item["source"],
                         item["published"], item["cves"])
                    )
                    new_count += 1
                except Exception as e:
                    logger.debug(f"[SCHEDULER] radar insert skip: {e}")
            await db.commit()
            # Record last run
            await db.execute(
                """INSERT OR REPLACE INTO scheduler_log (job, last_run, status, detail)
                   VALUES ('radar_refresh', datetime('now'), 'ok', ?)""",
                (f"Fetched {len(items)} items, {new_count} new",)
            )
            await db.commit()
        logger.info(f"[SCHEDULER] Radar refresh done — {len(items)} items fetched.")
    except Exception as e:
        logger.error(f"[SCHEDULER] Radar refresh failed: {e}")
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """INSERT OR REPLACE INTO scheduler_log (job, last_run, status, detail)
                   VALUES ('radar_refresh', datetime('now'), 'error', ?)""",
                (str(e),)
            )
            await db.commit()


async def _job_nvd_stack_scan():
    """Re-scan NVD for every technology in the user's stack."""
    logger.info("[SCHEDULER] Running scheduled NVD stack scan…")
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT name FROM stack_items")
            rows = await cursor.fetchall()
            stack = [r["name"] for r in rows]

        if not stack:
            logger.info("[SCHEDULER] Stack is empty — skipping NVD scan.")
            return

        total = 0
        async with aiosqlite.connect(DB_PATH) as db:
            for keyword in stack:
                results = await query_nvd_for_keyword(keyword)
                for r in results:
                    try:
                        await db.execute(
                            """INSERT OR REPLACE INTO nvd_alerts
                               (cve_id, stack_item, description, severity, cvss_score, published)
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (r["cve_id"], r["stack_item"], r["description"],
                             r["severity"], r["cvss_score"], r["published"])
                        )
                        total += 1
                    except Exception as e:
                        logger.debug(f"[SCHEDULER] NVD insert skip: {e}")
                await db.commit()
                await asyncio.sleep(1.5)   # NVD rate limit courtesy

            await db.execute(
                """INSERT OR REPLACE INTO scheduler_log (job, last_run, status, detail)
                   VALUES ('nvd_scan', datetime('now'), 'ok', ?)""",
                (f"Scanned {len(stack)} stack items, {total} CVE records",)
            )
            await db.commit()
        logger.info(f"[SCHEDULER] NVD scan done — {total} CVE records for {len(stack)} items.")
    except Exception as e:
        logger.error(f"[SCHEDULER] NVD scan failed: {e}")
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """INSERT OR REPLACE INTO scheduler_log (job, last_run, status, detail)
                   VALUES ('nvd_scan', datetime('now'), 'error', ?)""",
                (str(e),)
            )
            await db.commit()


# ─── Lifecycle ───────────────────────────────────────────────────────────────

def start_scheduler():
    global _scheduler
    _scheduler = AsyncIOScheduler(timezone="UTC")

    # Radar refresh every 6 hours
    _scheduler.add_job(
        _job_radar_refresh,
        trigger=IntervalTrigger(hours=6),
        id="radar_refresh",
        name="OSINT Radar Refresh",
        replace_existing=True,
        max_instances=1,
    )

    # NVD stack scan every 12 hours
    _scheduler.add_job(
        _job_nvd_stack_scan,
        trigger=IntervalTrigger(hours=12),
        id="nvd_stack_scan",
        name="NVD Stack Scan",
        replace_existing=True,
        max_instances=1,
    )

    _scheduler.start()
    logger.info("[SCHEDULER] Scheduler started. Jobs: radar@6h, nvd@12h")
    return _scheduler


def stop_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("[SCHEDULER] Scheduler stopped.")


def get_scheduler() -> AsyncIOScheduler | None:
    return _scheduler
