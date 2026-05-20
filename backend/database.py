import aiosqlite
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.path.join(os.path.dirname(__file__), os.getenv("DB_PATH", "threat_center.db"))

async def get_db():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        yield db

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS radar_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                link TEXT UNIQUE NOT NULL,
                source TEXT NOT NULL,
                published TEXT,
                cves TEXT,
                fetched_at TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS stack_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                version TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS nvd_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                stack_item TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published TEXT,
                fetched_at TEXT DEFAULT (datetime('now')),
                UNIQUE(cve_id, stack_item)
            )
        """)
        # ── NEW: Scheduler log ─────────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scheduler_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job TEXT NOT NULL UNIQUE,
                last_run TEXT,
                status TEXT,
                detail TEXT
            )
        """)
        # ── NEW: Threat map events (geo-located attack sources) ────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                country TEXT NOT NULL,
                country_code TEXT NOT NULL,
                lat REAL NOT NULL,
                lon REAL NOT NULL,
                attack_type TEXT,
                severity TEXT DEFAULT 'MEDIUM',
                cve_id TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                raw_title TEXT
            )
        """)
        # ── NEW: SBOM scan history ─────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sbom_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                parser TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                packages_found INTEGER DEFAULT 0,
                vulns_found INTEGER DEFAULT 0,
                scanned_at TEXT DEFAULT (datetime('now'))
            )
        """)
        # Dark Web Monitor
        await db.execute("""
            CREATE TABLE IF NOT EXISTS darkweb_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword TEXT NOT NULL UNIQUE,
                type TEXT DEFAULT 'keyword',
                added_at TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS darkweb_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                title TEXT,
                link TEXT,
                matched_keywords TEXT,
                risk TEXT DEFAULT 'MEDIUM',
                type TEXT,
                cves TEXT,
                published TEXT,
                found_at TEXT DEFAULT (datetime('now'))
            )
        """)
        # Migration: add version column to existing stack_items tables
        try:
            await db.execute("ALTER TABLE stack_items ADD COLUMN version TEXT DEFAULT ''")
        except Exception:
            pass  # Column already exists
        await db.commit()
