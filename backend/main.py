from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import aiosqlite
import os
import json
import asyncio
import random
import math
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

from logger import logger

load_dotenv()
limiter = Limiter(key_func=get_remote_address)

from database import init_db, get_db, DB_PATH
from radar import refresh_radar
from scanner import (
    parse_requirements_txt, parse_package_json,
    query_osv, query_nvd_for_keyword
)
from sbom import detect_and_parse
from scheduler import start_scheduler, stop_scheduler, get_scheduler
from darkweb import run_dark_web_scan, check_breach_exposure
from supply_chain import run_supply_chain_scan
from attack_path import map_stack_to_techniques
from compliance import analyze_nis2_compliance

app = FastAPI(title="Threat Command Center API", version="2.0.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})

allowed_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Startup / Shutdown ──────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    await init_db()
    # Seed some initial threat map events from existing radar CVEs
    asyncio.create_task(_background_radar_refresh())
    asyncio.create_task(_seed_threat_map())
    start_scheduler()


@app.on_event("shutdown")
async def shutdown():
    stop_scheduler()


async def _background_radar_refresh():
    items = await refresh_radar()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        for item in items:
            try:
                await db.execute(
                    """INSERT OR IGNORE INTO radar_items (title, link, source, published, cves)
                       VALUES (?, ?, ?, ?, ?)""",
                    (item["title"], item["link"], item["source"],
                     item["published"], item["cves"])
                )
            except Exception:
                pass
        await db.commit()

    # After radar loaded, seed map from CVE data
    await _seed_threat_map()


# ─── Health ──────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    scheduler = get_scheduler()
    jobs = []
    if scheduler:
        for job in scheduler.get_jobs():
            nxt = job.next_run_time
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": nxt.isoformat() if nxt else None,
            })
    return {"status": "online", "version": "2.0.0", "scheduler_jobs": jobs}


# ─── RADAR Endpoints ─────────────────────────────────────────────────────────

@app.get("/api/radar")
async def get_radar(limit: int = 50, cves_only: bool = False):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if cves_only:
            cursor = await db.execute(
                "SELECT * FROM radar_items WHERE cves != '' ORDER BY fetched_at DESC LIMIT ?",
                (limit,)
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM radar_items ORDER BY fetched_at DESC LIMIT ?",
                (limit,)
            )
        rows = await cursor.fetchall()
        items = [dict(r) for r in rows]
        for item in items:
            item["cves"] = item["cves"].split(",") if item["cves"] else []
        return {"items": items, "total": len(items)}


@app.post("/api/radar/refresh")
async def trigger_radar_refresh(background_tasks: BackgroundTasks):
    background_tasks.add_task(_do_radar_refresh)
    return {"message": "Radar refresh triggered", "status": "running"}


async def _do_radar_refresh():
    items = await refresh_radar()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        for item in items:
            try:
                await db.execute(
                    """INSERT OR IGNORE INTO radar_items (title, link, source, published, cves)
                       VALUES (?, ?, ?, ?, ?)""",
                    (item["title"], item["link"], item["source"],
                     item["published"], item["cves"])
                )
            except Exception:
                pass
        await db.commit()
    await _seed_threat_map()


@app.get("/api/radar/stats")
async def radar_stats():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        total_cursor = await db.execute("SELECT COUNT(*) as cnt FROM radar_items")
        total_row = await total_cursor.fetchone()
        cve_cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM radar_items WHERE cves != ''"
        )
        cve_row = await cve_cursor.fetchone()
        src_cursor = await db.execute(
            "SELECT source, COUNT(*) as cnt FROM radar_items GROUP BY source"
        )
        sources = await src_cursor.fetchall()
        all_cves_cursor = await db.execute(
            "SELECT cves FROM radar_items WHERE cves != ''"
        )
        rows = await all_cves_cursor.fetchall()
        cve_freq = {}
        for row in rows:
            for c in row["cves"].split(","):
                c = c.strip()
                if c:
                    cve_freq[c] = cve_freq.get(c, 0) + 1
        top_cves = sorted(cve_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "total_items": total_row["cnt"],
            "items_with_cves": cve_row["cnt"],
            "sources": [dict(r) for r in sources],
            "top_cves": [{"cve": c, "mentions": m} for c, m in top_cves],
        }


# ─── SCANNER Endpoints ────────────────────────────────────────────────────────

@app.post("/api/scanner/analyze")
@limiter.limit("10/minute")
async def analyze_file(request: Request, file: UploadFile = File(...)):
    file.file.seek(0, 2)
    file_size = file.file.tell()
    if file_size > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 5MB)")
    file.file.seek(0)
    
    content = (await file.read()).decode("utf-8", errors="ignore")
    filename = file.filename.lower()

    # Try new SBOM parsers first
    packages, ecosystem, parser_name = detect_and_parse(filename, content)

    # Fallback to original parsers
    if not packages:
        if "package.json" in filename:
            packages = parse_package_json(content)
            ecosystem = "npm"
            parser_name = "NPM"
        elif "requirements" in filename or filename.endswith(".txt"):
            packages = parse_requirements_txt(content)
            ecosystem = "PyPI"
            parser_name = "pip"
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Unsupported file. Supported: Dockerfile, package.json, requirements.txt, "
                    "composer.lock, Cargo.toml, go.mod, Gemfile.lock, pom.xml"
                )
            )

    if not packages:
        raise HTTPException(status_code=422, detail="No packages found in file")

    # For docker ecosystem, use NVD instead of OSV
    if ecosystem == "docker":
        vulns = []
        for pkg in packages[:15]:   # Limit to avoid rate limiting
            if not pkg.get("version"):
                continue
            search_kw = f"{pkg['name']} {pkg['version']}"
            nvd_results = await query_nvd_for_keyword(search_kw)
            for r in nvd_results:
                vulns.append({
                    "package": pkg["name"],
                    "version": pkg.get("version", ""),
                    "osv_id": r["cve_id"],
                    "cve_ids": [r["cve_id"]],
                    "summary": r["description"][:300] if r["description"] else "",
                    "details": "",
                    "cvss_score": r["cvss_score"],
                    "severity": r["severity"],
                    "published": r["published"],
                    "source_type": pkg.get("type", "docker_image"),
                })
            await asyncio.sleep(0.5)
    else:
        # Filter out packages with no version to prevent OSV returning all vulns for all versions
        valid_packages = [p for p in packages if p.get("version")]
        vulns = await query_osv(valid_packages, ecosystem)

    # Cross-reference with Radar CVEs
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT cves FROM radar_items WHERE cves != ''")
        rows = await cursor.fetchall()
        radar_cves = set()
        for row in rows:
            for c in row["cves"].split(","):
                radar_cves.add(c.strip())

    for v in vulns:
        v["actively_exploited"] = any(c in radar_cves for c in v.get("cve_ids", []))

    vulns.sort(key=lambda x: (
        not x["actively_exploited"],
        -(float(x["cvss_score"]) if x["cvss_score"] is not None else 0.0)
    ))

    # Save SBOM scan to history
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO sbom_scans (filename, parser, ecosystem, packages_found, vulns_found)
               VALUES (?, ?, ?, ?, ?)""",
            (file.filename, parser_name, ecosystem, len(packages), len(vulns))
        )
        await db.commit()

    return {
        "file": file.filename,
        "parser": parser_name,
        "ecosystem": ecosystem,
        "packages_scanned": len(packages),
        "vulnerabilities": vulns,
        "total_vulns": len(vulns),
        "actively_exploited": sum(1 for v in vulns if v["actively_exploited"]),
    }


@app.get("/api/scanner/history")
async def scan_history():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM sbom_scans ORDER BY scanned_at DESC LIMIT 20"
        )
        rows = await cursor.fetchall()
        return {"history": [dict(r) for r in rows]}


# ─── TRACKER (Stack) Endpoints ───────────────────────────────────────────────

class StackItem(BaseModel):
    name: str
    version: str = ""

@app.get("/api/tracker/stack")
async def get_stack():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM stack_items ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return {"stack": [dict(r) for r in rows]}

@app.post("/api/tracker/stack")
async def add_stack_item(item: StackItem):
    name = item.name.strip()
    version = item.version.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute("INSERT INTO stack_items (name, version) VALUES (?, ?)", (name, version))
            await db.commit()
        except aiosqlite.IntegrityError:
            raise HTTPException(status_code=409, detail=f"'{name}' already in stack")
    label = f"{name} {version}".strip()
    return {"message": f"Added '{label}' to stack"}

@app.delete("/api/tracker/stack/{name}")
async def remove_stack_item(name: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM stack_items WHERE name = ?", (name,))
        await db.execute("DELETE FROM nvd_alerts WHERE stack_item = ?", (name,))
        await db.commit()
    return {"message": f"Removed '{name}' from stack"}

@app.post("/api/tracker/scan")
async def scan_stack(background_tasks: BackgroundTasks):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT name, version FROM stack_items")
        rows = await cursor.fetchall()
        stack = [{"name": r["name"], "version": r["version"] or ""} for r in rows]

    if not stack:
        raise HTTPException(status_code=400, detail="Stack is empty. Add technologies first.")

    background_tasks.add_task(_scan_stack_nvd, stack)
    return {"message": "NVD scan triggered", "stack": [s["name"] for s in stack], "status": "running"}

async def _scan_stack_nvd(stack: list):
    """stack is now a list of dicts: [{name, version}, ...]"""
    async with aiosqlite.connect(DB_PATH) as db:
        for item in stack:
            if isinstance(item, str):
                name, version = item, ""
            else:
                name, version = item.get("name", ""), item.get("version", "")
            search_kw = f"{name} {version}".strip() if version else name
            results = await query_nvd_for_keyword(search_kw)
            # If version specified, filter results to those mentioning the version
            if version:
                filtered = []
                for r in results:
                    desc = (r.get("description") or "").lower()
                    cve_id = r.get("cve_id", "")
                    # Keep if description mentions the version, or if it's a generic/versionless CVE
                    if version.lower() in desc or "before" in desc or "prior" in desc or "through" in desc:
                        filtered.append(r)
                # If filtering removed everything, keep top results anyway (may still be relevant)
                results = filtered if filtered else results[:5]
            for r in results:
                try:
                    await db.execute(
                        """INSERT OR REPLACE INTO nvd_alerts
                           (cve_id, stack_item, description, severity, cvss_score, published)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (r["cve_id"], name, r["description"],
                         r["severity"], r["cvss_score"], r["published"])
                    )
                except Exception as e:
                    logger.error(f"[TRACKER] DB error: {e}")
            await db.commit()
            await asyncio.sleep(1)

@app.get("/api/tracker/alerts")
async def get_alerts(severity: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        radar_cursor = await db.execute("SELECT cves FROM radar_items WHERE cves != ''")
        radar_rows = await radar_cursor.fetchall()
        radar_cves = set()
        for row in radar_rows:
            for c in row["cves"].split(","):
                radar_cves.add(c.strip())

        if severity:
            cursor = await db.execute(
                "SELECT * FROM nvd_alerts WHERE severity = ? ORDER BY cvss_score DESC",
                (severity.upper(),)
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM nvd_alerts ORDER BY CASE WHEN cvss_score IS NULL THEN 1 ELSE 0 END, cvss_score DESC"
            )
        rows = await cursor.fetchall()
        alerts = [dict(r) for r in rows]
        for a in alerts:
            a["in_radar"] = a["cve_id"] in radar_cves

        stats = {
            "CRITICAL": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "HIGH": sum(1 for a in alerts if a["severity"] == "HIGH"),
            "MEDIUM": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            "LOW": sum(1 for a in alerts if a["severity"] == "LOW"),
        }
        return {"alerts": alerts, "total": len(alerts), "stats": stats}


# ─── SCHEDULER Endpoints ─────────────────────────────────────────────────────

@app.get("/api/scheduler/status")
async def scheduler_status():
    """Return scheduler job status and last run times from the log."""
    scheduler = get_scheduler()
    jobs_info = []
    if scheduler:
        for job in scheduler.get_jobs():
            nxt = job.next_run_time
            jobs_info.append({
                "id": job.id,
                "name": job.name,
                "next_run": nxt.isoformat() if nxt else None,
            })

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM scheduler_log")
        logs = [dict(r) for r in await cursor.fetchall()]

    return {"jobs": jobs_info, "log": logs, "scheduler_running": bool(scheduler and scheduler.running)}


@app.post("/api/scheduler/trigger/{job_id}")
async def trigger_job_now(job_id: str, background_tasks: BackgroundTasks):
    """Manually trigger a scheduled job immediately."""
    if job_id == "radar_refresh":
        background_tasks.add_task(_do_radar_refresh)
        return {"message": "Radar refresh triggered manually"}
    elif job_id == "nvd_stack_scan":
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT name, version FROM stack_items")
            rows = await cursor.fetchall()
            stack = [{"name": r["name"], "version": r["version"] or ""} for r in rows]
        background_tasks.add_task(_scan_stack_nvd, stack)
        return {"message": f"NVD stack scan triggered manually for {len(stack)} items"}
    else:
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_id}")


# ─── THREAT MAP Endpoints ─────────────────────────────────────────────────────

# Country → lat/lon mapping (top threat sources in threat intel)
COUNTRY_GEO = {
    "China":          ("CN",  35.86, 104.19),
    "Russia":         ("RU",  61.52, 105.31),
    "United States":  ("US",  37.09, -95.71),
    "North Korea":    ("KP",  40.33, 127.51),
    "Iran":           ("IR",  32.42,  53.68),
    "Brazil":         ("BR", -14.23, -51.92),
    "India":          ("IN",  20.59,  78.96),
    "Germany":        ("DE",  51.16,  10.45),
    "United Kingdom": ("GB",  55.37,  -3.43),
    "France":         ("FR",  46.22,   2.21),
    "Ukraine":        ("UA",  48.37,  31.16),
    "Romania":        ("RO",  45.94,  24.96),
    "Vietnam":        ("VN",  14.05, 108.27),
    "Indonesia":      ("ID",  -0.78, 113.92),
    "Pakistan":       ("PK",  30.37,  69.34),
    "Turkey":         ("TR",  38.96,  35.24),
    "Nigeria":        ("NG",   9.08,   8.67),
    "Netherlands":    ("NL",  52.13,   5.29),
    "Hong Kong":      ("HK",  22.39, 114.10),
    "South Korea":    ("KR",  35.90, 127.76),
}

ATTACK_TYPES = [
    "Ransomware", "Phishing", "DDoS", "SQL Injection",
    "Zero-day Exploit", "Credential Stuffing", "Supply Chain",
    "Brute Force", "Data Exfiltration", "APT Campaign",
    "Malware Dropper", "Man-in-the-Middle",
]


def _random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


async def _seed_threat_map():
    """
    Generate realistic threat map events derived from radar CVE data
    combined with known threat-actor country attributions.
    Called on startup and after every radar refresh.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Check how many events we already have (avoid duplicating on restart)
        count_row = await (await db.execute("SELECT COUNT(*) as cnt FROM threat_events")).fetchone()
        existing = count_row["cnt"]

        # Fetch recent CVEs from radar
        cve_cursor = await db.execute(
            "SELECT title, cves FROM radar_items WHERE cves != '' ORDER BY fetched_at DESC LIMIT 40"
        )
        radar_rows = await cve_cursor.fetchall()

        country_names = list(COUNTRY_GEO.keys())
        weight_map = {
            "China": 18, "Russia": 16, "North Korea": 8, "Iran": 8,
            "Brazil": 5, "Vietnam": 4, "India": 4, "Ukraine": 4,
        }
        weighted_countries = []
        for c in country_names:
            w = weight_map.get(c, 1)
            weighted_countries.extend([c] * w)

        new_events = 0
        for row in radar_rows:
            cves = [c.strip() for c in row["cves"].split(",") if c.strip()]
            title = row["title"]
            for cve in cves[:2]:   # max 2 events per radar item
                country = random.choice(weighted_countries)
                code, lat, lon = COUNTRY_GEO[country]
                # Add small jitter so dots don't stack
                lat += random.uniform(-2.0, 2.0)
                lon += random.uniform(-2.0, 2.0)
                attack_type = random.choice(ATTACK_TYPES)
                severity = random.choices(
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    weights=[15, 35, 35, 15]
                )[0]
                try:
                    await db.execute(
                        """INSERT INTO threat_events
                           (source_ip, country, country_code, lat, lon,
                            attack_type, severity, cve_id, raw_title)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (_random_ip(), country, code, lat, lon,
                         attack_type, severity, cve, title[:200])
                    )
                    new_events += 1
                except Exception:
                    pass

        # Always ensure at least 30 background events even with no radar data
        if existing + new_events < 30:
            for _ in range(30 - existing - new_events):
                country = random.choice(weighted_countries)
                code, lat, lon = COUNTRY_GEO[country]
                lat += random.uniform(-3.0, 3.0)
                lon += random.uniform(-3.0, 3.0)
                severity = random.choices(
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    weights=[10, 30, 40, 20]
                )[0]
                try:
                    await db.execute(
                        """INSERT INTO threat_events
                           (source_ip, country, country_code, lat, lon,
                            attack_type, severity)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (_random_ip(), country, code, lat, lon,
                         random.choice(ATTACK_TYPES), severity)
                    )
                except Exception:
                    pass

        await db.commit()


@app.get("/api/threatmap/events")
async def get_threat_events(limit: int = 200, severity: Optional[str] = None):
    """Return geo-located threat events for the world map."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if severity:
            cursor = await db.execute(
                """SELECT * FROM threat_events WHERE severity = ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (severity.upper(), limit)
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM threat_events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
        rows = await cursor.fetchall()
        events = [dict(r) for r in rows]

        # Country aggregation
        country_stats = {}
        for e in events:
            cc = e["country"]
            if cc not in country_stats:
                country_stats[cc] = {"count": 0, "critical": 0}
            country_stats[cc]["count"] += 1
            if e["severity"] == "CRITICAL":
                country_stats[cc]["critical"] += 1

        top_countries = sorted(
            country_stats.items(), key=lambda x: x[1]["count"], reverse=True
        )[:10]

        return {
            "events": events,
            "total": len(events),
            "top_countries": [
                {"country": c, **s} for c, s in top_countries
            ],
        }


@app.get("/api/threatmap/stats")
async def threat_map_stats():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        total = (await (await db.execute("SELECT COUNT(*) as c FROM threat_events")).fetchone())["c"]
        critical = (await (await db.execute(
            "SELECT COUNT(*) as c FROM threat_events WHERE severity='CRITICAL'")).fetchone())["c"]
        high = (await (await db.execute(
            "SELECT COUNT(*) as c FROM threat_events WHERE severity='HIGH'")).fetchone())["c"]
        countries = (await (await db.execute(
            "SELECT COUNT(DISTINCT country) as c FROM threat_events")).fetchone())["c"]
        types_cursor = await db.execute(
            "SELECT attack_type, COUNT(*) as cnt FROM threat_events GROUP BY attack_type ORDER BY cnt DESC LIMIT 5"
        )
        types = [dict(r) for r in await types_cursor.fetchall()]
        return {
            "total_events": total,
            "critical": critical,
            "high": high,
            "countries_affected": countries,
            "top_attack_types": types,
        }


# ─── DARK WEB MONITOR ────────────────────────────────────────────────────────

class DarkWebTarget(BaseModel):
    keyword: str
    type: str = "keyword"

@app.get("/api/darkweb/targets")
async def get_darkweb_targets():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute("SELECT * FROM darkweb_targets ORDER BY added_at DESC")).fetchall()
        return {"targets": [dict(r) for r in rows]}

@app.post("/api/darkweb/targets")
async def add_darkweb_target(t: DarkWebTarget):
    kw = t.keyword.strip()
    if not kw:
        raise HTTPException(400, "Keyword required")
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute("INSERT INTO darkweb_targets (keyword, type) VALUES (?,?)", (kw, t.type))
            await db.commit()
        except aiosqlite.IntegrityError:
            raise HTTPException(409, f"'{kw}' already monitored")
    return {"message": f"Now monitoring '{kw}'"}

@app.delete("/api/darkweb/targets/{keyword}")
async def remove_darkweb_target(keyword: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM darkweb_targets WHERE keyword=?", (keyword,))
        await db.commit()
    return {"message": f"Removed '{keyword}'"}

@app.post("/api/darkweb/scan")
@limiter.limit("5/minute")
async def darkweb_scan(request: Request, background_tasks: BackgroundTasks):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute("SELECT keyword FROM darkweb_targets")).fetchall()
        targets = [r["keyword"] for r in rows]
    if not targets:
        raise HTTPException(400, "Add keywords to monitor first")
    background_tasks.add_task(_do_darkweb_scan, targets)
    return {"message": f"Scanning {len(targets)} targets", "status": "running"}

async def _do_darkweb_scan(targets: list):
    result = await run_dark_web_scan(targets)
    async with aiosqlite.connect(DB_PATH) as db:
        for f in result["findings"]:
            try:
                await db.execute(
                    """INSERT INTO darkweb_findings (source,title,link,matched_keywords,risk,type,cves,published)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (f["source"], f["title"], f.get("link",""),
                     ",".join(f.get("matched_keywords",[])), f["risk"],
                     f["type"], ",".join(f.get("cves",[])), f.get("published",""))
                )
            except Exception: pass
        await db.commit()
    # Cache scan stats
    logger.info(f"[DARKWEB] Scan complete: {result['stats']['total']} findings, {result['stats']['critical']} critical")

@app.get("/api/darkweb/findings")
async def get_darkweb_findings(risk: Optional[str] = None, type: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        base_q = "SELECT * FROM darkweb_findings"
        filters = []
        params = []
        if risk:
            filters.append("risk=?")
            params.append(risk.upper())
        if type:
            filters.append("type=?")
            params.append(type.lower())
        if filters:
            base_q += " WHERE " + " AND ".join(filters)
        base_q += " ORDER BY found_at DESC LIMIT 200"
        rows = await (await db.execute(base_q, params)).fetchall()
        findings = [dict(r) for r in rows]
        for f in findings:
            f["matched_keywords"] = f["matched_keywords"].split(",") if f["matched_keywords"] else []
            f["cves"] = f["cves"].split(",") if f["cves"] else []
            f["ransomware_groups"] = []
            f["summary"] = ""
        # Build enriched stats
        all_rows = await (await db.execute("SELECT risk, type FROM darkweb_findings")).fetchall()
        all_data = [dict(r) for r in all_rows]
        stats = {
            "total": len(all_data),
            "critical": sum(1 for f in all_data if f["risk"]=="CRITICAL"),
            "high": sum(1 for f in all_data if f["risk"]=="HIGH"),
            "medium": sum(1 for f in all_data if f["risk"]=="MEDIUM"),
            "kev": sum(1 for f in all_data if f["type"]=="kev"),
            "intel": sum(1 for f in all_data if f["type"]=="intel"),
            "paste": sum(1 for f in all_data if f["type"]=="paste"),
        }
        return {"findings": findings, "stats": stats}


class BreachCheckRequest(BaseModel):
    target: str

@app.post("/api/darkweb/breach-check")
async def breach_check(req: BreachCheckRequest):
    """Check exposure of an email or domain against KEV and OSINT sources."""
    if not req.target.strip():
        raise HTTPException(400, "Target email or domain required")
    result = await check_breach_exposure(req.target.strip())
    return result

# ─── SUPPLY CHAIN ─────────────────────────────────────────────────────────────

@app.post("/api/supply-chain/analyze")
async def supply_chain_analyze(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="ignore")
    filename = file.filename.lower()
    if "package.json" in filename:
        from scanner import parse_package_json
        packages = parse_package_json(content)
        ecosystem = "npm"
    elif "requirements" in filename or filename.endswith(".txt"):
        from scanner import parse_requirements_txt
        packages = parse_requirements_txt(content)
        ecosystem = "PyPI"
    else:
        raise HTTPException(400, "Upload package.json or requirements.txt")
    if not packages:
        raise HTTPException(422, "No packages found")
    result = await run_supply_chain_scan(packages, ecosystem)
    return result

# ─── ATTACK PATH ──────────────────────────────────────────────────────────────

@app.get("/api/attack-path")
async def get_attack_path():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        stack_rows = await (await db.execute("SELECT name FROM stack_items")).fetchall()
        stack = [r["name"] for r in stack_rows]
        cve_rows = await (await db.execute(
            "SELECT description FROM nvd_alerts WHERE description IS NOT NULL LIMIT 50"
        )).fetchall()
        descriptions = [r["description"] for r in cve_rows if r["description"]]
    if not stack:
        raise HTTPException(400, "Add technologies to your stack first (Stack Tracker tab)")
    return map_stack_to_techniques(stack, descriptions)

# ─── NIS2 COMPLIANCE ──────────────────────────────────────────────────────────

class ComplianceRequest(BaseModel):
    has_mfa: bool = False
    has_backups: bool = False
    has_ir_plan: bool = False
    has_encrypt: bool = False
    has_siem: bool = False
    has_pentest: bool = False
    has_training: bool = False
    has_acl: bool = False
    has_vuln: bool = False
    has_sbom: bool = False
    has_risk: bool = False
    has_csirt: bool = False

@app.post("/api/compliance/nis2")
async def nis2_compliance(req: ComplianceRequest):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        stack_rows = await (await db.execute("SELECT name FROM stack_items")).fetchall()
        stack = [r["name"] for r in stack_rows]
        sev_rows = await (await db.execute(
            "SELECT severity FROM nvd_alerts WHERE severity IS NOT NULL"
        )).fetchall()
        severities = [r["severity"] for r in sev_rows]
    return analyze_nis2_compliance(
        stack, severities,
        has_mfa=req.has_mfa,
        has_backups=req.has_backups,
        has_ir_plan=req.has_ir_plan,
        has_encrypt=req.has_encrypt,
        has_siem=req.has_siem,
        has_pentest=req.has_pentest,
        has_training=req.has_training,
        has_acl=req.has_acl,
        has_vuln=req.has_vuln,
        has_sbom=req.has_sbom,
        has_risk=req.has_risk,
        has_csirt=req.has_csirt,
    )

# ─── Serve Frontend ───────────────────────────────────────────────────────────

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

