"""
darkweb.py — Dark Web & Breach Intelligence Monitor
Aggregates from:
  - Public paste site RSS feeds
  - CISA KEV (Known Exploited Vulnerabilities) — actively exploited in wild
  - Threat intel RSS feeds (SANS ISC, Bleeping Computer, The Hacker News)
  - Ransomware group trackers
  - AlienVault OTX public indicators
"""
import re
import httpx
import asyncio
import feedparser
from typing import List, Dict, Any
from datetime import datetime, timezone

from logger import logger

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# ─── Intelligence Feeds ───────────────────────────────────────────────────────

PASTE_FEEDS = [
    {"name": "Pastebin Recent", "url": "https://pastebin.com/rss", "weight": 1},
]

THREAT_INTEL_FEEDS = [
    {
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "weight": 2,
    },
    {
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "weight": 2,
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "weight": 2,
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "weight": 2,
    },
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "weight": 3,
    },
    {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "weight": 2,
    },
]

BREACH_KEYWORDS = [
    "dump", "breach", "leak", "credential", "password", "database",
    "exfiltrat", "ransom", "darknet", "tor", "onion", "stealer",
    "infostealer", "combo list", "data sale", "hacked", "extortion",
    "dark web", "darkweb", "malware", "trojan", "backdoor", "keylogger",
    "botnet", "phish", "spear phish", "initial access", "ttp", "threat actor",
    "apt", "nation state", "zero day", "0day", "exploit", "ransomware group",
    "lockbit", "blackcat", "alphv", "clop", "revil", "conti", "hive",
    "play ransomware", "royal ransomware", "data extortion", "double extortion",
]

RANSOMWARE_GROUPS = [
    "LockBit", "BlackCat", "ALPHV", "Cl0p", "REvil", "Conti", "Hive",
    "Play", "Royal", "BlackBasta", "Akira", "8Base", "NoEscape", "Rhysida",
    "Medusa", "INC Ransom", "Hunters International", "Scattered Spider",
]

HEADERS = {"User-Agent": "ThreatCommandCenter/2.0 (security-research)"}


# ─── Scoring ─────────────────────────────────────────────────────────────────

def _score_content(text: str, keywords: List[str]) -> int:
    t = text.lower()
    return sum(1 for k in keywords if k.lower() in t)


def _detect_ransomware_groups(text: str) -> List[str]:
    t = text.lower()
    return [g for g in RANSOMWARE_GROUPS if g.lower() in t]


def _assess_risk(hit_kw: list, breach_score: int, cves: list, entry_type: str) -> str:
    if entry_type == "kev":
        return "CRITICAL"
    if len(hit_kw) >= 2 and cves:
        return "CRITICAL"
    if len(hit_kw) >= 2 or (breach_score >= 3 and cves):
        return "HIGH"
    if hit_kw or breach_score >= 2:
        return "MEDIUM"
    return "LOW"


# ─── Fetchers ─────────────────────────────────────────────────────────────────

async def fetch_paste_signals(target_keywords: List[str]) -> List[Dict[str, Any]]:
    """Fetch paste feeds and match against monitored keywords."""
    findings = []

    async with httpx.AsyncClient(headers=HEADERS, timeout=20.0, follow_redirects=True) as client:
        for feed in PASTE_FEEDS:
            try:
                resp = await client.get(feed["url"])
                parsed = feedparser.parse(resp.text)
                for entry in parsed.entries[:30]:
                    title = entry.get("title", "")
                    summary = entry.get("summary", "") or entry.get("description", "")
                    combined = (title + " " + summary).lower()
                    hit_kw = [k for k in target_keywords if k.lower() in combined]
                    breach_score = _score_content(combined, BREACH_KEYWORDS)
                    cves = CVE_RE.findall(combined)
                    ransomware_groups = _detect_ransomware_groups(combined)
                    if hit_kw or (breach_score >= 2 and cves):
                        risk = _assess_risk(hit_kw, breach_score, cves, "paste")
                        findings.append({
                            "source": feed["name"],
                            "title": title[:200],
                            "link": entry.get("link", ""),
                            "matched_keywords": hit_kw,
                            "breach_signals": breach_score,
                            "cves": list(set(cves)),
                            "risk": risk,
                            "published": entry.get("published", ""),
                            "type": "paste",
                            "ransomware_groups": ransomware_groups,
                            "summary": summary[:300] if summary else "",
                        })
            except Exception as e:
                logger.error(f"[DARKWEB] Paste feed error {feed['name']}: {e}")

    return findings


async def fetch_threat_intel_feeds(target_keywords: List[str]) -> List[Dict[str, Any]]:
    """Fetch threat intelligence RSS feeds for dark web correlated signals."""
    findings = []

    async with httpx.AsyncClient(headers=HEADERS, timeout=25.0, follow_redirects=True) as client:
        for feed in THREAT_INTEL_FEEDS:
            try:
                resp = await client.get(feed["url"])
                parsed = feedparser.parse(resp.text)
                for entry in parsed.entries[:20]:
                    title = entry.get("title", "")
                    summary = (entry.get("summary", "") or entry.get("description", ""))[:500]
                    combined = (title + " " + summary).lower()
                    hit_kw = [k for k in target_keywords if k.lower() in combined]
                    breach_score = _score_content(combined, BREACH_KEYWORDS)
                    cves = CVE_RE.findall(combined)
                    ransomware_groups = _detect_ransomware_groups(combined)
                    is_high_signal = (
                        hit_kw or
                        (breach_score >= 3) or
                        (cves and breach_score >= 1) or
                        ransomware_groups
                    )
                    if is_high_signal:
                        risk = _assess_risk(hit_kw, breach_score, cves, "intel")
                        findings.append({
                            "source": feed["name"],
                            "title": title[:200],
                            "link": entry.get("link", ""),
                            "matched_keywords": hit_kw,
                            "breach_signals": breach_score,
                            "cves": list(set(cves)),
                            "risk": risk,
                            "published": entry.get("published", ""),
                            "type": "intel",
                            "ransomware_groups": ransomware_groups,
                            "summary": summary[:300] if summary else "",
                        })
            except Exception as e:
                logger.error(f"[DARKWEB] Intel feed error {feed['name']}: {e}")

    return findings


async def fetch_cisa_kev_signals(target_keywords: List[str]) -> List[Dict[str, Any]]:
    """Fetch CISA KEV and match against keywords — KEV = actively exploited in wild."""
    findings = []
    try:
        async with httpx.AsyncClient(headers=HEADERS, timeout=20.0) as client:
            resp = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            for v in vulns[:300]:
                product = (v.get("product", "") + " " + v.get("vendorProject", "")).lower()
                desc = v.get("shortDescription", "").lower()
                combined = product + " " + desc
                hit_kw = [k for k in target_keywords if k.lower() in combined]
                ransomware_use = v.get("knownRansomwareCampaignUse", "Unknown")
                if hit_kw or ransomware_use.lower() == "known":
                    findings.append({
                        "source": "CISA KEV (Active Exploitation)",
                        "title": f"{v.get('cveID')} — {v.get('vulnerabilityName', '')}",
                        "link": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
                        "matched_keywords": hit_kw,
                        "breach_signals": 5,
                        "cves": [v.get("cveID", "")],
                        "risk": "CRITICAL",
                        "published": v.get("dateAdded", ""),
                        "type": "kev",
                        "due_date": v.get("dueDate", ""),
                        "ransomware": ransomware_use,
                        "ransomware_groups": [],
                        "summary": v.get("shortDescription", "")[:300],
                        "vendor": v.get("vendorProject", ""),
                        "product": v.get("product", ""),
                    })
    except Exception as e:
        logger.error(f"[DARKWEB] CISA KEV error: {e}")
    return findings


async def check_breach_exposure(email_or_domain: str) -> Dict[str, Any]:
    """
    Check breach exposure via public signals.
    Note: Full HIBP requires a paid API key.
    """
    domain = email_or_domain.split("@")[-1] if "@" in email_or_domain else email_or_domain
    is_email = "@" in email_or_domain

    kev_hits = []
    try:
        async with httpx.AsyncClient(headers=HEADERS, timeout=15.0) as client:
            resp = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            data = resp.json()
            for v in data.get("vulnerabilities", [])[:500]:
                product = (v.get("product", "") + " " + v.get("vendorProject", "")).lower()
                if domain.lower().split(".")[0] in product:
                    kev_hits.append({
                        "cve": v.get("cveID"),
                        "name": v.get("vulnerabilityName"),
                        "date": v.get("dateAdded"),
                    })
    except Exception:
        pass

    return {
        "target": email_or_domain,
        "type": "email" if is_email else "domain",
        "domain": domain,
        "checked": True,
        "kev_hits": kev_hits[:5],
        "kev_count": len(kev_hits),
        "hibp_note": "Live breach check requires HaveIBeenPwned API key",
        "hibp_url": f"https://haveibeenpwned.com/account/{email_or_domain}" if is_email else f"https://haveibeenpwned.com/DomainSearch/{domain}",
        "shodan_url": f"https://www.shodan.io/search?query={domain}",
        "osint_url": f"https://search.censys.io/search?resource=hosts&q={domain}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def run_dark_web_scan(targets: List[str]) -> Dict[str, Any]:
    """Full dark web intelligence scan for a list of target keywords."""
    paste_task = fetch_paste_signals(targets)
    intel_task = fetch_threat_intel_feeds(targets)
    kev_task = fetch_cisa_kev_signals(targets)

    paste_results, intel_results, kev_results = await asyncio.gather(
        paste_task, intel_task, kev_task, return_exceptions=True
    )

    all_findings = []
    if isinstance(paste_results, list):
        all_findings.extend(paste_results)
    if isinstance(intel_results, list):
        all_findings.extend(intel_results)
    if isinstance(kev_results, list):
        all_findings.extend(kev_results)

    # Deduplicate by title
    seen_titles = set()
    unique_findings = []
    for f in all_findings:
        key = f["title"][:80].lower()
        if key not in seen_titles:
            seen_titles.add(key)
            unique_findings.append(f)

    unique_findings.sort(key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("risk", "LOW"), 3),
        -x.get("breach_signals", 0)
    ))

    all_ransomware = []
    for f in unique_findings:
        all_ransomware.extend(f.get("ransomware_groups", []))
    ransomware_counts = {}
    for g in all_ransomware:
        ransomware_counts[g] = ransomware_counts.get(g, 0) + 1

    stats = {
        "total": len(unique_findings),
        "critical": sum(1 for f in unique_findings if f.get("risk") == "CRITICAL"),
        "high": sum(1 for f in unique_findings if f.get("risk") == "HIGH"),
        "medium": sum(1 for f in unique_findings if f.get("risk") == "MEDIUM"),
        "kev_matches": sum(1 for f in unique_findings if f.get("type") == "kev"),
        "paste_matches": sum(1 for f in unique_findings if f.get("type") == "paste"),
        "intel_matches": sum(1 for f in unique_findings if f.get("type") == "intel"),
        "ransomware_mentions": len([f for f in unique_findings if f.get("ransomware_groups")]),
        "top_ransomware": sorted(ransomware_counts.items(), key=lambda x: x[1], reverse=True)[:5],
    }

    return {
        "findings": unique_findings,
        "stats": stats,
        "targets": targets,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
