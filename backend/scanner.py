import httpx
import json
import re
from typing import List, Dict, Any, Optional
from packaging.requirements import Requirement
from logger import logger

OSV_API = "https://api.osv.dev/v1"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ─── OSV Scanner ──────────────────────────────────────────────────────────────

def parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        try:
            req = Requirement(line)
            version = None
            for spec in req.specifier:
                if spec.operator in ("==", "~="):
                    version = spec.version
                    break
            packages.append({"name": req.name, "version": version or ""})
        except Exception:
            match = re.match(r"^([A-Za-z0-9_\-\.]+)[>=<!\[~]?([\d\.]*)", line)
            if match:
                packages.append({"name": match.group(1), "version": match.group(2)})
    return packages


def parse_package_json(content: str) -> List[Dict[str, str]]:
    packages = []
    try:
        data = json.loads(content)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        for name, ver in deps.items():
            clean = ver.lstrip("^~>=<").split(" ")[0].strip()
            packages.append({"name": name, "version": clean})
    except Exception as e:
        logger.error(f"[SCANNER] Error parsing package.json: {e}")
    return packages


async def query_osv(packages: List[Dict[str, str]], ecosystem: str) -> List[Dict[str, Any]]:
    results = []
    async with httpx.AsyncClient() as client:
        for pkg in packages:
            if not pkg.get("version"):
                continue
            payload = {
                "package": {
                    "name": pkg["name"],
                    "ecosystem": ecosystem,
                },
                "version": pkg["version"]
            }
            try:
                resp = await client.post(f"{OSV_API}/query", json=payload, timeout=20.0)
                data = resp.json()
                vulns = data.get("vulns", [])
                for v in vulns:
                    aliases = v.get("aliases", [])
                    cve_ids = [a for a in aliases if a.startswith("CVE-")]
                    score = _extract_osv_score(v)
                    results.append({
                        "package": pkg["name"],
                        "version": pkg.get("version", ""),
                        "osv_id": v.get("id"),
                        "cve_ids": cve_ids,
                        "summary": v.get("summary", ""),
                        "details": v.get("details", "")[:400],
                        "cvss_score": score,
                        "severity": _score_to_severity(score),
                        "published": v.get("published", ""),
                    })
            except Exception as e:
                logger.error(f"[SCANNER] OSV query error for {pkg['name']}: {e}")
    return results


def _extract_osv_score(vuln: dict) -> float | None:
    """
    Extract a numeric CVSS base score from an OSV vulnerability object.
    OSV severity[].score is a CVSS *vector string* (not a number).
    We check multiple locations and fall back to label-based estimation.
    """
    # 1. database_specific numeric fields
    db = vuln.get("database_specific", {})
    for key in ("cvss", "cvss_score", "score", "base_score"):
        val = db.get(key)
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                pass

    # 2. affected[].database_specific or ecosystem_specific
    for affected in vuln.get("affected", []):
        for sub in (affected.get("database_specific", {}),
                    affected.get("ecosystem_specific", {})):
            for key in ("cvss", "cvss_score", "score", "base_score", "severity_score"):
                val = sub.get(key)
                if val is not None:
                    try:
                        return float(val)
                    except (ValueError, TypeError):
                        pass

    # 3. Map severity label to midpoint score (for sorting when no numeric score exists)
    sev_label = db.get("severity", "")
    if not sev_label:
        for affected in vuln.get("affected", []):
            sev_label = affected.get("database_specific", {}).get("severity", "")
            if sev_label:
                break

    label_map = {
        "CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5,
        "LOW": 2.0, "MODERATE": 5.5, "IMPORTANT": 8.0,
    }
    if sev_label and sev_label.upper() in label_map:
        return label_map[sev_label.upper()]

    return None


def _score_to_severity(score) -> str:
    if score is None:
        return "UNKNOWN"
    try:
        s = float(score)
        if s >= 9.0:
            return "CRITICAL"
        elif s >= 7.0:
            return "HIGH"
        elif s >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    except Exception:
        return "UNKNOWN"


# ─── NVD Tracker ──────────────────────────────────────────────────────────────

async def query_nvd_for_keyword(keyword: str, days_back: int = 90) -> List[Dict[str, Any]]:
    results = []
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
    }
    headers = {"User-Agent": "ThreatCommandCenter/1.0"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(NVD_API, params=params, headers=headers, timeout=30.0)
            if resp.status_code != 200:
                logger.warning(f"[NVD] Non-200 for {keyword}: {resp.status_code}")
                return []
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
                metrics = cve.get("metrics", {})
                score, severity = _extract_nvd_score(metrics)
                results.append({
                    "cve_id": cve_id,
                    "stack_item": keyword,
                    "description": desc[:500],
                    "severity": severity,
                    "cvss_score": score,
                    "published": cve.get("published", ""),
                })
    except Exception as e:
        logger.error(f"[NVD] Error querying for '{keyword}': {e}")
    return results


def _extract_nvd_score(metrics: dict):
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity", "UNKNOWN")
            if not severity and score:
                severity = _score_to_severity(score)
            return score, severity
    return None, "UNKNOWN"
