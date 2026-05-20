"""compliance.py — NIS2 Directive Compliance Gap Analyzer"""
from typing import List, Dict, Any

NIS2_ARTICLES = [
    {
        "article": "Art. 21.2(a)", "title": "Policies on Risk Analysis & IS",
        "description": "Risk analysis and information system security policies must be in place.",
        "controls": ["risk_assessment","security_policy","asset_management"],
        "weight": 10,
    },
    {
        "article": "Art. 21.2(b)", "title": "Incident Handling",
        "description": "Policies and procedures for handling security incidents.",
        "controls": ["incident_response","siem","log_monitoring"],
        "weight": 10,
    },
    {
        "article": "Art. 21.2(c)", "title": "Business Continuity & DR",
        "description": "Business continuity management including backup management and disaster recovery.",
        "controls": ["backup","disaster_recovery","business_continuity"],
        "weight": 8,
    },
    {
        "article": "Art. 21.2(d)", "title": "Supply Chain Security",
        "description": "Security in the supply chain including security aspects concerning relationships with suppliers.",
        "controls": ["supplier_assessment","sbom","dependency_scanning"],
        "weight": 9,
    },
    {
        "article": "Art. 21.2(e)", "title": "Secure Dev & Vulnerability Handling",
        "description": "Security in network and information system acquisition, development and maintenance including vulnerability handling.",
        "controls": ["vulnerability_scanning","patch_management","sast","dast"],
        "weight": 10,
    },
    {
        "article": "Art. 21.2(f)", "title": "Policies to Assess Security Measures",
        "description": "Policies and procedures to assess the effectiveness of cybersecurity risk-management measures.",
        "controls": ["security_audits","penetration_testing","metrics"],
        "weight": 7,
    },
    {
        "article": "Art. 21.2(g)", "title": "Basic Cyber Hygiene & Training",
        "description": "Basic cyber hygiene practices and cybersecurity training.",
        "controls": ["security_training","mfa","password_policy","patch_management"],
        "weight": 8,
    },
    {
        "article": "Art. 21.2(h)", "title": "Cryptography & Encryption",
        "description": "Policies and procedures regarding the use of cryptography and, where appropriate, encryption.",
        "controls": ["encryption","tls_policy","key_management"],
        "weight": 8,
    },
    {
        "article": "Art. 21.2(i)", "title": "Human Resources & Access Control",
        "description": "Human resources security, access control policies and asset management.",
        "controls": ["access_control","mfa","identity_management","least_privilege"],
        "weight": 9,
    },
    {
        "article": "Art. 21.2(j)", "title": "Multi-Factor Authentication",
        "description": "The use of multi-factor authentication or continuous authentication solutions.",
        "controls": ["mfa","zero_trust"],
        "weight": 9,
    },
    {
        "article": "Art. 23", "title": "Incident Reporting Obligations",
        "description": "Significant incidents must be notified to CSIRT/authority within 24h (early warning) and 72h (notification).",
        "controls": ["incident_response","siem","log_monitoring","csirt_contact"],
        "weight": 10,
    },
]

# CVE severity → gap signal strength
CVE_GAP_SIGNALS = {
    "CRITICAL": {"vulnerability_scanning": -3, "patch_management": -3, "sast": -2},
    "HIGH":     {"vulnerability_scanning": -2, "patch_management": -2},
    "MEDIUM":   {"vulnerability_scanning": -1},
}

TECH_CONTROL_SIGNALS = {
    "docker":       {"sbom": 1, "dependency_scanning": 1},
    "kubernetes":   {"sbom": 1, "access_control": 1},
    "nginx":        {"tls_policy": 1},
    "apache":       {"tls_policy": 1},
    "openssl":      {"encryption": 1, "tls_policy": 1},
    "redis":        {"access_control": 1, "encryption": 1},
    "postgresql":   {"encryption": 1, "access_control": 1},
    "mysql":        {"encryption": 1, "access_control": 1},
    "wordpress":    {"patch_management": 1, "vulnerability_scanning": 1},
    "python":       {"dependency_scanning": 1, "sast": 1},
    "node.js":      {"dependency_scanning": 1, "sast": 1},
}


def _score_article(article: Dict, control_scores: Dict[str, int]) -> Dict:
    controls = article["controls"]
    total = len(controls)
    present = sum(1 for c in controls if control_scores.get(c, 0) > 0)
    gap = sum(1 for c in controls if control_scores.get(c, 0) < 0)
    
    if total == 0:
        pct = 100
    else:
        pct = max(0, int(((present - gap * 0.5) / total) * 100))
    
    if pct >= 70:
        status = "COMPLIANT"
        color = "#10b981"
    elif pct >= 40:
        status = "PARTIAL"
        color = "#f59e0b"
    else:
        status = "GAP"
        color = "#f43f5e"
    
    missing = [c for c in controls if control_scores.get(c, 0) <= 0]
    
    return {
        **article,
        "score": pct,
        "status": status,
        "color": color,
        "missing_controls": missing,
        "gap_controls": [c for c in controls if control_scores.get(c, 0) < 0],
    }


def analyze_nis2_compliance(
    stack_items: List[str],
    cve_severities: List[str],
    has_mfa: bool = False,
    has_backups: bool = False,
    has_ir_plan: bool = False,
    has_encrypt: bool = False,
    has_siem: bool = False,
    has_pentest: bool = False,
    has_training: bool = False,
    has_acl: bool = False,
    has_vuln: bool = False,
    has_sbom: bool = False,
    has_risk: bool = False,
    has_csirt: bool = False,
) -> Dict[str, Any]:
    # Start with neutral control scores
    control_scores: Dict[str, int] = {}

    # Apply stack signals
    for item in stack_items:
        il = item.lower()
        for tech, signals in TECH_CONTROL_SIGNALS.items():
            if tech in il:
                for ctrl, delta in signals.items():
                    control_scores[ctrl] = control_scores.get(ctrl, 0) + delta

    # Apply CVE signals (gaps)
    for sev in cve_severities:
        for ctrl, delta in CVE_GAP_SIGNALS.get(sev, {}).items():
            control_scores[ctrl] = control_scores.get(ctrl, 0) + delta

    # Apply explicit flags
    if has_mfa:
        control_scores["mfa"] = 2
    if has_backups:
        control_scores["backup"] = 2
        control_scores["disaster_recovery"] = 1
    if has_ir_plan:
        control_scores["incident_response"] = 2
        control_scores["csirt_contact"] = 1
    if has_encrypt:
        control_scores["encryption"] = 2
        control_scores["tls_policy"] = 2
        control_scores["key_management"] = 1
    if has_siem:
        control_scores["siem"] = 2
        control_scores["log_monitoring"] = 2
    if has_pentest:
        control_scores["penetration_testing"] = 2
        control_scores["security_audits"] = 1
    if has_training:
        control_scores["security_training"] = 2
    if has_acl:
        control_scores["access_control"] = 2
        control_scores["identity_management"] = 1
        control_scores["least_privilege"] = 1
    if has_vuln:
        control_scores["vulnerability_scanning"] = 2
    if has_sbom:
        control_scores["sbom"] = 2
        control_scores["dependency_scanning"] = 2
        control_scores["supplier_assessment"] = 1
    if has_risk:
        control_scores["risk_assessment"] = 2
        control_scores["security_policy"] = 2
        control_scores["asset_management"] = 1
    if has_csirt:
        control_scores["csirt_contact"] = 2

    # Score each article
    results = [_score_article(art, control_scores) for art in NIS2_ARTICLES]

    total_weight = sum(a["weight"] for a in NIS2_ARTICLES)
    weighted_score = sum(
        r["score"] * a["weight"] / 100
        for r, a in zip(results, NIS2_ARTICLES)
    )
    overall_pct = int((weighted_score / total_weight) * 100)

    gaps = [r for r in results if r["status"] == "GAP"]
    partials = [r for r in results if r["status"] == "PARTIAL"]

    if overall_pct >= 70:
        overall_status = "LARGELY COMPLIANT"
        overall_color = "#10b981"
    elif overall_pct >= 40:
        overall_status = "PARTIAL COMPLIANCE"
        overall_color = "#f59e0b"
    else:
        overall_status = "SIGNIFICANT GAPS"
        overall_color = "#f43f5e"

    return {
        "articles": results,
        "overall_score": overall_pct,
        "overall_status": overall_status,
        "overall_color": overall_color,
        "critical_gaps": len(gaps),
        "partial_gaps": len(partials),
        "compliant_articles": len([r for r in results if r["status"] == "COMPLIANT"]),
        "top_gaps": sorted(gaps, key=lambda x: x["weight"], reverse=True)[:5],
        "stack_analyzed": stack_items,
        "cve_count": len(cve_severities),
    }
