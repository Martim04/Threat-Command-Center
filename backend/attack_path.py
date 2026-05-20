"""attack_path.py — MITRE ATT&CK Kill Chain Visualizer"""
from typing import List, Dict, Any

TACTICS = [
    {"id":"TA0001","name":"Initial Access","color":"#f43f5e","order":1},
    {"id":"TA0002","name":"Execution","color":"#f97316","order":2},
    {"id":"TA0003","name":"Persistence","color":"#f59e0b","order":3},
    {"id":"TA0004","name":"Privilege Escalation","color":"#eab308","order":4},
    {"id":"TA0005","name":"Defense Evasion","color":"#84cc16","order":5},
    {"id":"TA0006","name":"Credential Access","color":"#10b981","order":6},
    {"id":"TA0007","name":"Discovery","color":"#06b6d4","order":7},
    {"id":"TA0008","name":"Lateral Movement","color":"#3b82f6","order":8},
    {"id":"TA0009","name":"Collection","color":"#6366f1","order":9},
    {"id":"TA0010","name":"Exfiltration","color":"#ec4899","order":10},
    {"id":"TA0040","name":"Impact","color":"#f43f5e","order":11},
]

TACTIC_BY_ID = {t["id"]: t for t in TACTICS}

KEYWORD_MAP = [
    {"kw":["web","apache","nginx","wordpress","php","iis"],"techs":[
        {"id":"T1190","name":"Exploit Public-Facing App","tactic":"TA0001","l":0.9},
        {"id":"T1133","name":"External Remote Services","tactic":"TA0001","l":0.5},
    ]},
    {"kw":["sql","mysql","postgresql","mongodb","oracle"],"techs":[
        {"id":"T1190","name":"Exploit Public-Facing App","tactic":"TA0001","l":0.8},
        {"id":"T1005","name":"Data from Local System","tactic":"TA0009","l":0.7},
        {"id":"T1041","name":"Exfiltration Over C2","tactic":"TA0010","l":0.6},
    ]},
    {"kw":["openssl","tls","ssl","crypto"],"techs":[
        {"id":"T1557","name":"Adversary-in-the-Middle","tactic":"TA0008","l":0.7},
        {"id":"T1552","name":"Unsecured Credentials","tactic":"TA0006","l":0.5},
    ]},
    {"kw":["auth","ldap","oauth","jwt","kerberos","active directory"],"techs":[
        {"id":"T1110","name":"Brute Force","tactic":"TA0006","l":0.8},
        {"id":"T1078","name":"Valid Accounts","tactic":"TA0001","l":0.7},
    ]},
    {"kw":["docker","kubernetes","container","k8s"],"techs":[
        {"id":"T1610","name":"Deploy Container","tactic":"TA0002","l":0.7},
        {"id":"T1611","name":"Escape to Host","tactic":"TA0004","l":0.6},
    ]},
    {"kw":["ssh","rdp","remote","openssh"],"techs":[
        {"id":"T1021","name":"Remote Services","tactic":"TA0008","l":0.8},
        {"id":"T1133","name":"External Remote Services","tactic":"TA0001","l":0.7},
    ]},
    {"kw":["python","pip","node","npm","java","spring","log4j"],"techs":[
        {"id":"T1195","name":"Supply Chain Compromise","tactic":"TA0001","l":0.6},
        {"id":"T1059","name":"Command Scripting Interpreter","tactic":"TA0002","l":0.7},
    ]},
    {"kw":["windows","smb","powershell","wmi"],"techs":[
        {"id":"T1059.001","name":"PowerShell","tactic":"TA0002","l":0.8},
        {"id":"T1543","name":"Create/Modify System Process","tactic":"TA0003","l":0.6},
        {"id":"T1021.002","name":"SMB/Windows Admin Shares","tactic":"TA0008","l":0.6},
    ]},
    {"kw":["redis","memcached","kafka","rabbitmq"],"techs":[
        {"id":"T1190","name":"Exploit Public-Facing App","tactic":"TA0001","l":0.7},
        {"id":"T1005","name":"Data from Local System","tactic":"TA0009","l":0.6},
    ]},
]

CVE_BOOST = {
    "T1190":["injection","rce","remote code","sqli","deserialization","path traversal"],
    "T1110":["brute","credential","auth bypass"],
    "T1557":["mitm","ssl strip","arp"],
    "T1195":["supply chain","dependency","typosquat"],
    "T1059":["command injection","shell","eval","exec"],
}


def map_stack_to_techniques(stack_items: List[str], cve_descriptions: List[str] = None) -> Dict[str, Any]:
    tech_map: Dict[str, Dict] = {}
    cve_descriptions = cve_descriptions or []

    for item in stack_items:
        il = item.lower()
        for mapping in KEYWORD_MAP:
            if any(kw in il for kw in mapping["kw"]):
                for tech in mapping["techs"]:
                    tid = tech["id"]
                    if tid not in tech_map:
                        tac = TACTIC_BY_ID.get(tech["tactic"], {})
                        tech_map[tid] = {
                            "id": tid, "name": tech["name"],
                            "tactic": tech["tactic"], "likelihood": tech["l"],
                            "tactic_name": tac.get("name",""),
                            "tactic_color": tac.get("color","#666"),
                            "tactic_order": tac.get("order",99),
                            "triggered_by": [],
                        }
                    tech_map[tid]["triggered_by"].append(item)

    for desc in cve_descriptions:
        dl = desc.lower()
        for tid, patterns in CVE_BOOST.items():
            if tid in tech_map and any(p in dl for p in patterns):
                tech_map[tid]["likelihood"] = min(1.0, tech_map[tid]["likelihood"] + 0.15)

    tactic_groups: Dict[str, list] = {}
    for tech in tech_map.values():
        tactic_groups.setdefault(tech["tactic"], []).append(tech)

    kill_chain = []
    for tac in sorted(TACTICS, key=lambda t: t["order"]):
        techs = tactic_groups.get(tac["id"], [])
        if techs:
            kill_chain.append({
                "tactic": tac,
                "techniques": sorted(techs, key=lambda t: -t["likelihood"]),
            })

    n = len(tech_map)
    risk = "CRITICAL" if n > 8 else "HIGH" if n > 5 else "MEDIUM" if n > 2 else "LOW"

    return {
        "kill_chain": kill_chain,
        "total_techniques": n,
        "tactics_covered": len(kill_chain),
        "overall_risk": risk,
        "high_likelihood": [t for t in tech_map.values() if t["likelihood"] >= 0.8],
        "stack_analyzed": stack_items,
    }
