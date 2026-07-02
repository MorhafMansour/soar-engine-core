#!/usr/bin/python3
"""
Wazuh Log Parser & Normalizer
Custom SOAR Engine - Graduation Project 2026
Detects: Droppers, Ransomware, Credential Theft, Persistence, C2, Injection
"""

import re
from datetime import datetime

# ─── MALWARE RULE ID GROUPS ───────────────────────────────────────────────────
DROPPER_RULES = [100200, 100201, 100202, 100209]
CREDENTIAL_THEFT_RULES = [100203, 100217]
INJECTION_RULES = [100204, 100214, 100215]
PERSISTENCE_RULES = [100205, 100206, 100207, 100213]
RANSOMWARE_RULES = [100210, 100211, 100216, 100220]
SUSPICIOUS_FILE_RULES = [100208]
C2_RULES = [100212]
LATERAL_MOVEMENT_RULES = [100218]
CORRELATION_RULES = [100219, 100220]

ALL_MALWARE_RULES = (
    DROPPER_RULES + CREDENTIAL_THEFT_RULES + INJECTION_RULES +
    PERSISTENCE_RULES + RANSOMWARE_RULES + SUSPICIOUS_FILE_RULES +
    C2_RULES + LATERAL_MOVEMENT_RULES + CORRELATION_RULES
)

ORIGINAL_RULES = [550, 554, 555, 591, 592, 593]
ALL_WATCHED_RULES = ALL_MALWARE_RULES + ORIGINAL_RULES

# ─── MALWARE FILE INDICATORS ──────────────────────────────────────────────────
MALICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com", ".pif"]
RANSOMWARE_EXTENSIONS = [".locked", ".encrypted", ".crypt", ".enc", ".ransom", ".wnry", ".wncry", ".zepto", ".locky", ".cerber"]
SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "\\programdata\\"]

MALICIOUS_URL_PATTERNS = [
    r"http[s]?://\d+\.\d+\.\d+\.\d+",
    r"(pastebin\.com|ngrok\.io|bit\.ly|raw\.githubusercontent)",
    r"(cmd=|exec=|shell=|payload=|IEX|Invoke-Expression)",
    r"(\.onion)",
]

# ─── ATTACK CLASSIFIER ────────────────────────────────────────────────────────
def classify_attack(rule_id: int) -> str:
    if rule_id in RANSOMWARE_RULES: return "ransomware"
    elif rule_id in DROPPER_RULES: return "dropper"
    elif rule_id in CREDENTIAL_THEFT_RULES: return "credential_theft"
    elif rule_id in INJECTION_RULES: return "injection"
    elif rule_id in PERSISTENCE_RULES: return "persistence"
    elif rule_id in C2_RULES: return "c2"
    elif rule_id in LATERAL_MOVEMENT_RULES: return "lateral_movement"
    elif rule_id in CORRELATION_RULES: return "correlated_malware"
    elif rule_id in SUSPICIOUS_FILE_RULES: return "suspicious_file"
    return "unknown"

# ─── CORRELATION TAG MAPPER ───────────────────────────────────────────────────
def get_correlation_tag(rule_id: int, eventdata: dict, rule_groups: list) -> str:
    cmd = (eventdata.get("commandLine", "") or "").lower()
    parent = (eventdata.get("parentImage", "") or "").lower()
    child = (eventdata.get("image", "") or "").lower()

    office_parents = ["winword", "excel", "outlook", "powerpnt", "msaccess"]
    script_children = ["cmd", "powershell", "wscript", "mshta", "cscript", "rundll32"]

    encoded = any(x in cmd for x in ["-enc", "-encodedcommand", "fromb64", "iex", "invoke-expression"])
    suspicious_parent = any(p in parent for p in office_parents) and any(c in child for c in script_children)

    if rule_id == 100219 or (encoded and suspicious_parent): return "macro_dropper"
    elif rule_id == 100220 or "ransomware" in rule_groups: return "ransomware"
    elif rule_id in CREDENTIAL_THEFT_RULES: return "credential_theft"
    elif rule_id in PERSISTENCE_RULES: return "persistence_installed"
    elif rule_id in C2_RULES: return "c2_lateral_movement"
    elif encoded: return "encoded_execution"
    return None

# ─── HASH EXTRACTOR ───────────────────────────────────────────────────────────
def extract_hash(raw_alert: dict, eventdata: dict) -> str:
    sc = raw_alert.get("syscheck", {})
    for field in ["sha256_after", "sha1_after", "md5_after"]:
        if sc.get(field): return sc[field]
    hashes = eventdata.get("hashes", "")
    m = re.search(r"SHA256=([A-Fa-f0-9]{64})", hashes)
    return m.group(1) if m else None

# ─── NORMALIZE ────────────────────────────────────────────────────────────────
def normalize_alert(raw_alert: dict) -> dict:
    """تقوم بتنظيف وبناء كائن التنبيه المنظم وإرجاعه محلياً كـ Dictionary لخدمة الـ Pipeline"""
    rule_id     = int(raw_alert.get("rule", {}).get("id", 0))
    rule_groups = raw_alert.get("rule", {}).get("groups", [])
    win       = raw_alert.get("data", {}).get("win", {})
    eventdata = win.get("eventdata", {})
    system    = win.get("system", {})
    event_id  = system.get("eventID", "N/A")

    full_log = raw_alert.get("full_log", "")
    url_match = re.search(r"https?://[^\s\"]+", full_log)

    cmd        = eventdata.get("commandLine", "") or ""
    parent_img = eventdata.get("parentImage", "") or ""
    child_img  = eventdata.get("image", "") or ""
    target_img = eventdata.get("targetImage", "") or ""

    encoded_command = any(x in cmd.lower() for x in [
        "-enc", "-encodedcommand", "fromb64string", "iex", "invoke-expression",
        "downloadstring", "webclient", "downloadfile"
    ])

    office_parents  = ["winword", "excel", "outlook", "powerpnt", "msaccess"]
    script_children = ["cmd", "powershell", "wscript", "mshta", "cscript", "rundll32", "regsvr32"]
    suspicious_parent_child = (
        any(p in parent_img.lower() for p in office_parents) and
        any(c in child_img.lower() for c in script_children)
    )

    registry_key = eventdata.get("targetObject") or eventdata.get("details") or None
    persistence_registry = registry_key and any(x in str(registry_key).lower() for x in ["\\run\\", "\\runonce\\", "\\services\\"])

    source_ip = (
        raw_alert.get("data", {}).get("srcip") or
        eventdata.get("ipAddress") or
        eventdata.get("sourceIp") or
        raw_alert.get("agent", {}).get("ip") or
        None
    )

    mitre_ids = raw_alert.get("rule", {}).get("mitre", {}).get("id", [])

    return {
        "timestamp":    raw_alert.get("timestamp", datetime.now().isoformat()),
        "agent_name":   raw_alert.get("agent", {}).get("name", "unknown"),
        "agent_ip":     raw_alert.get("agent", {}).get("ip", "unknown"),
        "rule_id":      rule_id,
        "rule_desc":    raw_alert.get("rule", {}).get("description", ""),
        "rule_groups":  rule_groups,
        "severity":     raw_alert.get("rule", {}).get("level", 0),
        "mitre_id":     mitre_ids[0] if mitre_ids else None,
        "mitre_tactic": raw_alert.get("rule", {}).get("mitre", {}).get("tactic", [None])[0],
        "mitre_technique": raw_alert.get("rule", {}).get("mitre", {}).get("technique", [None])[0],

        "attack_type":     classify_attack(rule_id),
        "correlation_tag": get_correlation_tag(rule_id, eventdata, rule_groups),
        "malware_family":  None,  

        "source_ip": source_ip,
        "dest_ip":   eventdata.get("destinationIp")   or None,
        "dest_port": eventdata.get("destinationPort") or None,

        "file_path": (raw_alert.get("syscheck", {}).get("path") or eventdata.get("image") or None),
        "file_hash": extract_hash(raw_alert, eventdata),

        "event_id":      event_id,
        "process_name":  child_img.split("\\")[-1] if child_img else (eventdata.get("processName") or None),
        "process_cmd":   cmd        or None,
        "parent_process": parent_img or None,
        "target_user":   eventdata.get("targetUserName") or eventdata.get("subjectUserName") or None,
        "target_host":   eventdata.get("workstationName") or raw_alert.get("agent", {}).get("name") or None,
        "powershell_cmd": eventdata.get("scriptBlockText") or None,
        "registry_key":  registry_key,
        "dll_path":      eventdata.get("imageLoaded") or None,

        "encoded_command":          encoded_command,
        "suspicious_parent_child":  suspicious_parent_child,
        "lsass_access":             event_id == "10" and "lsass" in target_img.lower(),
        "injection_signal":         event_id in ["8", "10"],
        "persistence_registry":     bool(persistence_registry),
        "wmi_activity":             event_id in ["20", "21"],
        "file_created":             event_id == "11",
        "network_connection":       event_id == "3",

        "url": url_match.group(0) if url_match else None,
        "full_log": full_log[:400] if full_log else None,
    }

# ─── FILTERS ──────────────────────────────────────────────────────────────────
def should_forward(alert: dict) -> bool:
    is_watched = int(alert.get("rule_id", 0)) in ALL_WATCHED_RULES
    is_high_sev = int(alert.get("severity", 0)) >= 10
    
    path = (alert.get("file_path") or "").lower()
    has_mal_file = any(path.endswith(ext) for ext in MALICIOUS_EXTENSIONS)
    has_ransom_ext = any(path.endswith(ext) for ext in RANSOMWARE_EXTENSIONS)
    has_susp_path = any(sp in path for sp in SUSPICIOUS_PATHS)
    
    log = alert.get("full_log") or ""
    has_mal_url = any(re.search(p, log, re.IGNORECASE) for p in MALICIOUS_URL_PATTERNS)
    
    has_behavioral = any([
        alert.get("encoded_command"), alert.get("suspicious_parent_child"),
        alert.get("lsass_access"), alert.get("injection_signal"),
        alert.get("persistence_registry"), alert.get("wmi_activity")
    ])
    
    return any([is_watched, is_high_sev, has_mal_file, has_ransom_ext, has_susp_path, has_mal_url, bool(has_behavioral)])