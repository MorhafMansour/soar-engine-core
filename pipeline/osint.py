#!/usr/bin/python3

import requests
import logging

VT_API_KEY = "Api-key"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

SYSTEM_BINARY_HASHES = [
    "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3",
    "f43d9bb316e30ae1a3494ac5b0624f6bea1bf054b521c8d8c3f7258cfe24ff12"
]

def run_osint_enrichment(alert: dict) -> dict:
    file_hash = alert.get("file_hash")
    agent_name = alert.get("agent_name")
    
    alert["osint_summary"] = "No hash available — OSINT skipped."
    alert["osint_confidence_boost"] = 0

    if not file_hash:
        return alert

    if file_hash.lower() in SYSTEM_BINARY_HASHES:
        alert["osint_summary"] = "Skipped: Known system binary — OSINT not needed."
        alert["osint_confidence_boost"] = 0
        logging.info(f"[{agent_name}] OSINT skipped for trusted Windows binary.")
        return alert

    logging.info(f"[{agent_name}] Running OSINT enrichment for hash: {file_hash}")
    osint_lines = []
    confidence_boost = 0
    enriched_family = alert.get("malware_family")

    if VT_API_KEY and VT_API_KEY != "87cbfe015ebf15dece0cf5ac9361ed034538595641bed0c4f414f846979a77f7":
        try:
            vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(vt_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                vt_data = response.json().get("data", {}).get("attributes", {})
                stats = vt_data.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values())
                
                verdict = "CLEAN"
                if malicious_count >= 5:
                    verdict = "MALICIOUS"
                    confidence_boost += 40
                elif malicious_count >= 1:
                    verdict = "SUSPICIOUS"
                    confidence_boost += 20
                    
                osint_lines.append(f"🦠 VirusTotal: {malicious_count}/{total_engines} engines flagged — {verdict}")
                
                vt_family = vt_data.get("popular_threat_classification", {}).get("suggested_threat_label")
                if vt_family:
                    osint_lines.append(f"   Suggested Family: {vt_family}")
                    enriched_family = enriched_family or vt_family
            else:
                osint_lines.append(f"🦠 VirusTotal: Hash not found (Status {response.status_code})")
        except Exception as e:
            osint_lines.append(f"🦠 VirusTotal Connection Error: {str(e)}")

    try:
        mb_payload = {"query": "get_info", "hash": file_hash}
        response = requests.post(MALWAREBAZAAR_URL, data=mb_payload, timeout=5)
        
        if response.status_code == 200:
            mb_data = response.json()
            if mb_data.get("query_status") == "ok" and mb_data.get("data"):
                sample = mb_data["data"][0]
                osint_lines.append("📦 MalwareBazaar: KNOWN MALICIOUS SAMPLE FOUND")
                confidence_boost += 25
                
                if sample.get("signature"):
                    osint_lines.append(f"   Signature/Family: {sample['signature']}")
                    enriched_family = enriched_family or sample["signature"]
            else:
                osint_lines.append("📦 MalwareBazaar: Hash not found")
    except Exception as e:
        osint_lines.append(f"📦 MalwareBazaar Connection Error: {str(e)}")

    alert["osint_summary"] = "\n".join(osint_lines) if osint_lines else "OSINT performed with no conclusive results."
    alert["osint_confidence_boost"] = min(confidence_boost, 40)
    alert["malware_family"] = enriched_family or alert["malware_family"]

    logging.info(f"[{agent_name}] OSINT processing complete. Boost calculated: {alert['osint_confidence_boost']}")
    return alert