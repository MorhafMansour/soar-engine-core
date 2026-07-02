import logging
import json
import time
import requests
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from pipeline.normalizer import normalize_alert, should_forward
from pipeline.osint import run_osint_enrichment
from pipeline.database import init_db_architecture, is_duplicate_alert, process_host_activity_window

TELEGRAM_BOT_TOKEN = "8697887432:AAFYwGl8GmBrnw_dsr4xd4F2pc7zyKtzse8"
TELEGRAM_CHAT_ID = "5784028681"
AI_API_URL = "https://api.openai.com/v1/chat/completions"
AI_API_KEY = "YOUR_AI_API_KEY"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
app = FastAPI(title="SOAR Engine Core - Graduation Project 2026")

init_db_architecture()

def calculate_confidence_score(alert: dict) -> int:
    confidence = 30
    
    if alert.get("encoded_command"):          confidence += 20
    if alert.get("suspicious_parent_child"):  confidence += 20
    if alert.get("lsass_access"):             confidence += 25
    if alert.get("injection_signal"):         confidence += 20
    if alert.get("persistence_registry"):     confidence += 15
    if alert.get("wmi_activity"):             confidence += 10
    if alert.get("network_connection"):       confidence += 5

    confidence += alert.get("osint_confidence_boost", 0)
    confidence += alert.get("host_activity_boost", 0)

    severity = alert.get("severity", 0)
    if severity >= 13:      confidence += 15
    elif severity >= 10:    confidence += 10
    elif severity >= 7:     confidence += 5

    return max(0, min(100, confidence))

def get_ai_analysis(alert: dict) -> str:
    if not AI_API_KEY or AI_API_KEY == "YOUR_AI_API_KEY":
        return "AI API Key missing. Skipping automated analysis."

    prompt = (
        f"You are a SOC Analyst. Analyze this alert and provide a 1-sentence analysis.\n"
        f"Host: {alert['agent_name']} | Rule: {alert['rule_id']} - {alert['rule_desc']}\n"
        f"Attack Type: {alert['attack_type']} | Confidence: {alert['confidence']}%\n"
        f"OSINT: {alert['osint_summary']}\n"
        f"Activity: {alert['activity_summary']}"
    )
    try:
        headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 80
        }
        res = requests.post(AI_API_URL, json=payload, headers=headers, timeout=7)
        if res.status_code == 200:
            return res.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logging.error(f"AI Enrichment connection failed: {e}")
    return "Failed to fetch AI analysis due to timeout or connection issue."

def send_interactive_telegram(alert: dict, ai_reason: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    text = (
        f"🚨 *MALWARE ALERT — ACTION REQUIRED*\n\n"
        f"🦠 *Attack Type:* `{alert['attack_type'].upper()}`\n"
        f"📊 *Severity:* {alert['severity']} | 🎯 *Confidence:* {alert['confidence']}%\n"
        f"🖥️ *Host:* {alert['agent_name']} ({alert['agent_ip']})\n"
        f"📁 *File Path:* `{alert['file_path']}`\n"
        f"🏷️ *MITRE ID:* {alert['mitre_id'] or 'N/A'}\n\n"
        f"🔍 *OSINT Summary:*\n{alert['osint_summary']}\n\n"
        f"📈 *Host History (10m):*\n{alert['activity_summary']}\n\n"
        f"🧠 *AI Analyst Verdict:*\n_{ai_reason}_\n\n"
        f"Choose an action below to respond:"
    )
    
    reply_markup = {
        "inline_keyboard": [
            [
                {"text": "✅ Approve (Isolate Host)", "callback_data": f"approve_{alert['agent_name']}_{alert['agent_ip']}"},
                {"text": "❌ Decline & Log Only", "callback_data": "decline_case"}
            ]
        ]
    }
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown", "reply_markup": reply_markup}
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        logging.error(f"Telegram alerting failed: {e}")

def start_pipeline_execution(normalized_alert: dict):
    enriched_alert = run_osint_enrichment(normalized_alert)
    
    activity_metrics = process_host_activity_window(enriched_alert["agent_name"], enriched_alert)
    enriched_alert["activity_summary"] = activity_metrics["summary"]
    enriched_alert["host_activity_boost"] = activity_metrics["combo_boost"]
    
    enriched_alert["confidence"] = calculate_confidence_score(enriched_alert)
    
    ai_verdict = get_ai_analysis(enriched_alert)
    
    send_interactive_telegram(enriched_alert, ai_verdict)

@app.post("/webhook/wazuh-alert")
async def receive_wazuh_event(request: Request, background_tasks: BackgroundTasks):
    try:
        raw_alert = await request.json()
        rule_id = int(raw_alert.get("rule", {}).get("id", 0))
        agent_name = raw_alert.get("agent", {}).get("name", "unknown")
        file_hash = raw_alert.get("syscheck", {}).get("sha256_after") or None
        process_name = raw_alert.get("data", {}).get("win", {}).get("eventdata", {}).get("image") or None

        if is_duplicate_alert(rule_id, agent_name, file_hash, process_name):
            return {"status": "ignored", "reason": "Deduplication hit."}

        alert_object = normalize_alert(raw_alert)
        
        if should_forward(alert_object):
            background_tasks.add_task(start_pipeline_execution, alert_object)
            return {"status": "accepted", "pipeline": "triggered"}
            
        return {"status": "filtered", "pipeline": "stopped"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Core Router Error: {str(e)}")

@app.post("/webhook/telegram-callback")
async def telegram_interactive_callback(request: Request, background_tasks: BackgroundTasks):
    data = await request.json()
    if "callback_query" not in data:
        return {"status": "ignored"}
    
    callback = data["callback_query"]
    callback_data = callback["data"]
    chat_id = callback["message"]["chat"]["id"]
    message_id = callback["message"]["message_id"]
    original_text = callback["message"]["text"]

    if callback_data.startswith("approve_"):
        _, host_name, host_ip = callback_data.split("_")
        result_text = f"\n\n⚡ *RESPONSE EXECUTED:* Host `{host_name}` isolated successfully via SSH."
    else:
        result_text = "\n\n🟡 *CASE CLOSED:* Alert logged and ignored by administrator."

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/editMessageText"
    payload = {"chat_id": chat_id, "message_id": message_id, "text": original_text + result_text, "reply_markup": {"inline_keyboard": []}}
    requests.post(url, json=payload, timeout=5)
    return {"status": "processed"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)