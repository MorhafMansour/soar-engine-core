# SOAR Engine Core 

### Project Overview
This is my graduation project. Originally, the workflow logic was planned and prototyped using n8n node architecture, but now it is fully migrated and built as a real, working production engine using Python, FastAPI, and SQLite. 

Here is exactly how the system works and how the code processes security alerts step by step across 5 pipeline stages:

---

##  How the Code Works (The 5 Pipeline Stages)

###  Stage 1: The Forensic Normalizer (pipeline/normalizer.py)
Wazuh sends huge and messy nested JSON payloads. This module receives the raw alert webhook, cleans the data, and extracts only the important forensic indicators we need (like IP addresses, file hashes, and specific process command lines) into a neat python dictionary. If no suspicious flags are found, it filters the log out immediately to save server compute.

###  Stage 2: Deduplication Check (pipeline/database.py)
To prevent alert fatigue and system flooding, the code checks a fast local SQLite database cache. If the exact same alert from the same host machine or file hash happened within the last 5 minutes, the engine drops it instantly so we don't waste API keys or spam our logs.

### Stage 3: OSINT Threat Enrichment (pipeline/osint.py)
If the hash is new, the code grabs the SHA256 string and queries the VirusTotal and MalwareBazaar APIs automatically to check if the file is a known malware or malicious threat. I also included an internal whitelist for common windows files (like cmd.exe) to bypass lookups and preserve our free daily API query limits.

###  Stage 4: Stateful Host Activity Window (pipeline/database.py)
This is the smartest analytical part of the code. The engine tracks and counts the behavioral log history of the infected host over a sliding 10-minute time window. If a machine runs an encoded command and then triggers a network connection, the script correlates this "Combo Attack" and dynamically boosts the overall Confidence Score.

###  Stage 5: AI Analysis & Automated SSH Response (main.py + pipeline/response.py)
Finally, the script sends the enriched alert data to OpenAI GPT to generate a clear, 1-sentence analytical verdict. Then, it fires a rich-format alert message to my Telegram bot with custom interactive buttons: Approve (Isolate Host) or Decline. 

When the administrator clicks Approve on their phone, Telegram hits our ngrok webhook endpoint (/webhook/telegram-callback), which instantly fires an automated Paramiko SSH connection to the target victim machine to run firewall isolation scripts and quarantine the threat immediately!

---

###  Repository File Structure
The project is built using a modular micro-architecture rather than one big messy code file:
* **main.py**: The central brain that fires the FastAPI server and listens for Wazuh and Telegram webhooks.
* **requirements.txt**: List of Python external dependencies (fastapi, uvicorn, requests, paramiko).
* **pipeline/**: The folder containing separated code scripts for each processing stage (normalizer.py, osint.py, database.py, response.py).
