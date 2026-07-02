#!/usr/bin/python3

import sqlite3
import time

DB_FILE = "soar_memory.db"

def init_db_architecture():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS deduplication_cache (
            dedup_key TEXT PRIMARY KEY,
            timestamp INTEGER
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS host_events_buffer (
            agent_name TEXT,
            rule_id INTEGER,
            timestamp INTEGER,
            encoded_command INTEGER,
            network_connection INTEGER,
            file_created INTEGER,
            persistence_registry INTEGER,
            injection_signal INTEGER,
            lsass_access INTEGER,
            severity INTEGER
        )
    """)
    conn.commit()
    conn.close()

def is_duplicate_alert(rule_id: int, agent_name: str, file_hash: str, process_name: str) -> bool:
    now = int(time.time())
    five_minutes = 5 * 60
    
    indicator = file_hash or process_name or "unknown"
    dedup_key = f"{rule_id}|{agent_name}|{indicator}"
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM deduplication_cache WHERE ? - timestamp > ?", (now, five_minutes))
    
    cursor.execute("SELECT 1 FROM deduplication_cache WHERE dedup_key = ?", (dedup_key,))
    exists = cursor.fetchone()
    
    if exists:
        conn.close()
        return True
        
    cursor.execute("INSERT INTO deduplication_cache (dedup_key, timestamp) VALUES (?, ?)", (dedup_key, now))
    conn.commit()
    conn.close()
    return False

def process_host_activity_window(agent_name: str, alert: dict) -> dict:
    now = int(time.time())
    ten_minutes = 10 * 60
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM host_events_buffer WHERE ? - timestamp > ?", (now, ten_minutes))
    
    cursor.execute("""
        INSERT INTO host_events_buffer 
        (agent_name, rule_id, timestamp, encoded_command, network_connection, file_created, persistence_registry, injection_signal, lsass_access, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        agent_name, alert["rule_id"], now,
        int(alert["encoded_command"]), int(alert["network_connection"]),
        int(alert["file_created"]), int(alert["persistence_registry"]),
        int(alert["injection_signal"]), int(alert["lsass_access"]),
        alert["severity"]
    ))
    conn.commit()
    
    cursor.execute("SELECT * FROM host_events_buffer WHERE agent_name = ?", (agent_name,))
    recent_events = cursor.fetchall()
    conn.close()
    
    count = len(recent_events)
    if count <= 1:
        return {
            "summary": "First alert from this host in the last 10 minutes.",
            "combo_boost": 0
        }
        
    encoded_sum = sum(row[3] for row in recent_events)
    network_sum = sum(row[4] for row in recent_events)
    file_sum    = sum(row[5] for row in recent_events)
    registry_sum= sum(row[6] for row in recent_events)
    inject_sum  = sum(row[7] for row in recent_events)
    lsass_sum   = sum(row[8] for row in recent_events)
    max_severity= max(row[9] for row in recent_events)
    
    combo_boost = 0
    if encoded_sum >= 1 and network_sum >= 1: combo_boost += 25
    if encoded_sum >= 1 and file_sum >= 1:    combo_boost += 20
    if inject_sum >= 1 and lsass_sum >= 1:    combo_boost += 35
    if count >= 5: combo_boost += 15
    
    summary = (
        f"Host had {count} alerts in last 10 min — "
        f"encoded:{encoded_sum} network:{network_sum} file:{file_sum} "
        f"registry:{registry_sum} injection:{inject_sum} lsass:{lsass_sum} "
        f"max_severity:{max_severity}"
    )
    
    return {
        "summary": summary,
        "combo_boost": combo_boost
    }