import json
import os
import time
from threading import Lock

SESSION_FILE = "sessions.json"
session_lock = Lock()


# ---------- SAFE FILE READ ----------

def load_sessions():

    if not os.path.exists(SESSION_FILE):
        return {}

    with session_lock:
        try:
            with open(SESSION_FILE, "r") as f:
                return json.load(f)

        except json.JSONDecodeError:
            # Prevent crash if file becomes corrupted
            print("⚠️ sessions.json corrupted — resetting safely")
            return {}


# ---------- ATOMIC FILE WRITE ----------

def save_sessions(sessions):

    temp_file = SESSION_FILE + ".tmp"

    with session_lock:

        with open(temp_file, "w") as f:
            json.dump(sessions, f, indent=2)

        # Atomic replace prevents half-written files
        os.replace(temp_file, SESSION_FILE)


# ---------- CREATE / FETCH SESSION ----------

def get_or_create_session(session_id):

    sessions = load_sessions()

    if session_id not in sessions:

        sessions[session_id] = {

            # 🔴 Critical for engagement metrics
            "startTime": time.time(),

            "messages": [],
            "totalMessages": 0,

            "scamDetected": False,
            "agentActive": False,
            "closed": False,
            "callbackSent": False,

            # Helps generate evaluator-grade notes
            "lastAgentReply": "",

            "intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
                "emails": [],
                "ifscCodes": [],
                "telegramIds": [],
                "apkLinks": []
            }
        }

        save_sessions(sessions)

    return sessions[session_id]


# ---------- UPDATE SESSION ----------

def update_session(session_id, session_data):

    sessions = load_sessions()
    sessions[session_id] = session_data
    save_sessions(sessions)
