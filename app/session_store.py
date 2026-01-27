# app/session_store.py
import time

sessions = {}

def get_or_create_session(session_id: str):
    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [],
            "scamDetected": False,
            "agentActive": False,
            "intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "startTime": time.time(),
            "totalMessages": 0,
            "closed": False
        }
    return sessions[session_id]
