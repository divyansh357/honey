"""
Session Storage Module
=======================
Thread-safe JSON-based session persistence for the honeypot.

Each session tracks:
- Message history
- Extracted intelligence
- Scam detection state
- Timing for engagement metrics
- Callback delivery status

Uses file-level locking and atomic writes (write to temp, then replace)
to prevent data corruption under concurrent access.
"""

import json
import os
import time
import logging
from threading import Lock

logger = logging.getLogger(__name__)

SESSION_FILE = "sessions.json"
session_lock = Lock()


def load_sessions() -> dict:

    """
    Load all sessions from the JSON file.

    Thread-safe read with corruption recovery — if the file is
    malformed, returns empty dict instead of crashing.

    Returns:
        Dict mapping session IDs to session data
    """
    if not os.path.exists(SESSION_FILE):
        return {}

    with session_lock:
        try:
            with open(SESSION_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("sessions.json corrupted — resetting safely")
            return {}
        except Exception as e:
            logger.error(f"Failed to load sessions: {e}")
            return {}


# ---------- ATOMIC FILE WRITE ----------

def save_sessions(sessions: dict) -> None:
    """
    Persist all sessions to JSON file using atomic write.

    Writes to a temporary file first, then atomically replaces
    the original to prevent corruption from partial writes.

    Args:
        sessions: Complete sessions dict to persist
    """
    temp_file = SESSION_FILE + ".tmp"

    with session_lock:
        try:
            with open(temp_file, "w") as f:
                json.dump(sessions, f, indent=2)
            os.replace(temp_file, SESSION_FILE)
        except Exception as e:
            logger.error(f"Failed to save sessions: {e}")


# ---------- CREATE / FETCH SESSION ----------

def get_or_create_session(session_id: str) -> dict:
    """
    Retrieve existing session or create a new one.

    New sessions are initialized with empty intelligence, timing
    data for engagement metrics, and default state flags.

    Args:
        session_id: Unique session identifier

    Returns:
        Session data dict (existing or newly created)
    """
    sessions = load_sessions()

    if session_id not in sessions:

        sessions[session_id] = {
            # Critical for engagement metrics calculation
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

def update_session(session_id: str, session_data: dict) -> None:
    """
    Update a session's data in persistent storage.

    Args:
        session_id: Unique session identifier
        session_data: Complete updated session data dict
    """
    sessions = load_sessions()
    sessions[session_id] = session_data
    save_sessions(sessions)
