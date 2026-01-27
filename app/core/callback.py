# app/core/callback.py

import requests

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_final_callback(session_id: str, session_data: dict):
    payload = {
        "sessionId": session_id,
        "scamDetected": session_data["scamDetected"],
        "totalMessagesExchanged": session_data["totalMessages"],
        "extractedIntelligence": session_data["intelligence"],
        "agentNotes": "Scammer used urgency and payment redirection tactics"
    }

    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5
        )
        response.raise_for_status()
        print(f"[GUVI CALLBACK SUCCESS] session={session_id}")
    except Exception as e:
        print(f"[GUVI CALLBACK FAILED] session={session_id} error={e}")
