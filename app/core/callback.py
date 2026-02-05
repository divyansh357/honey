import requests

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


def send_final_callback(session_id: str, session_data: dict):

    if session_data.get("callbackSent"):
        print(f"[CALLBACK SKIPPED] Already sent for {session_id}")
        return

    agent_notes = session_data.get("lastAgentReply")

    if not agent_notes:
        agent_notes = "Scammer attempted urgent account verification and requested sensitive banking details."

    payload = {
        "sessionId": session_id,
        "scamDetected": session_data["scamDetected"],
        "totalMessagesExchanged": session_data["totalMessages"],
        "extractedIntelligence": session_data["intelligence"],
        "agentNotes": agent_notes
    }

    print("==== GUVI CALLBACK PAYLOAD ====")
    print(payload)

    for attempt in range(2):
        try:
            response = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=10
            )

            print("CALLBACK STATUS:", response.status_code)
            print("CALLBACK RESPONSE:", response.text)

            response.raise_for_status()

            session_data["callbackSent"] = True

            print(f"[GUVI CALLBACK SUCCESS] session={session_id}")
            return

        except Exception as e:
            print(f"[CALLBACK RETRY {attempt+1}] error={e}")
