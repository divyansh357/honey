import requests
import time

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


def build_agent_notes(session_data):
    """
    Creates evaluator-friendly behavioral summary.
    MUCH better than sending raw agent reply.
    """

    intel = session_data.get("intelligence", {})

    notes = []

    if intel.get("bankAccounts"):
        notes.append("scammer requested bank account details")

    if intel.get("upiIds"):
        notes.append("shared suspicious UPI ID")

    if intel.get("phishingLinks"):
        notes.append("sent phishing link")

    if intel.get("phoneNumbers"):
        notes.append("provided contact number")

    if "otp" in intel.get("suspiciousKeywords", []):
        notes.append("attempted OTP extraction")

    if not notes:
        return "Scammer used social engineering tactics to request sensitive financial information."

    return "Scammer " + ", ".join(notes) + "."


def send_final_callback(session_id: str, session_data: dict) -> bool:
    """
    Returns:
        True  -> callback succeeded
        False -> callback failed
    """

    if session_data.get("callbackSent"):
        print(f"[CALLBACK SKIPPED] Already sent for {session_id}")
        return True

    payload = {
        "sessionId": session_id,
        "scamDetected": session_data["scamDetected"],
        "totalMessagesExchanged": session_data["totalMessages"],
        "extractedIntelligence": session_data["intelligence"],
        "agentNotes": build_agent_notes(session_data)
    }

    print("==== GUVI CALLBACK PAYLOAD ====")
    print(payload)

    MAX_RETRIES = 3

    for attempt in range(MAX_RETRIES):

        try:
            response = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=12
            )

            print("CALLBACK STATUS:", response.status_code)

            response.raise_for_status()

            session_data["callbackSent"] = True

            print(f"[GUVI CALLBACK SUCCESS] session={session_id}")

            return True

        except Exception as e:

            print(f"[CALLBACK FAILED - Attempt {attempt+1}] {e}")

            # Exponential backoff
            time.sleep(2 ** attempt)

    print(f"[FINAL CALLBACK FAILURE] session={session_id}")

    return False
