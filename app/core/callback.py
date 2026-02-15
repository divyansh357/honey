import requests
import time

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


def build_agent_notes(session_data):
    """
    Creates evaluator-friendly behavioral summary.
    Covers urgency tactics, payment redirection, and intelligence gathered.
    """

    intel = session_data.get("intelligence", {})
    keywords = intel.get("suspiciousKeywords", [])

    notes = []

    # Tactic-based notes
    urgency_words = {"urgent", "immediately", "act now", "limited time", "expire"}
    if urgency_words & set(keywords):
        notes.append("used urgency tactics")

    if intel.get("bankAccounts"):
        notes.append("attempted to extract bank account details")

    if intel.get("upiIds"):
        notes.append("shared suspicious UPI ID for payment redirection")

    if intel.get("phishingLinks"):
        notes.append("sent phishing link")

    if intel.get("phoneNumbers"):
        notes.append("provided contact number for off-platform communication")

    if "otp" in keywords:
        notes.append("attempted OTP extraction")

    if "kyc" in keywords:
        notes.append("used fake KYC verification pretext")

    if {"blocked", "suspended", "account blocked", "account suspended"} & set(keywords):
        notes.append("claimed account suspension to create panic")

    if {"refund", "claim", "lottery", "prize", "winner"} & set(keywords):
        notes.append("used fake reward/refund scheme")

    if {"password", "cvv", "card number", "credential"} & set(keywords):
        notes.append("attempted credential theft")

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

    # Format phone numbers with +91 prefix as required by GUVI
    intel = session_data["intelligence"]
    formatted_intel = {
        "bankAccounts": intel.get("bankAccounts", []),
        "upiIds": intel.get("upiIds", []),
        "phishingLinks": intel.get("phishingLinks", []),
        "phoneNumbers": [
            f"+91{p}" if not p.startswith("+") else p
            for p in intel.get("phoneNumbers", [])
        ],
        "suspiciousKeywords": intel.get("suspiciousKeywords", [])
    }

    payload = {
        "sessionId": session_id,
        "scamDetected": session_data["scamDetected"],
        "totalMessagesExchanged": session_data["totalMessages"],
        "extractedIntelligence": formatted_intel,
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
                headers={"Content-Type": "application/json"},
                timeout=5
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
