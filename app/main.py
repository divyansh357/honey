# app/main.py

import uuid
import time
from fastapi import FastAPI, Depends
from requests import session
from requests import session
from app.security import verify_api_key
from app.schemas import (
    IncomingRequest,
    ApiResponse,
    EngagementMetrics,
    ExtractedIntelligence
)
from app.session_store import get_or_create_session
from app.core.scam_detector import detect_scam
from app.core.agent import generate_agent_reply
from app.core.intelligence import extract_intelligence
from app.core.callback import send_final_callback

app = FastAPI(title="Agentic HoneyPot API")


# ---------- HELPER FUNCTIONS ----------

def conversation_to_text(messages):
    if not messages:
        return "No conversation yet."

    lines = []
    for msg in messages:
        sender = msg.get("sender", "unknown")
        text = msg.get("text", "")
        lines.append(f"{sender}: {text}")

    return "\n".join(lines)


def should_close_session(session: dict) -> bool:
    intelligence = session["intelligence"]

    has_payment_info = (
        len(intelligence["bankAccounts"]) > 0 or
        len(intelligence["upiIds"]) > 0 or
        len(intelligence["phishingLinks"]) > 0
    )

    enough_turns = session["totalMessages"] >= 6

    return has_payment_info or enough_turns


# ---------- API ENDPOINT ----------

@app.post("/honeypot", response_model=ApiResponse)
def honeypot_endpoint(
    data: IncomingRequest,
    _: str = Depends(verify_api_key)
):
    # --------- INPUT NORMALIZATION (CRITICAL FOR TESTER) ---------

    # Ensure sessionId
    session_id = data.sessionId or f"tester-{uuid.uuid4()}"
    session = get_or_create_session(session_id)

    # Normalize message
    if isinstance(data.message, dict):
        sender = data.message.get("sender", "scammer")
        text = data.message.get("text", "test message")
    elif isinstance(data.message, str):
        sender = "scammer"
        text = data.message
    else:
        sender = "scammer"
        text = "test message"

    normalized_message = {
        "sender": sender,
        "text": text,
        "timestamp": None
    }

    session["messages"].append(normalized_message)
    session["totalMessages"] += 1

    # 2️⃣ Convert conversation for LLM
    conversation_text = conversation_to_text(session["messages"])

    # 3️⃣ Scam detection
    if not session["scamDetected"]:
        result = detect_scam(conversation_text)
        session["scamDetected"] = result.get("scamDetected", False)

    # 4️⃣ Agent activation
    agent_reply = ""
    if session["scamDetected"]:
        agent_reply = generate_agent_reply(conversation_text)
        session["agentActive"] = True

    # 5️⃣ Intelligence extraction (ONLY from scammer)
    if data.message.sender == "scammer":
        extracted = extract_intelligence(data.message.text)

        for key, values in extracted.items():
            for value in values:
                if value not in session["intelligence"][key]:
                    session["intelligence"][key].append(value)

    # 6️⃣ NOW check for conversation completion
    if session["scamDetected"] and not session.get("closed", False):
        if should_close_session(session):
            send_final_callback(data.sessionId, session)
            session["closed"] = True

    # 7️⃣ Engagement metrics
    duration = int(time.time() - session["startTime"])

    return ApiResponse(
        status="success",
        scamDetected=session["scamDetected"],
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=duration,
            totalMessagesExchanged=session["totalMessages"]
        ),
        extractedIntelligence=ExtractedIntelligence(
            **session["intelligence"]
        ),
        agentNotes=agent_reply if agent_reply else "Monitoring conversation"
    )
