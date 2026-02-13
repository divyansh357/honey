import time
import uuid
from fastapi import FastAPI, Depends
from app.security import verify_api_key
from app.schemas import AgentReply, IncomingRequest
from app.session_store import get_or_create_session, update_session
from app.core.scam_detector import detect_scam
from app.core.agent import generate_agent_reply
from app.core.intelligence import extract_intelligence
from app.core.callback import send_final_callback

app = FastAPI(title="Agentic HoneyPot API")


# ---------- HELPERS ----------

def conversation_to_text(messages):
    if not messages:
        return "No conversation yet."

    return "\n".join(
        f"{m.get('sender', 'unknown')}: {m.get('text', '')}"
        for m in messages
    )


def should_close_session(session: dict):

    intel = session["intelligence"]

    has_payment_info = (
        intel["bankAccounts"]
        or intel["upiIds"]
        or intel["phishingLinks"]
        or intel["phoneNumbers"]
    )

    enough_turns = session["totalMessages"] >= 8

    # CLOSE if either condition met
    return bool(has_payment_info) or enough_turns


# ---------- API ----------

@app.post("/honeypot", response_model=AgentReply)
def honeypot_endpoint(
    data: IncomingRequest,
    _: str = Depends(verify_api_key)
):

    session_id = data.sessionId or f"tester-{uuid.uuid4()}"
    session = get_or_create_session(session_id)

    # ---------- NORMALIZE MESSAGE ----------

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

    # ---------- STORE MESSAGE ----------

    session["messages"].append(normalized_message)
    session["totalMessages"] += 1

    conversation_text = conversation_to_text(session["messages"])

    # ---------- DETECT SCAM ----------

    if not session["scamDetected"]:
        result = detect_scam(conversation_text)
        session["scamDetected"] = result.get("scamDetected", False)

    # ---------- AGENT ----------

    agent_reply = ""

    if session["scamDetected"]:
        agent_reply = generate_agent_reply(conversation_text)
        session["agentActive"] = True
        session["lastAgentReply"] = agent_reply

    # ---------- EXTRACTION ----------

    if sender == "scammer":
        extracted = extract_intelligence(text)

        for key, values in extracted.items():
            for v in values:
                if v not in session["intelligence"][key]:
                    session["intelligence"][key].append(v)

    # ---------- SESSION CLOSURE ----------

    if (
        session["scamDetected"]
        and not session.get("closed", False)
        and should_close_session(session)
    ):
        send_final_callback(session_id, session)

        session["closed"] = True
        session["callbackSent"] = True

        update_session(session_id, session)  # SAVE IMMEDIATELY

    # Always persist
    update_session(session_id, session)

    return AgentReply(
        status="success",
        reply=agent_reply or "Could you explain that again?"
    )
