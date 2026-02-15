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


# ---------- HEALTH CHECK ----------

@app.get("/")
def health_check():
    return {"status": "running", "service": "Agentic HoneyPot API"}


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

    intel_categories_found = sum([
        bool(intel["bankAccounts"]),
        bool(intel["upiIds"]),
        bool(intel["phishingLinks"]),
        bool(intel["phoneNumbers"]),
        bool(intel.get("emails", [])),
    ])

    enough_turns = session["totalMessages"] >= 14

    # Require BOTH: enough conversation depth AND some intelligence
    # OR very high message count (platform might stop sending)
    rich_intel = intel_categories_found >= 2

    return (enough_turns and rich_intel) or session["totalMessages"] >= 20


# ---------- API ----------

@app.post("/", response_model=AgentReply)
@app.post("/honeypot", response_model=AgentReply)
def honeypot_endpoint(
    data: IncomingRequest,
    _: str = Depends(verify_api_key)
):
  try:
    session_id = data.sessionId or f"tester-{uuid.uuid4()}"
    session = get_or_create_session(session_id)

    # ---------- REBUILD SESSION FROM EVALUATOR HISTORY ----------

    rebuilt_messages = []

    # Add previous conversation history if provided
    if isinstance(data.conversationHistory, list):
        for msg in data.conversationHistory:
            if isinstance(msg, dict):
                rebuilt_messages.append({
                    "sender": msg.get("sender", "unknown"),
                    "text": msg.get("text", ""),
                    "timestamp": msg.get("timestamp")
                })

    # Add current incoming message
    if isinstance(data.message, dict):
        rebuilt_messages.append({
            "sender": data.message.get("sender", "scammer"),
            "text": data.message.get("text", ""),
            "timestamp": data.message.get("timestamp")
        })
    else:
        rebuilt_messages.append({
            "sender": "scammer",
            "text": str(data.message),
            "timestamp": None
        })

    # Replace session message history with evaluator truth
    session["messages"] = rebuilt_messages
    session["totalMessages"] = len(rebuilt_messages) + 1  # +1 for agent reply

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
    else:
        # Still respond naturally even before scam is confirmed
        agent_reply = generate_agent_reply(conversation_text)

    # ---------- EXTRACTION ----------

    # Extract from ALL scammer messages in conversation (not just latest)
    # This ensures nothing is missed even if previous extraction was partial
    session["intelligence"] = {
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

    for msg in rebuilt_messages:
        if msg.get("sender") == "scammer":
            extracted = extract_intelligence(msg["text"])
            for key, values in extracted.items():
                for v in values:
                    if v not in session["intelligence"].get(key, []):
                        if key not in session["intelligence"]:
                            session["intelligence"][key] = []
                        session["intelligence"][key].append(v)

    # ---------- SESSION CLOSURE (mandatory callback) ----------

    if (
        session["scamDetected"]
        and not session.get("closed", False)
        and should_close_session(session)
    ):
        # Synchronous callback — mandatory for GUVI scoring
        success = send_final_callback(session_id, session)
        if success:
            session["closed"] = True
            session["callbackSent"] = True

    update_session(session_id, session)

    return AgentReply(
        status="success",
        reply=agent_reply or "Could you explain that again?"
    )

  except Exception as e:
    print(f"[HONEYPOT ERROR] {e}")
    return AgentReply(
        status="error",
        reply="Could you explain that again?"
    )
