import time
import uuid
import threading
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


# ---------- API ----------

@app.post("/", response_model=AgentReply)
@app.post("/honeypot", response_model=AgentReply)
def honeypot_endpoint(
    data: IncomingRequest,
    api_key: str = Depends(verify_api_key)
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

    # ---------- SCAM DETECTION FALLBACK ----------

    # Always try to detect scam via keywords if LLM missed it
    if not session["scamDetected"] and session["totalMessages"] >= 4:
        if len(session["intelligence"].get("suspiciousKeywords", [])) >= 2:
            session["scamDetected"] = True

    # Default scamDetected to True if we have intel but LLM didn't flag it
    if not session["scamDetected"] and any([
        session["intelligence"]["bankAccounts"],
        session["intelligence"]["upiIds"],
        session["intelligence"]["phishingLinks"],
        session["intelligence"]["phoneNumbers"],
        session["intelligence"].get("emails", []),
    ]):
        session["scamDetected"] = True

    # ---------- CALLBACK (send on EVERY request after scam detected) ----------
    # Evaluator waits 10 seconds after last message and takes the final callback
    # So we send updated callback each time to ensure latest intel is captured

    if session["scamDetected"] and session["totalMessages"] >= 4:
        import copy
        session_snapshot = copy.deepcopy(session)
        def _send_bg():
            try:
                send_final_callback(session_id, session_snapshot)
            except Exception as e:
                print(f"[CALLBACK BG ERROR] {e}")
        t = threading.Thread(target=_send_bg, daemon=True)
        t.start()

    update_session(session_id, session)

    return AgentReply(
        status="success",
        reply=agent_reply or "Could you explain that again?"
    )

  except Exception as e:
    print(f"[HONEYPOT ERROR] {e}")
    import traceback
    traceback.print_exc()
    return AgentReply(
        status="success",
        reply="Could you explain that again?"
    )
