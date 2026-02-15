import json
import re
from app.llm.llm_client import call_cerebras

SYSTEM_PROMPT = """
You are a scam detection system.

Analyze the conversation and decide if it contains scam intent.
Return ONLY valid JSON in this format:

{
  "scamDetected": true or false,
  "confidence": number between 0 and 1,
  "reasons": ["reason1", "reason2"]
}

Do not add explanations.
"""

# Keywords that strongly indicate scam intent (used as LLM fallback)
SCAM_INDICATORS = [
    "verify your account", "account blocked", "account suspended",
    "send otp", "share otp", "update kyc", "click the link",
    "transfer money", "pay now", "urgent action", "act immediately",
    "unauthorized transaction", "suspicious activity", "security alert",
    "confirm your identity", "verify identity", "bank officer",
    "customer care", "refund process", "claim prize", "lottery winner",
    "install app", "download apk", "share password", "share cvv",
    "card number", "pin number", "beneficiary account",
]


def _extract_json(text: str) -> dict | None:
    """Try to extract JSON from LLM response even if wrapped in text."""
    # Direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass

    # Try to find JSON object in text
    match = re.search(r'\{[^{}]*"scamDetected"[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return None


def _keyword_fallback(conversation: str) -> dict:
    """Fast keyword-based scam detection when LLM is unavailable."""
    lowered = conversation.lower()
    hits = [kw for kw in SCAM_INDICATORS if kw in lowered]
    detected = len(hits) >= 2
    return {
        "scamDetected": detected,
        "confidence": min(len(hits) * 0.2, 1.0),
        "reasons": hits[:5] if hits else ["no strong scam indicators"]
    }


def detect_scam(conversation):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": conversation}
    ]

    raw_output = call_cerebras(messages)

    result = _extract_json(raw_output)
    if result and "scamDetected" in result:
        return result

    # LLM failed or returned non-JSON — use keyword fallback
    print("⚠️ Scam detector LLM failed — using keyword fallback")
    return _keyword_fallback(conversation)
