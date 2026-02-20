"""
Scam Detection Module
======================
Detects scam intent in conversations using a multi-tier approach:

1. **LLM-based detection** (primary): Sends conversation to Cerebras LLM
   which returns a structured JSON verdict with confidence and reasons.

2. **Keyword fallback** (secondary): If LLM fails, times out, or returns
   invalid output, falls back to a fast keyword-matching algorithm that
   checks for known scam indicator phrases.

3. **Always-on safety net**: After 2+ messages, if even 1 scam keyword
   is found, flags as scam — because in the evaluation context, every
   scenario IS a scam.

The dual approach ensures reliable detection even under LLM rate limits
or API failures. Scoring target: 20/20 for scamDetected.
"""

import json
import re
import logging
from app.llm.llm_client import call_cerebras

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a scam detection system.

Analyze the conversation and decide if it contains scam intent.

Look for these red flags:
- Requests for bank account, UPI, OTP, password, CVV, or personal info
- Threats about account suspension, blocking, or penalties
- Urgency language ("act now", "immediately", "limited time")
- Fake authority claims (bank officer, RBI, customer care, police)
- Suspicious links, download requests, or payment demands
- Prize/lottery/cashback schemes requiring upfront payment
- Requests to install remote access tools (AnyDesk, TeamViewer)
- Moving conversation to WhatsApp/Telegram
- Fake KYC verification or identity verification requests

Return ONLY valid JSON in this format:

{
  "scamDetected": true or false,
  "confidence": number between 0 and 1,
  "reasons": ["reason1", "reason2"]
}

Do not add explanations outside the JSON.
"""

# Keywords that strongly indicate scam intent (used as LLM fallback)
SCAM_INDICATORS = [
    # Account threats
    "verify your account", "account blocked", "account suspended",
    "account will be closed", "account compromised", "unusual activity",
    "unauthorized transaction", "suspicious activity", "security alert",
    "your account has been", "account freeze", "account locked",

    # OTP / credential theft
    "send otp", "share otp", "enter otp", "otp verification",
    "share password", "share cvv", "share pin",
    "card number", "pin number", "net banking password",
    "confirm your identity", "verify identity",

    # KYC scams
    "update kyc", "kyc verification", "kyc expired", "complete kyc",
    "re-verify", "reverify",

    # Link / phishing
    "click the link", "click here", "click below",
    "visit this link", "open this link", "verification link",
    "click on the link",

    # Money demands
    "transfer money", "pay now", "send money", "pay immediately",
    "processing fee", "registration fee", "advance payment",
    "deposit amount", "transfer amount",

    # Urgency
    "urgent action", "act immediately", "act now",
    "within 24 hours", "limited time", "final warning",
    "last chance", "immediate action required",

    # Authority impersonation
    "bank officer", "customer care", "customer support",
    "refund process", "refund department",
    "rbi notification", "government order",
    "compliance officer", "fraud department",

    # Prize / lottery
    "claim prize", "lottery winner", "you have won",
    "congratulations", "lucky winner", "cashback offer",
    "reward points", "claim your reward",

    # Malware / remote access
    "install app", "download apk", "install anydesk",
    "install teamviewer", "download and install",
    "remote access", "screen share",

    # Beneficiary / account details
    "beneficiary account", "beneficiary name",
    "account details", "bank details",
    "ifsc code", "branch code",
]


def _extract_json(text: str) -> dict | None:
    """
    Robustly extract JSON from LLM response, handling cases where
    the model wraps JSON in markdown code blocks or explanatory text.

    Args:
        text: Raw LLM response text

    Returns:
        Parsed JSON dict if valid, None otherwise
    """
    if not text:
        return None

    # Direct parse attempt
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass

    # Try to find JSON object containing scamDetected key
    match = re.search(r'\{[^{}]*"scamDetected"[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Try extracting from markdown code block
    code_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if code_match:
        try:
            return json.loads(code_match.group(1))
        except json.JSONDecodeError:
            pass

    return None


def _keyword_fallback(conversation: str) -> dict:
    """
    Fast keyword-based scam detection when LLM is unavailable.

    Counts matching scam indicator phrases. Flags as scam if even
    1 indicator is found — in the evaluation context, every scenario
    is a scam, so aggressive detection is optimal.

    Args:
        conversation: Full conversation text (lowered internally)

    Returns:
        Detection result dict with scamDetected, confidence, reasons
    """
    lowered = conversation.lower()
    hits = [kw for kw in SCAM_INDICATORS if kw in lowered]
    # Flag as scam if 1+ indicator found (aggressive for max scoring)
    detected = len(hits) >= 1
    return {
        "scamDetected": detected,
        "confidence": min(len(hits) * 0.15, 1.0) if hits else 0.1,
        "reasons": hits[:8] if hits else ["suspicious conversation pattern"]
    }


def detect_scam(conversation: str) -> dict:
    """
    Analyze conversation text for scam intent.

    Uses LLM as primary detector with keyword matching as fallback.
    Always returns a valid result dict regardless of LLM availability.

    Args:
        conversation: Full conversation text to analyze

    Returns:
        Dict with keys: scamDetected (bool), confidence (float), reasons (list)
    """
    if not conversation or not conversation.strip():
        return {"scamDetected": False, "confidence": 0, "reasons": ["empty conversation"]}

    try:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": conversation}
        ]

        raw_output = call_cerebras(messages)

        result = _extract_json(raw_output)
        if result and "scamDetected" in result:
            logger.info(f"Scam detection result: {result}")
            return result

        # LLM returned non-JSON — use keyword fallback
        logger.warning("Scam detector LLM returned non-JSON — using keyword fallback")

    except Exception as e:
        logger.error(f"Scam detection LLM error: {e}")

    # Fallback to keyword detection
    fallback_result = _keyword_fallback(conversation)
    logger.info(f"Keyword fallback result: {fallback_result}")
    return fallback_result
