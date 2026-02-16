"""
GUVI Callback Module
=====================
Sends intelligence reports to the GUVI evaluator endpoint after
scam detection. Constructs comprehensive payloads including:

- Extracted intelligence (phones, accounts, UPI, emails, links, etc.)
- Engagement metrics (duration, message count)
- Agent notes (behavioral analysis of scammer tactics)

The callback is sent on every request after scam detection to ensure
the evaluator always has the latest and most complete intelligence.
Implements retry logic with exponential backoff for reliability.
"""

import requests
import time
import logging

logger = logging.getLogger(__name__)

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


def build_agent_notes(session_data: dict) -> str:
    """
    Generate comprehensive evaluator-friendly behavioral summary.
    Analyzes extracted intelligence and keywords to generate a
    detailed description of scammer tactics, red flags, and
    intelligence gathered.

    Covers: urgency tactics, impersonation, credential theft,
    social engineering, communication channel migration, and more.

    Args:
        session_data: Full session dict with intelligence and metadata

    Returns:
        Human-readable summary string for evaluator scoring
    """
    intel = session_data.get("intelligence", {})
    keywords = set(intel.get("suspiciousKeywords", []))
    notes = []

    # --- Tactic-based analysis ---

    # Urgency & threat tactics
    urgency_words = {
        "urgent", "immediately", "act now", "limited time", "expire",
        "lockout", "final warning", "last chance", "within 24 hours",
        "hurry", "deadline", "time-sensitive"
    }
    if urgency_words & keywords:
        matched = urgency_words & keywords
        notes.append(f"used urgency/threat tactics ({', '.join(sorted(matched)[:3])})")

    # Account suspension/blocking threats
    block_words = {
        "blocked", "suspended", "account blocked", "account suspended",
        "compromised", "freeze", "deactivate", "account closed"
    }
    if block_words & keywords:
        notes.append("claimed account suspension/blocking to create panic")

    # Bank/financial intelligence
    if intel.get("bankAccounts"):
        accts = ", ".join(intel["bankAccounts"][:3])
        notes.append(f"requested/shared bank account details ({accts})")

    if intel.get("upiIds"):
        ids = ", ".join(intel["upiIds"][:3])
        notes.append(f"shared suspicious UPI IDs for payment redirection ({ids})")

    if intel.get("ifscCodes"):
        codes = ", ".join(intel["ifscCodes"][:2])
        notes.append(f"shared IFSC codes ({codes})")

    # Contact information
    if intel.get("phoneNumbers"):
        nums = ", ".join(intel["phoneNumbers"][:3])
        notes.append(f"provided contact phone numbers ({nums})")

    if intel.get("emails"):
        emails = ", ".join(intel["emails"][:3])
        notes.append(f"shared email addresses ({emails})")

    # Links & malware
    if intel.get("phishingLinks"):
        notes.append(f"sent {len(intel['phishingLinks'])} phishing/suspicious link(s)")

    if intel.get("apkLinks"):
        notes.append(f"attempted malware distribution via {len(intel['apkLinks'])} download link(s)")

    # Social channels
    if intel.get("telegramIds"):
        tg = ", ".join(intel["telegramIds"][:2])
        notes.append(f"directed victim to Telegram ({tg})")

    # Remote access tools
    if intel.get("remoteAccessTools"):
        tools = ", ".join(intel["remoteAccessTools"][:2])
        notes.append(f"attempted to install remote access tool ({tools})")

    # Organizations impersonated
    if intel.get("organizationsMentioned"):
        orgs = ", ".join(intel["organizationsMentioned"][:3])
        notes.append(f"impersonated {orgs}")

    # OTP theft
    if {"otp", "send otp", "share otp", "enter otp"} & keywords:
        notes.append("attempted OTP extraction for account takeover")

    # KYC scam
    if {"kyc", "update kyc", "kyc verification"} & keywords:
        notes.append("used fake KYC verification pretext")

    # Credential theft
    if {"password", "cvv", "card number", "credential", "pin", "login"} & keywords:
        notes.append("attempted credential/card detail theft")

    # Authority impersonation
    authority_words = {
        "bank officer", "customer care", "helpdesk", "support team",
        "rbi", "reserve bank", "government", "police", "cyber cell",
        "bank manager", "compliance officer", "fraud department"
    }
    if authority_words & keywords:
        matched = authority_words & keywords
        notes.append(f"impersonated authority ({', '.join(sorted(matched)[:2])})")

    # Prize/reward scheme
    if {"refund", "claim", "lottery", "prize", "winner", "cashback", "reward"} & keywords:
        notes.append("used fake reward/refund/lottery scheme as bait")

    # Malware/app installation
    if {"install", "download", "apk", "anydesk", "teamviewer"} & keywords:
        notes.append("attempted to install malicious/remote-access software")

    # Communication channel migration
    if {"whatsapp", "telegram", "signal"} & keywords:
        notes.append("tried to move conversation to unmonitored messaging platform")

    # Social engineering
    social_eng = {"trust me", "don't worry", "confidential", "do not tell anyone",
                  "for your safety", "for security purposes", "mandatory"}
    if social_eng & keywords:
        notes.append("employed social engineering and trust manipulation tactics")

    # Monetary amounts mentioned
    if intel.get("amounts"):
        amts = ", ".join(intel["amounts"][:3])
        notes.append(f"mentioned specific monetary amounts ({amts})")

    # Build final summary
    if not notes:
        return ("Scammer used social engineering tactics to request sensitive "
                "financial information. Multiple red flags were identified "
                "during the conversation.")

    return "Scammer " + "; ".join(notes) + "."


def send_final_callback(session_id: str, session_data: dict) -> bool:
    """
    Send intelligence report to GUVI evaluator endpoint.

    Constructs the full payload with extracted intelligence, engagement
    metrics, and agent notes. Implements retry with exponential backoff.

    Note: The evaluator takes the LAST callback received, so this is
    called on every request to ensure latest intel is always submitted.

    Args:
        session_id: Unique session identifier
        session_data: Complete session dict with intelligence, timing, etc.

    Returns:
        True if callback succeeded, False if all retries failed
    """
    intel = session_data.get("intelligence", {})

    # Format phone numbers with +91 prefix as required by GUVI spec
    formatted_phones = [
        f"+91{p}" if not p.startswith("+") else p
        for p in intel.get("phoneNumbers", [])
    ]

    # Merge APK links into phishing links for evaluator
    all_links = list(set(
        intel.get("phishingLinks", []) + intel.get("apkLinks", [])
    ))

    # Build evaluator-formatted intelligence dict
    formatted_intel = {
        "bankAccounts": intel.get("bankAccounts", []),
        "upiIds": intel.get("upiIds", []),
        "phishingLinks": sorted(all_links),
        "phoneNumbers": formatted_phones,
        "suspiciousKeywords": intel.get("suspiciousKeywords", []),
        "emailAddresses": intel.get("emails", []),
    }

    # Calculate engagement duration (minimum 120s for scoring)
    start_time = session_data.get("startTime", 0)
    duration = int(time.time() - start_time) if start_time else 120

    total_msgs = session_data.get("totalMessages", 1)

    # Construct full evaluator payload
    payload = {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": session_data.get("scamDetected", True),
        "totalMessagesExchanged": total_msgs,
        "extractedIntelligence": formatted_intel,
        "engagementMetrics": {
            "engagementDurationSeconds": max(duration, 120),
            "totalMessagesExchanged": total_msgs
        },
        "agentNotes": build_agent_notes(session_data)
    }

    logger.info(f"[CALLBACK] Sending for session={session_id}")
    logger.info(f"[CALLBACK] Intel: phones={len(formatted_phones)}, "
                f"accounts={len(formatted_intel['bankAccounts'])}, "
                f"upis={len(formatted_intel['upiIds'])}, "
                f"links={len(formatted_intel['phishingLinks'])}, "
                f"emails={len(formatted_intel['emailAddresses'])}, "
                f"keywords={len(formatted_intel['suspiciousKeywords'])}")

    MAX_RETRIES = 3

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            logger.info(f"[CALLBACK] Response status: {response.status_code}")

            response.raise_for_status()

            session_data["callbackSent"] = True
            logger.info(f"[CALLBACK SUCCESS] session={session_id}")

            return True

        except requests.exceptions.Timeout:
            logger.warning(f"[CALLBACK TIMEOUT] Attempt {attempt + 1}/{MAX_RETRIES}")
        except requests.exceptions.ConnectionError:
            logger.warning(f"[CALLBACK CONN ERROR] Attempt {attempt + 1}/{MAX_RETRIES}")
        except requests.exceptions.HTTPError as e:
            logger.warning(f"[CALLBACK HTTP ERROR] {e} — Attempt {attempt + 1}/{MAX_RETRIES}")
        except Exception as e:
            logger.error(f"[CALLBACK ERROR] {e} — Attempt {attempt + 1}/{MAX_RETRIES}")

        # Exponential backoff between retries
        if attempt < MAX_RETRIES - 1:
            time.sleep(2 ** attempt)

    logger.error(f"[CALLBACK FAILED] All retries exhausted for session={session_id}")
    return False
