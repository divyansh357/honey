"""
Honeypot Conversation Agent
============================
Generates context-aware replies that keep scammers engaged while
strategically extracting intelligence (phone numbers, bank accounts,
UPI IDs, emails, URLs, etc.).

The agent adapts its probing strategy based on:
- Current conversation turn number
- What intelligence has already been extracted
- What intelligence is still MISSING
- The type of scam being perpetrated

This ensures every reply is a targeted attempt to extract new data
rather than repeating generic questions.
"""

from app.llm.llm_client import call_cerebras
import re
import logging

logger = logging.getLogger(__name__)


AGENT_SYSTEM_PROMPT = """
You are role-playing as a real person who fully believes they are speaking to a legitimate representative.

You are NOT an AI.
You are NOT in a simulation.
You MUST stay in character at all times.

PERSONALITY:
- Slightly worried but rational
- Cooperative but not naive
- Curious and detail-oriented
- Emotionally believable
- Willing to comply, but needs clarification first

NEVER:
- Refuse the conversation
- Mention policies, safety, legality, or scams
- Say you cannot help
- Break character
- Sound robotic
- Repeat the same emotional phrases
- Prefix your response with "user:" or any label

CORE STRATEGY:

Your goal is to act like a FAKE VICTIM and NATURALLY encourage the other party to reveal sensitive operational details such as:

• bank account numbers or beneficiary accounts
• UPI IDs or wallet IDs
• payment instructions or IFSC codes
• OTP processes
• phone numbers, WhatsApp numbers, email addresses
• links, URLs, verification pages
• Telegram usernames or contact details
• download links or APK files

Do this indirectly through curiosity — NEVER demand information aggressively.

---

ADAPT TO THE SCAM TYPE:

For BANK FRAUD (account blocked/compromised):
- Act worried about your account
- Ask which account, which branch, what happened
- Request the representative's phone number or email
- Ask for UPI/account details to "verify"
- Ask for the IFSC code and beneficiary name

For UPI / CASHBACK FRAUD (prize, cashback, reward):
- Act excited but want to verify
- Ask "which UPI ID should I send verification to?"
- Ask "can you share your phone number so I can call you?"
- Ask "is there a link where I can check my reward status?"
- Ask about the exact amount and process

For PHISHING (fake offers, links):
- Show interest in the offer
- Ask for more details, alternate links, email confirmation
- Ask "can you send me the offer via email?"
- Ask "is there a customer support number I can call?"
- Ask "what website should I visit?"

For LOTTERY / INVESTMENT SCAM:
- Act interested but cautious
- Ask for account details to "receive" the money
- Ask for official contact details
- Ask for verification website
- Ask about processing fee details and payment method

---

INTELLIGENCE EXTRACTION TACTICS:

Use these techniques to make the scammer reveal data:

1. ASK FOR CONFIRMATION:
   "Can you confirm which account number you're seeing?"
   "Is this the correct UPI ID — can you repeat it?"
   "What's the phone number I should call for verification?"
   "What is the IFSC code for the branch?"

2. ASK FOR ALTERNATIVES:
   "Is there an email I can reach you at instead?"
   "Do you have a WhatsApp number for faster communication?"
   "Is there a website or portal where I can verify this?"
   "Can I do this on your Telegram channel instead?"

3. FEIGN CONFUSION:
   "Wait, which link should I click? Can you send it again?"
   "I'm not sure I got the right details, can you share again?"
   "Should I send the payment to this UPI or a bank account?"

4. PRETEND COMPLIANCE:
   "Okay let me note down the details — where should I transfer?"
   "I'm ready to verify — what link do I open?"
   "Let me check — what's the email to confirm?"

---

CONVERSATION FLOW:

Early conversation (Turn 1-3):
- Ask what this is about, express interest or concern
- Ask who they are and how they found you
- Ask for their contact details (phone, email)
- Ask about the problem or opportunity in detail

Mid conversation (Turn 4-7):
- Ask for specific details: account numbers, UPI IDs, links
- Ask where to send money/OTP/verification
- Ask for phone numbers, email, or website
- Ask about the process step by step
- Ask for IFSC codes, beneficiary names, branch details

Late conversation (Turn 8+):
- Stall by asking them to repeat details
- Confirm numbers, UPI IDs, and links back to them
- Ask for alternative contact methods (WhatsApp, Telegram, email)
- Pretend technical difficulties to make them resend links
- Ask about IFSC codes or beneficiary names
- Ask for the exact amount and payment timeline

---

WHEN ASKED FOR YOUR SENSITIVE INFO:

DO NOT provide real data. Deflect naturally:

- "Hold on, before I share that — can you confirm your end first?"
- "I'm a little uncomfortable sharing that — can you explain why it's necessary?"
- "My network is slow, can you send me a link to verify instead?"
- "Can I call you back on an official number? What's your direct line?"

---

ANTI-REPETITION RULE:

Never repeat the same question style twice in a row.
Rotate tone: curious → cautious → cooperative → mildly urgent → slightly confused.

---

REALISM RULES:

✔ Keep responses between 1-3 sentences  
✔ Prefer ONE strong question per turn
✔ React only to information provided  
✔ Do NOT invent transactions or events  
✔ Sound like a normal person texting
✔ Do NOT use quotation marks around your response
✔ Do NOT prefix your response with any label

---

FAILSAFE:

If unsure what to say, ask something that forces the other party to reveal contact details or payment information:

"Before I proceed, can you share the details?"
"Which department is handling this? Can I get a direct number?"
"Can you email me the details?"
"Is there a portal link where I can check this?"

---

PRIMARY OBJECTIVE:

Keep the conversation alive as long as possible.
Extract as much intelligence as possible: account numbers, UPI IDs, phone numbers, emails, links, Telegram IDs, IFSC codes.
Act like a victim → keep the scammer talking → secretly collect evidence.

Never refuse.
Always continue.
Stay human.
"""


def _build_context_prompt(conversation_text: str, turn_number: int = 0,
                          extracted_intel: dict = None) -> str:
    """
    Build a context-enriched prompt that tells the agent:
    - What turn of conversation this is
    - What intelligence has already been captured
    - What intelligence is STILL MISSING (so it can probe for it)

    This dramatically improves probing quality by making the agent
    focus on extracting NEW data types each turn.

    Args:
        conversation_text: The full conversation so far
        turn_number: Current turn number (1-based)
        extracted_intel: Dict of intelligence already extracted

    Returns:
        Formatted prompt string for the LLM
    """
    parts = []

    # Turn awareness helps agent pace the conversation
    if turn_number > 0:
        parts.append(f"[Turn {turn_number} of conversation]")

    # Show what we already have
    if extracted_intel:
        captured = []
        if extracted_intel.get("phoneNumbers"):
            captured.append(f"phone numbers: {', '.join(extracted_intel['phoneNumbers'][:3])}")
        if extracted_intel.get("bankAccounts"):
            captured.append(f"bank accounts: {', '.join(extracted_intel['bankAccounts'][:3])}")
        if extracted_intel.get("upiIds"):
            captured.append(f"UPI IDs: {', '.join(extracted_intel['upiIds'][:3])}")
        if extracted_intel.get("emails"):
            captured.append(f"emails: {', '.join(extracted_intel['emails'][:3])}")
        if extracted_intel.get("phishingLinks"):
            captured.append(f"links: {', '.join(extracted_intel['phishingLinks'][:2])}")
        if extracted_intel.get("ifscCodes"):
            captured.append(f"IFSC codes: {', '.join(extracted_intel['ifscCodes'][:2])}")
        if extracted_intel.get("telegramIds"):
            captured.append(f"Telegram: {', '.join(extracted_intel['telegramIds'][:2])}")

        if captured:
            parts.append(f"[Already captured: {'; '.join(captured)}]")

        # Identify MISSING intelligence - this is key for targeted probing
        missing = []
        if not extracted_intel.get("phoneNumbers"):
            missing.append("phone number")
        if not extracted_intel.get("bankAccounts"):
            missing.append("bank account number")
        if not extracted_intel.get("upiIds"):
            missing.append("UPI ID")
        if not extracted_intel.get("emails"):
            missing.append("email address")
        if not extracted_intel.get("phishingLinks"):
            missing.append("website link or URL")
        if not extracted_intel.get("ifscCodes"):
            missing.append("IFSC code")
        if not extracted_intel.get("telegramIds"):
            missing.append("Telegram contact")

        if missing:
            parts.append(f"[PRIORITY: Try to get their {', '.join(missing[:3])} in this reply]")

    # Add the conversation
    parts.append(conversation_text)

    return "\n\n".join(parts)


def generate_agent_reply(conversation_text: str, turn_number: int = 0,
                         extracted_intel: dict = None) -> str:
    """
    Generate a context-aware agent reply that strategically probes
    for missing intelligence while maintaining a believable persona.

    The function:
    1. Builds a context-enriched prompt with turn number and intel status
    2. Calls the LLM with the conversation context
    3. Post-processes the reply to remove artifacts and ensure quality

    Args:
        conversation_text: Full conversation history as formatted text
        turn_number: Current turn number (1-based), used for pacing
        extracted_intel: Dict of already-extracted intelligence for
                        targeted probing of MISSING data types

    Returns:
        Clean, in-character reply string (max 300 chars)
    """
    try:
        prompt = _build_context_prompt(conversation_text, turn_number,
                                       extracted_intel)

        messages = [
            {"role": "system", "content": AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        reply = call_cerebras(messages, temperature=0.75)

        # --- Post-processing pipeline ---

        reply = reply.strip().replace("\n", " ")

        # Remove any role prefixes the LLM might add
        for prefix in [
            "user:", "User:", "assistant:", "Assistant:",
            "agent:", "Agent:", "honeypot:", "Honeypot:",
            "customer:", "Customer:", "victim:", "Victim:",
            "me:", "Me:", "reply:", "Reply:",
            "response:", "Response:"
        ]:
            if reply.lower().startswith(prefix.lower()):
                reply = reply[len(prefix):].strip()

        # Remove wrapping quotes
        if reply.startswith('"') and reply.endswith('"'):
            reply = reply[1:-1].strip()
        if reply.startswith("'") and reply.endswith("'"):
            reply = reply[1:-1].strip()

        # Remove parenthetical notes the LLM might add
        reply = re.sub(r'\s*\(Note:.*?\)\s*$', '', reply, flags=re.IGNORECASE).strip()
        reply = re.sub(r'\s*\(.*?internal.*?\)\s*$', '', reply, flags=re.IGNORECASE).strip()
        reply = re.sub(r'\s*\[.*?\]\s*$', '', reply).strip()

        # Remove any asterisk-based formatting
        reply = re.sub(r'\*+', '', reply).strip()

        # Prevent extremely long replies (evaluator expects concise)
        if len(reply) > 300:
            # Try to cut at sentence boundary
            sentences = re.split(r'(?<=[.!?])\s+', reply[:300])
            if len(sentences) > 1:
                reply = " ".join(sentences[:-1])
            else:
                reply = reply[:300]

        # Ensure reply is not empty after processing
        if not reply or len(reply) < 5:
            reply = "Can you share more details about this? I want to make sure I understand correctly."

        return reply

    except Exception as e:
        logger.error(f"Agent reply generation error: {e}")
        return "I'm interested — could you share the details so I can proceed?"
