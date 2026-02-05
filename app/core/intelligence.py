import re


# ==============================
# STRONG REGEX PATTERNS
# ==============================

# UPI (covers most real-world formats)
UPI_REGEX = re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b")

# URLs (safer than previous)
URL_REGEX = re.compile(
    r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"
)

# Indian phone numbers
PHONE_REGEX = re.compile(
    r"(?:\+91[-\s]?|0)?[6-9]\d{9}"
)

# Bank / card / long numeric identifiers
BANK_REGEX = re.compile(
    r"\b\d{10,18}\b"
)

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "blocked",
    "suspended",
    "immediately",
    "click",
    "payment",
    "transfer",
    "account",
    "upi",
    "otp",
    "kyc"
]


# ==============================
# TEXT CLEANING (VERY IMPORTANT)
# ==============================

def clean_scammer_text(text: str) -> str:
    """
    Removes LLM reasoning noise that evaluator simulators often leak.
    Makes extraction MUCH more reliable.
    """

    if not text:
        return ""

    noise_phrases = [
        "The user",
        "We need to",
        "The system",
        "instruction",
        "policy",
        "simulated",
        "role-play",
        "assistant should",
        "according to policy"
    ]

    # If reasoning text exists, try extracting quoted message
    if any(n in text for n in noise_phrases):
        quoted = re.findall(r'"([^"]+)"', text)

        if quoted:
            # Return longest quoted chunk (usually the scam message)
            return max(quoted, key=len)

    return text


# ==============================
# EXTRACTION ENGINE
# ==============================

def extract_intelligence(text: str) -> dict:

    # 🔥 ALWAYS CLEAN FIRST
    text = clean_scammer_text(text)

    if not text:
        return {
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "bankAccounts": [],
            "suspiciousKeywords": []
        }

    # ---------- PHONE ----------
    raw_phones = set(PHONE_REGEX.findall(text))

    phones = set()

    for p in raw_phones:
        digits = re.sub(r"\D", "", p)

        # Normalize to last 10 digits
        if len(digits) >= 10:
            phones.add(digits[-10:])

    # ---------- BANK ----------
    raw_numbers = set(BANK_REGEX.findall(text))

    banks = set()

    for num in raw_numbers:

        digits = re.sub(r"\D", "", num)

        # Skip if looks like phone
        if digits[-10:] in phones:
            continue

        # Ignore very repetitive garbage numbers
        if len(set(digits)) <= 2:
            continue

        banks.add(digits)

    # ---------- UPI ----------
    upis = set(UPI_REGEX.findall(text))

    # ---------- URL ----------
    urls = set(URL_REGEX.findall(text))

    # ---------- KEYWORDS ----------
    lowered = text.lower()

    keywords = {
        kw for kw in SUSPICIOUS_KEYWORDS
        if kw in lowered
    }

    # Return deduplicated intelligence
    return {
        "upiIds": list(sorted(upis)),
        "phishingLinks": list(sorted(urls)),
        "phoneNumbers": list(sorted(phones)),
        "bankAccounts": list(sorted(banks)),
        "suspiciousKeywords": list(sorted(keywords))
    }
