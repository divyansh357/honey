import re


# ==============================
# STRONG REGEX PATTERNS
# ==============================

# Covers most real-world UPI formats
UPI_REGEX = re.compile(
    r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z0-9.-]{2,}\b"
)

# Catch http, https, AND www
URL_REGEX = re.compile(
    r"\b(?:https?://|www\.)[^\s]+\b"
)

# STRICT Indian phone detection
PHONE_REGEX = re.compile(
    r"\b(?:\+91[-\s]?|0)?([6-9]\d{9})\b"
)

# Bank / card / long identifiers
BANK_REGEX = re.compile(
    r"\b\d{10,18}\b"
)

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "verify now",
    "blocked",
    "suspended",
    "immediately",
    "click",
    "payment",
    "transfer",
    "account",
    "account blocked",
    "account suspended",
    "upi",
    "otp",
    "kyc",
    "fraud",
    "pin",
    "link",
    "expire",
    "penalty",
    "refund",
    "claim",
    "lottery",
    "prize",
    "winner",
    "offer",
    "limited time",
    "act now",
    "share",
    "credential",
    "password",
    "cvv",
    "card number"
]


# ==============================
# TEXT CLEANING
# ==============================

def clean_scammer_text(text: str) -> str:

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

    if any(n in text for n in noise_phrases):

        quoted = re.findall(r'"([^"]+)"', text)

        if quoted:
            return max(quoted, key=len)

    return text


# ==============================
# EXTRACTION ENGINE
# ==============================

def extract_intelligence(text: str) -> dict:

    text = clean_scammer_text(text)

    if not text:
        return empty_intel()

    # ---------- PHONE ----------
    raw_phones = PHONE_REGEX.findall(text)

    phones = set()

    for p in raw_phones:

        digits = re.sub(r"\D", "", p)

        # STRICT: must be EXACTLY 10
        if len(digits) == 10:
            phones.add(digits)

    # ---------- BANK ----------
    raw_numbers = set(BANK_REGEX.findall(text))

    banks = set()

    for num in raw_numbers:

        digits = re.sub(r"\D", "", num)

        # Skip if same as phone
        if digits in phones:
            continue

        # Ignore garbage numbers
        if len(set(digits)) <= 2:
            continue

        banks.add(digits)

    # ---------- UPI ----------
    upis = set(u.lower() for u in UPI_REGEX.findall(text))

    # ---------- URL ----------
    urls = set(u.lower() for u in URL_REGEX.findall(text))

    # ---------- KEYWORDS ----------
    lowered = text.lower()

    keywords = {
        kw for kw in SUSPICIOUS_KEYWORDS
        if kw in lowered
    }

    return {
        "upiIds": list(sorted(upis)),
        "phishingLinks": list(sorted(urls)),
        "phoneNumbers": list(sorted(phones)),
        "bankAccounts": list(sorted(banks)),
        "suspiciousKeywords": list(sorted(keywords))
    }


def empty_intel():
    return {
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "bankAccounts": [],
        "suspiciousKeywords": []
    }
