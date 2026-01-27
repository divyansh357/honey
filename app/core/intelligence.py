# app/core/intelligence.py

import re

# ---------- REGEX PATTERNS ----------

UPI_REGEX = re.compile(r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s]+")
PHONE_REGEX = re.compile(r"\b(?:\+?91)?[6-9]\d{9}\b")
BANK_REGEX = re.compile(r"\b\d{9,18}\b")

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
    "upi"
]


# ---------- EXTRACTION FUNCTION ----------

def extract_intelligence(text: str) -> dict:
    # Find phone numbers (with or without country code)
    raw_phones = set(PHONE_REGEX.findall(text))

    # Normalize phones: keep only last 10 digits
    phones = {p[-10:] for p in raw_phones if len(p) >= 10}

    # Find all long numbers
    raw_banks = set(BANK_REGEX.findall(text))

    # Exclude numbers that look like phone numbers
    banks = set()
    for b in raw_banks:
        # If last 10 digits look like a phone number, skip
        if b[-10:] in phones:
            continue
        banks.add(b)

    return {
        "upiIds": list(set(UPI_REGEX.findall(text))),
        "phishingLinks": list(set(URL_REGEX.findall(text))),
        "phoneNumbers": list(phones),
        "bankAccounts": list(banks),
        "suspiciousKeywords": list(
            {kw for kw in SUSPICIOUS_KEYWORDS if kw in text.lower()}
        )
    }

