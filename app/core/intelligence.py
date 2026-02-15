import re


# ==============================
# REGEX PATTERNS
# ==============================

# UPI: user@handler (exclude common email domains)
EMAIL_DOMAINS = {"gmail", "yahoo", "hotmail", "outlook", "protonmail", "mail", "rediffmail", "live", "icloud", "aol"}

UPI_HANDLERS = {
    "paytm", "ybl", "upi", "oksbi", "okaxis", "okicici", "okhdfcbank",
    "axl", "ibl", "sbi", "icici", "hdfcbank", "apl", "ratn",
    "unionbank", "boi", "citi", "pnb", "kotak", "indus", "federal",
    "freecharge", "phonepe", "gpay", "amazonpay", "airtel", "jio",
    "fakebank", "bank", "pay", "wallet"
}

UPI_REGEX = re.compile(
    r"[a-zA-Z0-9._-]{2,}@[a-zA-Z0-9._-]{2,}"
)

# Email addresses
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# Catch http, https, www, and suspicious short URLs
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s\"\'>]+",
    re.IGNORECASE
)

# APK / download links
APK_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s]*\.(?:apk|exe|msi|dmg|zip|rar)",
    re.IGNORECASE
)

# Indian phone numbers - must NOT be inside longer digit sequences
PHONE_REGEX = re.compile(
    r"(?<!\d)(?:\+91[\s-]?|91[\s-]?|0)?([6-9]\d[\s-]?\d{4}[\s-]?\d{4})(?!\d)"
)

# Bank / card / long identifiers (10-18 digits, may have spaces/dashes)
BANK_REGEX = re.compile(
    r"\b(\d[\d\s-]{9,20}\d)\b"
)

# IFSC Code pattern
IFSC_REGEX = re.compile(
    r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
)

# Telegram usernames
TELEGRAM_REGEX = re.compile(
    r"(?:@|t\.me/|telegram\.me/)([a-zA-Z][a-zA-Z0-9_]{4,})"
)

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "verify now", "blocked", "suspended",
    "immediately", "click", "payment", "transfer", "account",
    "account blocked", "account suspended", "upi", "otp", "kyc",
    "fraud", "pin", "link", "expire", "penalty", "refund",
    "claim", "lottery", "prize", "winner", "offer", "limited time",
    "act now", "share", "credential", "password", "cvv", "card number",
    "rbi", "reserve bank", "aadhaar", "pan card", "ifsc",
    "compromised", "unauthorized", "suspicious", "lockout", "freeze",
    "beneficiary", "confirmation code", "security alert", "update kyc",
    "reactivate", "deactivate", "verify identity", "send otp",
    "bank officer", "customer care", "helpdesk", "support team",
    "whatsapp", "telegram", "install", "download", "apk"
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
# CLASSIFICATION HELPERS
# ==============================

def is_upi_id(value: str) -> bool:
    """Check if an @-address is a UPI ID (not an email)."""
    parts = value.split("@")
    if len(parts) != 2:
        return False
    domain = parts[1].lower().rstrip(".")
    # If domain matches a known UPI handler
    if domain in UPI_HANDLERS:
        return True
    # If domain does NOT have a TLD (no dot), likely UPI
    if "." not in domain:
        return True
    # If domain matches an email domain
    domain_base = domain.split(".")[0]
    if domain_base in EMAIL_DOMAINS:
        return False
    return False


def is_email(value: str) -> bool:
    """Check if an @-address is an email."""
    parts = value.split("@")
    if len(parts) != 2:
        return False
    domain = parts[1].lower()
    # Must have a TLD
    return "." in domain


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
        if len(digits) == 10:
            phones.add(digits)

    # ---------- ALL @-addresses ----------
    at_addresses = set(UPI_REGEX.findall(text))

    upis = set()
    emails = set()

    for addr in at_addresses:
        addr_lower = addr.lower()
        if is_upi_id(addr_lower):
            upis.add(addr_lower)
        elif is_email(addr_lower):
            emails.add(addr_lower)

    # Also catch emails that UPI regex might miss
    for em in EMAIL_REGEX.findall(text):
        em_lower = em.lower()
        if is_email(em_lower) and em_lower not in upis:
            emails.add(em_lower)

    # ---------- BANK ----------
    raw_numbers = BANK_REGEX.findall(text)

    banks = set()
    for num in raw_numbers:
        digits = re.sub(r"\D", "", num)

        # Must be 10-18 digits
        if len(digits) < 10 or len(digits) > 18:
            continue

        # Skip if same as phone
        if digits in phones:
            continue

        # Skip if it's 91 + phone number (country code prefix)
        if len(digits) >= 12 and digits[:2] == "91" and digits[2:] in phones:
            continue

        # Skip if it CONTAINS a known phone number as substring
        is_phone_variant = False
        for ph in phones:
            if ph in digits:
                is_phone_variant = True
                break
        if is_phone_variant and len(digits) <= 12:
            continue

        # Ignore garbage numbers (all same digit or too few unique)
        if len(set(digits)) <= 2:
            continue

        banks.add(digits)

    # ---------- URL ----------
    urls = set(u.lower().rstrip(".,;:)") for u in URL_REGEX.findall(text))

    # ---------- APK ----------
    apks = set(u.lower().rstrip(".,;:)") for u in APK_REGEX.findall(text))
    urls = urls | apks  # merge APK links into phishing links

    # ---------- IFSC ----------
    ifscs = set(IFSC_REGEX.findall(text))

    # ---------- TELEGRAM ----------
    telegrams = set(f"@{t}" for t in TELEGRAM_REGEX.findall(text))

    # ---------- KEYWORDS ----------
    lowered = text.lower()
    keywords = {kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered}

    return {
        "upiIds": sorted(upis),
        "phishingLinks": sorted(urls),
        "phoneNumbers": sorted(phones),
        "bankAccounts": sorted(banks),
        "suspiciousKeywords": sorted(keywords),
        "emails": sorted(emails),
        "ifscCodes": sorted(ifscs),
        "telegramIds": sorted(telegrams),
        "apkLinks": sorted(apks)
    }


def empty_intel():
    return {
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "bankAccounts": [],
        "suspiciousKeywords": [],
        "emails": [],
        "ifscCodes": [],
        "telegramIds": [],
        "apkLinks": []
    }
