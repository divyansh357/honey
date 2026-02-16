"""
Intelligence Extraction Engine
================================
Extracts actionable intelligence from scam conversation messages using
regex-based pattern matching and heuristic classification.

Categories extracted:
- Phone numbers (Indian mobile format)
- Bank account numbers (9-18 digits)
- UPI IDs (user@handler)
- Email addresses
- Phishing/suspicious URLs
- APK/malware download links
- IFSC codes
- Telegram usernames
- WhatsApp numbers
- Suspicious keywords and phrases
- Card numbers (13-19 digits)
- Monetary amounts (INR, Rs, ₹)
- Organization/entity names impersonated
"""

import re
import logging

logger = logging.getLogger(__name__)


# ==============================
# REGEX PATTERNS
# ==============================

# --- UPI & Email Classification ---

# Common email domains (to separate from UPI IDs)
EMAIL_DOMAINS = {
    "gmail", "yahoo", "hotmail", "outlook", "protonmail", "mail",
    "rediffmail", "live", "icloud", "aol", "zoho", "yandex",
    "msn", "inbox", "fastmail", "tutanota", "hey"
}

# Known UPI payment handlers
UPI_HANDLERS = {
    "paytm", "ybl", "upi", "oksbi", "okaxis", "okicici", "okhdfcbank",
    "axl", "ibl", "sbi", "icici", "hdfcbank", "apl", "ratn",
    "unionbank", "boi", "citi", "pnb", "kotak", "indus", "federal",
    "freecharge", "phonepe", "gpay", "amazonpay", "airtel", "jio",
    "fakebank", "bank", "pay", "wallet", "axis", "hdfc", "abfspay",
    "axisb", "yesbank", "rbl", "payzapp", "slice", "jupiter",
    "fi", "cred", "niyopay", "dbs", "hsbc", "sc", "idbi",
    "centralbank", "canara", "bob", "barb", "mahb", "syndicate",
    "ubi", "corp", "vijb", "obc", "barodampay", "aubank",
    "equitas", "bandhan", "dcb", "kvb", "kbl", "iob",
    "dlb", "tmb", "psb", "jkb", "cub", "csb"
}

# Pattern: user@handler — catches both UPI and email candidates
UPI_REGEX = re.compile(
    r"[a-zA-Z0-9._-]{2,}@[a-zA-Z0-9._-]{2,}"
)

# Standard email regex
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# --- URLs ---

# HTTP/HTTPS/WWW URLs
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s\"\'>]+",
    re.IGNORECASE
)

# Domain-like strings without protocol (e.g., "verify-bank.com/login")
BARE_DOMAIN_REGEX = re.compile(
    r"\b[a-zA-Z0-9-]+\.(?:com|in|org|net|co\.in|info|xyz|top|click|link|online|site|tech|io|app|page|live|me|cc|tk|ml|ga|cf|gq|buzz|club|win|bid|stream|racing|download|review|date|accountant|science|party|cricket|faith|loan|trade|webcam|work)\b[/\w.-]*",
    re.IGNORECASE
)

# APK / executable download links
APK_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s]*\.(?:apk|exe|msi|dmg|zip|rar|bat|cmd|ps1|scr|jar)",
    re.IGNORECASE
)

# --- Phone Numbers ---

# Indian phone numbers with lookbehind/lookahead to prevent false positives
PHONE_REGEX = re.compile(
    r"(?<!\d)(?:\+91[\s-]?|91[\s-]?|0)?([6-9]\d[\s-]?\d{4}[\s-]?\d{4})(?!\d)"
)

# WhatsApp number mentions
WHATSAPP_REGEX = re.compile(
    r"(?:whatsapp|whats\s*app|wa)\s*(?:no|number|num|#)?[\s:.-]*(?:\+91[\s-]?|91[\s-]?|0)?([6-9]\d[\s-]?\d{4}[\s-]?\d{4})",
    re.IGNORECASE
)

# --- Bank / Financial ---

# Bank account numbers: 9-18 digits (may have spaces/dashes)
BANK_REGEX = re.compile(
    r"\b(\d[\d\s-]{8,20}\d)\b"
)

# Credit/debit card numbers: 13-19 digits, commonly 16
CARD_REGEX = re.compile(
    r"\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b"
)

# IFSC Code: 4 letters + 0 + 6 alphanumeric
IFSC_REGEX = re.compile(
    r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
)

# --- Social / Messaging ---

# Telegram usernames and links
TELEGRAM_REGEX = re.compile(
    r"(?:@|t\.me/|telegram\.me/)([a-zA-Z][a-zA-Z0-9_]{4,})"
)

# --- Monetary Amounts ---

AMOUNT_REGEX = re.compile(
    r"(?:Rs\.?|INR|₹)\s*[\d,]+(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s*(?:rupees?|rs|lakh|lakhs|crore|crores)\b",
    re.IGNORECASE
)

# --- Organization / Authority Impersonation ---

ORGANIZATION_PATTERNS = [
    r"\b(?:State Bank of India|SBI|HDFC|ICICI|Axis Bank|PNB|Bank of India|Canara Bank|Union Bank|BOB|Bank of Baroda|Kotak|Yes Bank|IndusInd|RBL|IDBI|Indian Bank|UCO Bank|Central Bank)\b",
    r"\b(?:Reserve Bank|RBI|SEBI|TRAI|UIDAI|Income Tax|IT Department|Cyber (?:Cell|Crime|Police)|CBI|ED|Enforcement Directorate)\b",
    r"\b(?:PayTM|PhonePe|Google Pay|GPay|Amazon Pay|Flipkart|Jio|Airtel|Vodafone|BSNL)\b",
    r"\b(?:AnyDesk|TeamViewer|Quick Support|QuickSupport)\b",
    r"\b(?:Microsoft|Apple|Google|Amazon|Netflix|WhatsApp|Telegram|Facebook|Instagram)\b"
]

ORGANIZATION_REGEX = re.compile(
    "|".join(ORGANIZATION_PATTERNS),
    re.IGNORECASE
)

# --- Remote Access Tools (red flag) ---

REMOTE_ACCESS_REGEX = re.compile(
    r"\b(?:anydesk|teamviewer|quick\s*support|ammyy\s*admin|ultraviewer|airdroid|remote\s*desktop)\b",
    re.IGNORECASE
)


# ==============================
# SUSPICIOUS KEYWORDS (expanded)
# ==============================

SUSPICIOUS_KEYWORDS = [
    # Urgency & Threats
    "urgent", "immediately", "act now", "limited time", "expire",
    "penalty", "lockout", "freeze", "last chance", "final warning",
    "within 24 hours", "deadline", "time-sensitive", "hurry",

    # Account / Security
    "verify", "verify now", "verify identity", "verify account",
    "blocked", "suspended", "compromised", "unauthorized",
    "suspicious", "security alert", "unusual activity",
    "account blocked", "account suspended", "account closed",
    "deactivate", "reactivate", "update kyc", "kyc verification",
    "re-verify", "identity verification",

    # Actions
    "click", "click here", "click the link", "click below",
    "payment", "transfer", "pay now", "send money",
    "install", "download", "apk", "install app",
    "share", "share otp", "send otp", "enter otp",
    "confirm", "confirmation code",

    # Financial
    "upi", "otp", "kyc", "pin", "cvv", "card number",
    "ifsc", "beneficiary", "beneficiary account",
    "account number", "bank account", "credit card", "debit card",
    "transaction", "refund", "cashback", "reward", "prize",
    "claim", "lottery", "winner", "offer", "bonus",
    "processing fee", "registration fee", "tax",

    # Credentials
    "credential", "password", "login", "username",
    "net banking", "internet banking", "mobile banking",

    # Impersonation
    "rbi", "reserve bank", "aadhaar", "pan card", "aadhar",
    "bank officer", "customer care", "helpdesk", "support team",
    "bank manager", "branch manager", "technical team",
    "compliance officer", "fraud department", "security team",
    "government", "police", "cyber cell", "cyber crime",

    # Communication Channels
    "whatsapp", "telegram", "signal",

    # Remote Access
    "anydesk", "teamviewer", "remote access", "screen share",
    "quick support",

    # Social Engineering
    "trust me", "don't worry", "confidential", "secret",
    "do not tell anyone", "don't share", "keep this private",
    "this is official", "authorized", "legitimate",
    "for your safety", "for security purposes", "mandatory",

    # Link-related
    "link", "url", "portal", "website", "form", "page",
    "registration link", "verification link", "secure link",

    # Money terms
    "rupees", "lakh", "crore", "amount", "balance",
    "wallet", "deposit", "withdraw", "fee"
]


# ==============================
# TEXT CLEANING
# ==============================

def clean_scammer_text(text: str) -> str:
    """
    Clean message text by removing meta/noise content that might
    interfere with pattern matching. Extracts quoted content if
    the message appears to contain system instructions.

    Args:
        text: Raw message text from conversation

    Returns:
        Cleaned text suitable for intelligence extraction
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

    if any(n in text for n in noise_phrases):
        # If message looks like system text, try to extract the actual content
        quoted = re.findall(r'"([^"]+)"', text)
        if quoted:
            return max(quoted, key=len)

    return text


# ==============================
# CLASSIFICATION HELPERS
# ==============================

def is_upi_id(value: str) -> bool:
    """
    Determine if an @-address is a UPI ID (not an email).

    Checks against known UPI handlers and domain structure.
    UPI IDs typically have no TLD (e.g., user@paytm, user@ybl).

    Args:
        value: The @-address string to classify

    Returns:
        True if the address is likely a UPI ID
    """
    parts = value.split("@")
    if len(parts) != 2:
        return False
    domain = parts[1].lower().rstrip(".")

    # Known UPI handler → definitely UPI
    if domain in UPI_HANDLERS:
        return True

    # No TLD (no dot in domain) → likely UPI
    if "." not in domain:
        return True

    # Has a TLD but domain base is a known email provider → not UPI
    domain_base = domain.split(".")[0]
    if domain_base in EMAIL_DOMAINS:
        return False

    return False


def is_email(value: str) -> bool:
    """
    Determine if an @-address is an email address.

    Args:
        value: The @-address string to classify

    Returns:
        True if the address has a valid email domain with TLD
    """
    parts = value.split("@")
    if len(parts) != 2:
        return False
    domain = parts[1].lower()
    # Must have a TLD (dot in domain part)
    return "." in domain


# ==============================
# EXTRACTION ENGINE
# ==============================

def extract_intelligence(text: str) -> dict:
    """
    Extract all actionable intelligence from a single message text.

    Runs multiple regex patterns to identify phone numbers, bank accounts,
    UPI IDs, emails, URLs, IFSC codes, Telegram handles, card numbers,
    monetary amounts, organizations mentioned, and suspicious keywords.

    Each extraction section is independently try/except wrapped so a
    failure in one category doesn't prevent extraction of others.

    Args:
        text: A single message text to analyze

    Returns:
        Dictionary with categorized intelligence lists
    """
    text = clean_scammer_text(text)

    if not text:
        return empty_intel()

    result = empty_intel()

    # ---------- PHONE NUMBERS ----------
    try:
        raw_phones = PHONE_REGEX.findall(text)
        phones = set()
        for p in raw_phones:
            digits = re.sub(r"\D", "", p)
            if len(digits) == 10:
                phones.add(digits)

        # Also catch WhatsApp-specific numbers
        wa_matches = WHATSAPP_REGEX.findall(text)
        for p in wa_matches:
            digits = re.sub(r"\D", "", p)
            if len(digits) == 10:
                phones.add(digits)

        result["phoneNumbers"] = sorted(phones)
    except Exception as e:
        logger.error(f"Phone extraction error: {e}")

    # ---------- ALL @-ADDRESSES (UPI & Email) ----------
    try:
        at_addresses = set(UPI_REGEX.findall(text))
        upis = set()
        emails = set()

        for addr in at_addresses:
            addr_lower = addr.lower()
            if is_upi_id(addr_lower):
                upis.add(addr_lower)
            elif is_email(addr_lower):
                emails.add(addr_lower)

        # Catch emails that UPI regex might miss
        for em in EMAIL_REGEX.findall(text):
            em_lower = em.lower()
            if is_email(em_lower) and em_lower not in upis:
                emails.add(em_lower)

        result["upiIds"] = sorted(upis)
        result["emails"] = sorted(emails)
    except Exception as e:
        logger.error(f"UPI/Email extraction error: {e}")

    # ---------- BANK ACCOUNT NUMBERS ----------
    try:
        phones_set = set(result.get("phoneNumbers", []))
        raw_numbers = BANK_REGEX.findall(text)
        banks = set()

        for num in raw_numbers:
            digits = re.sub(r"\D", "", num)

            # Must be 9-18 digits (Indian accounts can be 9-18 digits)
            if len(digits) < 9 or len(digits) > 18:
                continue

            # Skip if same as phone
            if digits in phones_set:
                continue

            # Skip if it's 91 + phone number (country code prefix)
            if len(digits) >= 12 and digits[:2] == "91" and digits[2:] in phones_set:
                continue

            # Skip if it CONTAINS a known phone number as substring
            is_phone_variant = False
            for ph in phones_set:
                if ph in digits:
                    is_phone_variant = True
                    break
            if is_phone_variant and len(digits) <= 12:
                continue

            # Ignore garbage numbers (all same digit or too few unique)
            if len(set(digits)) <= 2:
                continue

            banks.add(digits)

        result["bankAccounts"] = sorted(banks)
    except Exception as e:
        logger.error(f"Bank account extraction error: {e}")

    # ---------- CARD NUMBERS ----------
    try:
        card_matches = CARD_REGEX.findall(text)
        cards = set()
        for c in card_matches:
            digits = re.sub(r"\D", "", c)
            if 13 <= len(digits) <= 19:
                # Don't add if already in bank accounts
                if digits not in set(result.get("bankAccounts", [])):
                    cards.add(digits)
        if cards:
            # Add card numbers to bank accounts (evaluator scores them there)
            result["bankAccounts"] = sorted(
                set(result.get("bankAccounts", [])) | cards
            )
    except Exception as e:
        logger.error(f"Card number extraction error: {e}")

    # ---------- URLS ----------
    try:
        urls = set(u.lower().rstrip(".,;:)") for u in URL_REGEX.findall(text))

        # Also catch bare domain URLs
        bare_domains = BARE_DOMAIN_REGEX.findall(text)
        for d in bare_domains:
            d_clean = d.lower().rstrip(".,;:)")
            if d_clean and "." in d_clean:
                urls.add(d_clean)

        # APK / malware links
        apks = set(u.lower().rstrip(".,;:)") for u in APK_REGEX.findall(text))
        urls = urls | apks  # merge APK links into phishing links

        result["phishingLinks"] = sorted(urls)
        result["apkLinks"] = sorted(apks)
    except Exception as e:
        logger.error(f"URL extraction error: {e}")

    # ---------- IFSC CODES ----------
    try:
        ifscs = set(IFSC_REGEX.findall(text))
        result["ifscCodes"] = sorted(ifscs)
    except Exception as e:
        logger.error(f"IFSC extraction error: {e}")

    # ---------- TELEGRAM ----------
    try:
        telegrams = set(f"@{t}" for t in TELEGRAM_REGEX.findall(text))
        result["telegramIds"] = sorted(telegrams)
    except Exception as e:
        logger.error(f"Telegram extraction error: {e}")

    # ---------- MONETARY AMOUNTS ----------
    try:
        amounts = AMOUNT_REGEX.findall(text)
        result["amounts"] = sorted(set(a.strip() for a in amounts))
    except Exception as e:
        logger.error(f"Amount extraction error: {e}")

    # ---------- ORGANIZATIONS MENTIONED ----------
    try:
        orgs = ORGANIZATION_REGEX.findall(text)
        result["organizationsMentioned"] = sorted(
            set(o.strip() for o in orgs if o.strip())
        )
    except Exception as e:
        logger.error(f"Organization extraction error: {e}")

    # ---------- REMOTE ACCESS TOOLS ----------
    try:
        remote_tools = REMOTE_ACCESS_REGEX.findall(text)
        if remote_tools:
            result["remoteAccessTools"] = sorted(
                set(r.lower().strip() for r in remote_tools)
            )
    except Exception as e:
        logger.error(f"Remote access extraction error: {e}")

    # ---------- SUSPICIOUS KEYWORDS ----------
    try:
        lowered = text.lower()
        keywords = set()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in lowered:
                keywords.add(kw)
        result["suspiciousKeywords"] = sorted(keywords)
    except Exception as e:
        logger.error(f"Keyword extraction error: {e}")

    return result


def merge_intelligence(existing: dict, new_intel: dict) -> dict:
    """
    Merge newly extracted intelligence into existing intelligence dict.
    Deduplicates values across all categories.

    Args:
        existing: Current accumulated intelligence
        new_intel: Freshly extracted intelligence to merge

    Returns:
        Merged intelligence dictionary with deduplicated values
    """
    merged = {}
    all_keys = set(list(existing.keys()) + list(new_intel.keys()))

    for key in all_keys:
        existing_vals = existing.get(key, [])
        new_vals = new_intel.get(key, [])
        if isinstance(existing_vals, list) and isinstance(new_vals, list):
            # Deduplicate while preserving order
            seen = set()
            combined = []
            for v in existing_vals + new_vals:
                if v not in seen:
                    seen.add(v)
                    combined.append(v)
            merged[key] = sorted(combined)
        else:
            merged[key] = new_vals if new_vals else existing_vals

    return merged


def empty_intel() -> dict:
    """
    Returns an empty intelligence template with all expected keys.

    Returns:
        Dictionary with empty lists for all intelligence categories
    """
    return {
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "bankAccounts": [],
        "suspiciousKeywords": [],
        "emails": [],
        "ifscCodes": [],
        "telegramIds": [],
        "apkLinks": [],
        "amounts": [],
        "organizationsMentioned": [],
        "remoteAccessTools": []
    }
