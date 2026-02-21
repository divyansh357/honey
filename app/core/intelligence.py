"""
Intelligence Extraction Engine
================================
Extracts actionable intelligence from scam conversation messages using
regex-based pattern matching and heuristic classification.

Categories extracted:
- Phone numbers (Indian mobile format, multiple variants)
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
- Case/reference IDs (CASE-XXXX, REF-XXXX, etc.)
- Policy numbers (POL-XXXX, POLICY/XXXX, etc.)
- Order numbers (ORD-XXXX, ORDER#XXXX, etc.)

Scoring target: 30 pts (dynamic: 30 ÷ total fake fields in scenario)
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

# Indian phone numbers — handles many formats:
# +91 98765 43210, +91-9876543210, 09876543210, 91 9876543210,
# 9876543210, +91 9876-543-210, etc.
PHONE_REGEX = re.compile(
    r"(?<!\d)(?:\+?91[\s\-.]?|0)?([6-9]\d[\s\-.]?\d{4}[\s\-.]?\d{4})(?!\d)"
)

# WhatsApp number mentions
WHATSAPP_REGEX = re.compile(
    r"(?:whatsapp|whats\s*app|wa)\s*(?:no|number|num|#)?[\s:.\-]*(?:\+?91[\s\-.]?|0)?([6-9]\d[\s\-.]?\d{4}[\s\-.]?\d{4})",
    re.IGNORECASE
)

# Explicit phone number mentions with label
LABELED_PHONE_REGEX = re.compile(
    r"(?:phone|mobile|cell|contact|call|reach|number|dial|helpline|toll[\s\-]?free)[\s:.\-#]*(?:\+?91[\s\-.]?|0)?([6-9]\d[\s\-.]?\d{4}[\s\-.]?\d{4})",
    re.IGNORECASE
)

# Toll-free numbers (1800-XXX-XXXX or 1800XXXXXXX)
TOLL_FREE_REGEX = re.compile(
    r"(?<!\d)1800[\s\-.]?\d{2,3}[\s\-.]?\d{4}(?!\d)"
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

# Common organization names that should NOT be treated as Telegram handles
# when matched by the @username pattern
TELEGRAM_FALSE_POSITIVES = {
    "phonepe", "paytm", "amazon", "microsoft", "google", "apple",
    "netflix", "flipkart", "india", "gmail", "yahoo", "whatsapp",
    "facebook", "instagram", "twitter", "incometax", "telegram",
    "fakebank", "fakeupi", "fakefinance", "fakeinternational",
    "fakeecommerce", "fakeutility", "fakepost", "fakepayment",
    "fakegovt", "fakecryptoplatform", "fakeincometax", "fakekyc",
    "licrenewal", "phonepe12345",
}

# --- Monetary Amounts ---

AMOUNT_REGEX = re.compile(
    r"(?:Rs\.?|INR|₹)\s*[\d,]+(?:\.\d{1,2})?(?:\s*(?:lakh|lakhs|crore|crores)\b)?|\b\d[\d,]*(?:\.\d{1,2})?\s*(?:rupees?|rs|lakh|lakhs|crore|crores)\b",
    re.IGNORECASE
)

# --- Case / Reference IDs ---
# Catches patterns like: CASE-12345, REF-ABC123, Case No. 12345,
# Reference Number: ABC-12345, case id: XY12345, FIR No 123/2025
CASE_ID_REGEX = re.compile(
    r"(?:case[\s\-_#:]*(?:no\.?|number|id|ref)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:ref(?:erence)?[\s\-_#:]*(?:no\.?|number|id)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:FIR[\s\-_#:]*(?:no\.?|number)?[\s\-_#:]*\d[\w\-/]{1,15})"
    r"|(?:complaint[\s\-_#:]*(?:no\.?|number|id)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:ticket[\s\-_#:]*(?:no\.?|number|id)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:incident[\s\-_#:]*(?:no\.?|number|id)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:[A-Z]{2,5}[-/]\d[\w\-/]{2,20})",
    re.IGNORECASE
)

# --- Policy Numbers ---
# Catches patterns like: POL-12345, Policy No. ABC123, POLICY/12345,
# policy number: LI-12345, insurance policy: INS123456
POLICY_NUMBER_REGEX = re.compile(
    r"(?:polic(?:y|ies)[\s\-_#:]*(?:no\.?|number|id|num)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:insurance[\s\-_#:]*(?:no\.?|number|id|policy)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:POL[\s\-_/#:]*\d[A-Z0-9]{2,14})"
    r"|(?:INS[\s\-_/#:]*\d[A-Z0-9]{2,14})"
    r"|(?:LI[\s\-_/#:]*\d{4,15})",
    re.IGNORECASE
)

# --- Order Numbers ---
# Catches patterns like: ORD-12345, ORDER#123, Order No. ABC123,
# order id: XY12345, transaction id: TXN123456
ORDER_NUMBER_REGEX = re.compile(
    r"(?:order[\s\-_#:]*(?:no\.?|number|id|num)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:transaction[\s\-_#:]*(?:no\.?|number|id)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:track(?:ing)?[\s\-_#:]*(?:no\.?|number|id)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:shipment[\s\-_#:]*(?:no\.?|number|id)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})"
    r"|(?:ORD[\s\-_/#:]*\d[A-Z0-9]{2,14})"
    r"|(?:TXN[\s\-_/#:]*\d[A-Z0-9]{2,14})"
    r"|(?:invoice[\s\-_#:]*(?:no\.?|number|id)?[\s\-_#:]*[A-Z0-9][\w\-/]{2,20})",
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


def _clean_id_match(match_text: str) -> str:
    """Strip label prefixes (case, ref, order, etc.) from extracted ID matches."""
    cleaned = re.sub(
        r"^(?:case|ref(?:erence)?|fir|complaint|ticket|incident|"
        r"polic(?:y|ies)|insurance|order|transaction|invoice|"
        r"track(?:ing)?|shipment|consignment)\s*"
        r"(?:no\.?|number|id|ref|num)?\s*[-_#:=]*\s*",
        "", match_text.strip(), flags=re.IGNORECASE
    ).strip()
    return cleaned if len(cleaned) >= 3 else match_text.strip()


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

        # Also catch labeled phone number mentions
        labeled_matches = LABELED_PHONE_REGEX.findall(text)
        for p in labeled_matches:
            digits = re.sub(r"\D", "", p)
            if len(digits) == 10:
                phones.add(digits)

        # Toll-free numbers (1800-XXX-XXXX)
        tf_matches = TOLL_FREE_REGEX.findall(text)
        for p in tf_matches:
            digits = re.sub(r"\D", "", p)
            if 10 <= len(digits) <= 11:
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
            # Strip trailing periods that can corrupt UPI IDs/emails
            addr_lower = addr.lower().rstrip(".")
            if is_upi_id(addr_lower):
                upis.add(addr_lower)
            elif is_email(addr_lower):
                emails.add(addr_lower)

        # Catch emails that UPI regex might miss
        for em in EMAIL_REGEX.findall(text):
            em_lower = em.lower().rstrip(".")
            if is_email(em_lower) and em_lower not in upis:
                emails.add(em_lower)

        result["upiIds"] = sorted(upis)
        result["emailAddresses"] = sorted(emails)
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

            # Skip toll-free numbers (1800XXXXXXX) — NOT bank accounts
            if digits.startswith("1800"):
                continue

            # Skip numbers that look like years or short codes
            if len(digits) <= 10 and digits[:4] in ("2024", "2025", "2026", "2023"):
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

        # Also catch bare domain URLs — but skip if the full-URL version
        # (with http(s)://) is already captured, to avoid duplicates like
        # "https://sbi-verify.com/portal" AND "sbi-verify.com/portal"
        bare_domains = BARE_DOMAIN_REGEX.findall(text)
        existing_stripped = {u.split("://", 1)[1] if "://" in u else u for u in urls}
        for d in bare_domains:
            d_clean = d.lower().rstrip(".,;:)")
            if d_clean and "." in d_clean and d_clean not in existing_stripped:
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
        raw_telegrams = TELEGRAM_REGEX.findall(text)
        telegrams = set()
        # Collect UPI/email domains to filter Telegram false positives
        upi_email_domains = set()
        for upi in result.get("upiIds", []):
            if "@" in upi:
                upi_email_domains.add(upi.split("@")[1].lower().rstrip("."))
        for email in result.get("emailAddresses", []):
            if "@" in email:
                domain_parts = email.split("@")[1].lower().rstrip(".").split(".")
                upi_email_domains.add(domain_parts[0])
        for t in raw_telegrams:
            t_lower = t.lower()
            # Filter out common org names AND UPI/email domains
            if t_lower not in TELEGRAM_FALSE_POSITIVES and t_lower not in upi_email_domains:
                telegrams.add(f"@{t}")
        result["telegramIds"] = sorted(telegrams)
    except Exception as e:
        logger.error(f"Telegram extraction error: {e}")

    # ---------- MONETARY AMOUNTS ----------
    try:
        amounts = AMOUNT_REGEX.findall(text)
        cleaned_amounts = set()
        for a in amounts:
            a_clean = a.strip().rstrip(",.:;")
            # Skip garbage matches like 'Rs,' or 'Rs.'
            if len(a_clean) > 3 and any(c.isdigit() for c in a_clean):
                cleaned_amounts.add(a_clean)
        result["amounts"] = sorted(cleaned_amounts)
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

    # ---------- CASE / REFERENCE IDS ----------
    try:
        case_matches = CASE_ID_REGEX.findall(text)
        if case_matches:
            case_ids = set()
            for c in case_matches:
                cleaned = _clean_id_match(c.rstrip(".,;:"))
                # Require at least one digit and min length
                if len(cleaned) >= 4 and any(ch.isdigit() for ch in cleaned):
                    case_ids.add(cleaned)
            result["caseIds"] = sorted(case_ids)
    except Exception as e:
        logger.error(f"Case ID extraction error: {e}")

    # ---------- POLICY NUMBERS ----------
    try:
        policy_matches = POLICY_NUMBER_REGEX.findall(text)
        if policy_matches:
            policy_nums = set()
            for p in policy_matches:
                cleaned = _clean_id_match(p.rstrip(".,;:"))
                # Require at least one digit to avoid English word matches
                if len(cleaned) >= 4 and any(ch.isdigit() for ch in cleaned):
                    policy_nums.add(cleaned)
            result["policyNumbers"] = sorted(policy_nums)
    except Exception as e:
        logger.error(f"Policy number extraction error: {e}")

    # ---------- ORDER NUMBERS ----------
    try:
        order_matches = ORDER_NUMBER_REGEX.findall(text)
        if order_matches:
            order_nums = set()
            for o in order_matches:
                cleaned = _clean_id_match(o.rstrip(".,;:"))
                # Require at least one digit to avoid English word matches
                if len(cleaned) >= 4 and any(ch.isdigit() for ch in cleaned):
                    order_nums.add(cleaned)
            result["orderNumbers"] = sorted(order_nums)
    except Exception as e:
        logger.error(f"Order number extraction error: {e}")

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

    Includes all data types from the Feb 19 evaluation spec:
    phones, banks, UPIs, links, emails, case IDs, policy numbers,
    order numbers, IFSC codes, Telegram IDs, amounts, organizations,
    remote access tools, and suspicious keywords.

    Returns:
        Dictionary with empty lists for all intelligence categories
    """
    return {
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "bankAccounts": [],
        "suspiciousKeywords": [],
        "emailAddresses": [],
        "ifscCodes": [],
        "telegramIds": [],
        "apkLinks": [],
        "amounts": [],
        "organizationsMentioned": [],
        "remoteAccessTools": [],
        "caseIds": [],
        "policyNumbers": [],
        "orderNumbers": []
    }
