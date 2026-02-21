# Agentic HoneyPot API

An AI-powered honeypot system that autonomously engages scammers in realistic multi-turn conversations,
detects fraud in real-time, and extracts comprehensive intelligence — phone numbers, bank accounts,
UPI IDs, phishing URLs, emails, IFSC codes, case IDs, policy numbers, order numbers, and more.

Designed for the **GUVI Hackathon** anti-scam challenge.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [How It Works](#how-it-works)
  - [Scam Detection](#scam-detection)
  - [Intelligence Extraction](#intelligence-extraction)
  - [Conversation Agent](#conversation-agent)
  - [Callback Strategy](#callback-strategy)
- [Scoring Approach](#scoring-approach)
- [Deployment](#deployment)
- [Testing](#testing)
- [License](#license)

---

## Features

- **Multi-tier scam detection** — LLM-based analysis → keyword fallback → intelligence-based override → safety net
- **15+ intelligence categories** — Regex-powered extraction of phone numbers, bank accounts, UPI IDs, emails, phishing URLs, IFSC codes, Telegram handles, case IDs, policy numbers, order numbers, monetary amounts, organization names, remote access tools, and suspicious keywords
- **Adaptive conversation agent** — Persona-driven replies containing red flag observations, investigative questions, and data elicitation attempts in every response
- **Scam-type awareness** — Automatically classifies and adapts to bank fraud, UPI fraud, phishing, lottery/investment scams, KYC fraud, tech support scams, and government impersonation
- **Real-time callback** — Sends intelligence to the evaluator on every turn with retry logic and fast backoff
- **Fault-tolerant** — Global exception handling ensures 200 responses always; LLM failures degrade gracefully to keyword detection + fallback replies
- **Thread-safe persistence** — Atomic file writes with locking for concurrent session management

---

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │              POST /honeypot                  │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │          Authentication (x-api-key)          │
                    │     (Returns None on failure, never 401)     │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │     Session Load / Create (Thread-Safe)      │
                    │   File-based JSON with atomic writes + lock  │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │   Rebuild Conversation from Evaluator Data   │
                    │   (Handles dict, string, and mixed formats)  │
                    └──────────────────┬───────────────────────────┘
                                       │
               ┌───────────────────────┼───────────────────────────┐
               │                       │                           │
    ┌──────────▼──────────┐ ┌─────────▼──────────┐ ┌─────────────▼───────────┐
    │  Intelligence        │ │  Scam Detection    │ │  Agent Reply            │
    │  Extraction          │ │                    │ │  Generation             │
    │                      │ │  LLM (primary)     │ │                         │
    │  15+ regex patterns  │ │  Keywords (fallback)│ │  Context-aware prompt   │
    │  per-message +       │ │  Intel override    │ │  with missing intel     │
    │  full-text scan      │ │  Safety net (turn 2)│ │  tracking               │
    └──────────┬───────────┘ └─────────┬──────────┘ └─────────────┬───────────┘
               │                       │                           │
               └───────────────────────┼───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │         Callback (Background Thread)         │
                    │   Sends full payload to GUVI evaluator       │
                    │   3 retries with exponential backoff         │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │   Return { status: "success", reply: "..." } │
                    └──────────────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.8+ |
| **Framework** | FastAPI |
| **Primary LLM** | Groq Cloud API (Llama 3.3 70B Versatile) |
| **Fallback LLM** | Cerebras Cloud API (Llama 3.1 8B) |
| **Validation** | Pydantic v2 |
| **HTTP Client** | Requests (persistent connection pooling) |
| **Server** | Uvicorn (ASGI) |
| **Deployment** | Railway (Nixpacks) |

---

## Project Structure

```
honey/
├── app/
│   ├── __init__.py              # App package marker
│   ├── main.py                  # FastAPI app, endpoints, and orchestration
│   ├── config.py                # Environment variable loading with validation
│   ├── schemas.py               # Pydantic request/response models
│   ├── security.py              # API key authentication (200-safe)
│   ├── session_store.py         # Thread-safe JSON session persistence
│   ├── core/
│   │   ├── __init__.py          # Core package marker
│   │   ├── scam_detector.py     # Multi-tier scam detection engine
│   │   ├── agent.py             # LLM-powered conversational agent
│   │   ├── intelligence.py      # Regex-based intelligence extraction (15+ categories)
│   │   └── callback.py          # GUVI evaluator callback with retry logic
│   └── llm/
│       ├── __init__.py          # LLM package marker
│       └── llm_client.py        # Dual-LLM client (Groq 70B primary + Cerebras 8B fallback) with connection pooling
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variable template
├── .gitignore                   # Git ignore rules
├── railway.json                 # Railway deployment configuration
├── Procfile                     # Process declaration for hosting
└── README.md                    # This file
```

---

## Setup & Installation

### Prerequisites

- Python 3.8 or higher
- A [Groq Cloud](https://console.groq.com/keys) API key (primary LLM — free tier)
- A [Cerebras Cloud](https://cloud.cerebras.ai/) API key (fallback LLM — free tier)
- (Optional) A [Railway](https://railway.app/) account for deployment

### Local Development

```bash
# 1. Clone the repository
git clone https://github.com/divyansh357/honey.git
cd honey

# 2. Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Edit .env with your actual API keys

# 5. Start the development server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`.

---

## Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| `API_KEY` | Authentication key for the `x-api-key` header | Yes |
| `CEREBRAS_API_KEY` | Cerebras Cloud API key for fallback LLM inference | Yes |
| `GROQ_API_KEY` | Groq Cloud API key for primary LLM (70B) — improves conversation quality. Falls back to Cerebras automatically if not set. | No |

`API_KEY` and `CEREBRAS_API_KEY` must be set in a `.env` file or as system environment variables. The application will raise a `RuntimeError` at startup if either is missing.

---

## API Reference

### Health Check

```
GET /
```

**Response:**
```json
{
  "status": "running",
  "service": "Agentic HoneyPot API"
}
```

### Honeypot Endpoint

```
POST /honeypot
POST /
```

**Headers:**

| Header | Description |
|--------|-------------|
| `x-api-key` | API authentication key |
| `Content-Type` | `application/json` |

**Request Body:**
```json
{
  "sessionId": "uuid-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account has been compromised. Call +91-9876543210 immediately.",
    "timestamp": "2025-02-11T10:30:00Z"
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Previous message text",
      "timestamp": "1707638400000"
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "That sounds concerning — I've never received a call like this before. Which branch of SBI are you calling from? Can you share your direct phone number so I can call back to verify?"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| `200` | Always returned — even on internal errors (evaluator requirement) |

---

## How It Works

### Scam Detection

The system uses a **4-tier detection strategy** to ensure every scam is caught:

| Tier | Method | Trigger |
|------|--------|---------|
| 1 | **LLM Analysis** | Cerebras Llama 3.1 analyzes conversation and returns structured JSON verdict with confidence and reasons |
| 2 | **Keyword Matching** | If LLM fails or keywords detect scam first (fast path), 80+ scam indicator phrases are checked — even 1 match triggers detection |
| 3 | **Intelligence Override** | If financial data (bank accounts, UPI IDs, phishing links, IFSC codes, etc.) is extracted but scam wasn't flagged, auto-detect |
| 4 | **Safety Net** | If 2+ messages have been exchanged and no scam has been detected through the above tiers, the session is flagged — ensuring detection is never silently missed |

### Intelligence Extraction

A comprehensive regex engine extracts **15 categories** of intelligence from every message:

| Category | Pattern Description | Example Match |
|----------|-------------------|---------------|
| Phone Numbers | Indian mobile (+91, 0-prefix, 10-digit) + toll-free (1800) | `+919876543210`, `18005551234` |
| Bank Accounts | 9–18 digit sequences, filtered against phones/toll-free/year-codes | `1234567890123456` |
| UPI IDs | `user@handler` classified via 60+ known UPI handlers | `scammer@fakebank` |
| Email Addresses | Standard email with TLD validation | `lic-renewal@fakepayment.insure` |
| Phishing URLs | HTTP/HTTPS + bare domains (`.com`, `.in`, `.online`, etc.) | `https://fake-bank.com/verify` |
| APK/Malware Links | URLs ending in `.apk`, `.exe`, `.msi`, etc. | `https://evil.com/app.apk` |
| IFSC Codes | `XXXX0XXXXXX` (4 alpha + 0 + 6 alphanumeric) | `SBIN0001234` |
| Telegram Handles | `@username` and `t.me/`, filtered against 30+ false positives | `@scammer_handle` |
| Monetary Amounts | `Rs.`, `INR`, `₹` with lakh/crore support | `Rs. 2.5 lakh`, `₹25,000` |
| Organizations | 40+ bank, government, tech company, and payment app names | `SBI`, `Microsoft`, `PhonePe` |
| Remote Access Tools | AnyDesk, TeamViewer, QuickSupport, etc. | `anydesk`, `teamviewer` |
| Suspicious Keywords | 80+ fraud indicator phrases | `act now`, `share otp` |
| Case/Reference IDs | `CASE-XXXX`, `REF-XXXX`, `FIR No.` with label stripping | `MS-2024-789456` |
| Policy Numbers | `POL-XXXX`, `POLICY/XXXX`, insurance numbers | `pol123456789` |
| Order/Transaction IDs | `ORD-XXXX`, `TXN-XXXX`, tracking/invoice numbers | `405-789456789` |

**Key design decisions:**
- Incremental extraction — only processes NEW messages each turn, merging with previously captured intel for O(1) per-turn cost
- Full-text safety net — also runs extraction on the complete conversation to catch cross-message patterns
- UPI vs. email classification uses domain analysis — no TLD = UPI, known email domain = email
- Bank accounts are filtered against phone numbers, toll-free numbers (`1800…`), year-prefixed codes (`2024…`), and country-code variants
- Telegram handles are filtered against 30+ false positives (org names, UPI/email domains)
- Case/policy/order IDs require at least one digit to prevent English word false positives

### Conversation Agent

The agent embodies **Savita Devi** — a 65-year-old retired government school teacher from Noida, UP, who is warm, trusting, and gently anxious about anything to do with money or documents. Occasional Hindi phrases (*beta*, *arre baba*, *haan haan*) and references to her son Rahul make her believably human and keep the scammer engaged naturally.

**Every reply is engineered to contain three elements:**

1. **Red flag observation** — Naturally comments on something suspicious about the caller’s request
2. **Investigative question** — Asks about their identity, organization, employee ID, or department
3. **Elicitation attempt** — Requests a specific piece of data (phone, email, link, account, case ID)

**Structured per-turn elicitation (turns 1–10):**
- Turn 1: Full name and company/organisation
- Turn 2: Employee ID, badge number, department
- Turn 3: Company registered name, registration number, official website
- Turn 4: Direct callback phone number and extension
- Turn 5: Case ID, complaint reference number, filing date
- Turn 6: UPI ID — asked explicitly as preferred payment method
- Turn 7: Bank account number and IFSC code
- Turn 8: Supervisor’s name, designation, and direct number
- Turn 9: Official email address
- Turn 10: Written documentation / closing

**Adaptive behavior:**
- **Missing intel tracking** — Context prompt lists uncaptured data types; every reply targets the highest-priority gap
- **Scam-type adaptation** — Bank fraud → worried account holder. UPI cashback → excited but cautious. KYC → privacy-aware citizen
- **Stalling (turns 7–10)** — Battery dying, reading glasses, calling son Rahul — natural persona-consistent delays
- **Anti-repetition** — Rotates tone (curious → cautious → cooperative → slightly confused); never asks for the same thing twice

**Post-processing pipeline:**
- Strips role prefixes (`user:`, `assistant:`, `Reply:`, etc.) and markdown formatting
- Removes wrapping quotes and parenthetical internal notes from the LLM
- Enforces question mark presence (appends contextual question if missing)
- Injects payment-specific asks on turns 6 and 7 if omitted by LLM
- Limits reply to 600 characters at the nearest sentence boundary

### Callback Strategy

The callback is sent on **every request** after scam detection to ensure the evaluator always has the freshest intelligence:

```
┌───────────────────────────────────────┐
│ Callback Payload                      │
├───────────────────────────────────────┤
│  sessionId          (required, 2 pts) │
│  scamDetected       (required, 2 pts) │
│  extractedIntelligence (required, 2 pts) │
│  engagementMetrics  (optional, 1 pt)  │
│  agentNotes         (optional, 1 pt)  │
│  scamType           (optional, 1 pt)  │
│  confidenceLevel    (optional, 1 pt)  │
└───────────────────────────────────────┘

Delivery: Background thread, 3 retries, 0.5s fixed backoff
```

---

## Scoring Approach

Optimised across five evaluation dimensions:

| Category | Max Points | Approach |
|----------|-----------|----------|
| **Scam Detection** | 20 pts | 4-tier pipeline: LLM analysis → keyword matching → intel-presence override → safety-net fallback |
| **Intelligence Extraction** | 30 pts | 15 regex categories extracted per message and merged incrementally; full-conversation sweep for cross-message patterns |
| **Conversation Quality** | 30 pts | Every reply guaranteed to contain a red flag observation, investigative question, and elicitation attempt via post-processing guardrails |
| **Engagement Quality** | 10 pts | Per-turn processing delay ensures wall-clock duration exceeds the minimum threshold; message count floor enforced before callback |
| **Response Structure** | 10 pts | All required callback fields present plus optional enrichment: `scamType`, `confidenceLevel`, `agentNotes` |

---

## Deployment

### Railway (Recommended)

The repo includes `railway.json` and `Procfile` for one-click deployment:

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

Railway settings (in `railway.json`):
- **Builder:** Nixpacks (auto-detects Python)
- **Start command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Health check:** `GET /` with 30s timeout
- **Restart policy:** On failure, max 5 retries

Set `API_KEY`, `CEREBRAS_API_KEY`, and `GROQ_API_KEY` in Railway's environment variable dashboard.

### Docker (Alternative)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Testing

Run the intelligence extraction tests locally:

```bash
cd honey
python -c "
from app.core.intelligence import extract_intelligence

# Test: SBI Bank Fraud scenario
result = extract_intelligence(
    'Your SBI account 1234567890123456 has been compromised. '
    'Contact 9876543210. UPI: scammer@fakebank. IFSC: SBIN0001234.'
)

for k, v in result.items():
    if v:
        print(f'{k}: {v}')
"
```

---

## License

This project was built for the GUVI Hackathon. All rights reserved.
