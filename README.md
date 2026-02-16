# Agentic HoneyPot API

## Description

An AI-powered honeypot system that detects scam messages across multiple fraud types (bank fraud, UPI fraud, phishing, lottery/investment scams) and autonomously engages scammers through multi-turn conversations to extract actionable intelligence — bank accounts, UPI IDs, phone numbers, phishing links, email addresses, IFSC codes, and more.

## Tech Stack

- **Language/Framework**: Python 3.8+ / FastAPI
- **LLM Provider**: Cerebras Cloud API (Llama 3.1 8B)
- **Key Libraries**: `requests`, `uvicorn`, `pydantic`, `python-dotenv`
- **Deployment**: Railway

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/divyansh357/honey.git
   cd honey/GUVI-Hackathon1
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your actual API keys
   ```

4. **Run the application**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

## API Endpoint

- **URL**: `https://your-deployed-url.com/honeypot` (also accepts POST to `/`)
- **Method**: POST
- **Authentication**: `x-api-key` header

### Request Format
```json
{
  "sessionId": "uuid-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your account has been compromised...",
    "timestamp": "2025-02-11T10:30:00Z"
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Previous message",
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

### Response Format
```json
{
  "status": "success",
  "reply": "I'm concerned about my account. Can you verify your identity?"
}
```

## Approach

### How We Detect Scams
- **LLM-based analysis**: Conversation text is analyzed by Cerebras Llama 3.1 for scam intent classification with confidence scoring
- **Robust JSON extraction**: Even if the LLM wraps JSON in explanatory text, we extract it reliably
- **Keyword fallback**: If the LLM fails (rate limit, timeout, refusal), a weighted keyword scoring system detects scams using patterns like urgency, threats, financial requests, and impersonation
- **Intel-based override**: If intelligence is extracted (bank accounts, UPI IDs, etc.) but LLM missed the scam, we auto-flag it
- **No hardcoded responses**: All detection is generic and pattern-based

### How We Extract Intelligence
Regex-based entity extraction runs across ALL scammer messages in the conversation history:
- **Phone numbers**: Indian formats (+91-XXXX, 91XXXX, 0XXXX) with smart filtering to avoid substring matches
- **Bank account numbers**: 10-18 digit sequences, filtered against phone numbers and country-code variants
- **UPI IDs**: Smart classification — domain without TLD = UPI, with TLD = email. Supports 30+ known UPI handles
- **Phishing URLs**: HTTP/HTTPS/www links including APK download links
- **Email addresses**: Standard email pattern with TLD validation
- **IFSC codes**: XXXX0XXXXXX format
- **Telegram usernames**: @username and t.me/username patterns
- **Suspicious keywords**: 40+ fraud-related terms

### How We Maintain Engagement
- **Persona-based agent**: Acts as a confused, cooperative victim across any scam type (bank fraud, UPI cashback, phishing, lottery)
- **Scam-type adaptation**: Agent automatically adjusts persona based on context — worried bank customer vs. excited prize winner
- **Strategic information seeking**: Feigns compliance while asking for phone numbers, UPI IDs, verification links, email addresses, alternative contacts
- **Multi-turn memory**: Full conversation history passed to LLM for contextual responses
- **Anti-repetition**: Rotates tone cycle (curious → cautious → cooperative → confused)
- **Reply post-processing**: Strips role prefixes, quotation marks, parenthetical notes from LLM output

### Callback Strategy
- Callback sent on **every request** after scam is detected (not just at session close)
- Evaluator waits 10 seconds after last message and takes the final callback
- Includes `engagementMetrics`, `extractedIntelligence`, `agentNotes`, and `status`
- 3 retries with exponential backoff on failure

### Architecture
```
POST /honeypot
     │
     ├─ Auth Check (x-api-key, always returns 200)
     ├─ Session Load/Create (file-based, thread-safe)
     ├─ Rebuild History from evaluator data
     ├─ Scam Detection (LLM → keyword fallback → intel override)
     ├─ Agent Reply Generation (LLM with scam-type-adaptive prompt)
     ├─ Intelligence Extraction (regex on ALL scammer messages)
     ├─ Callback (async, sent every request after scam detected)
     └─ Return { status: "success", reply: "..." }
```

## Project Structure
```
GUVI-Hackathon1/
├── app/
│   ├── main.py              # FastAPI endpoints and orchestration
│   ├── config.py             # Environment variable loading
│   ├── schemas.py            # Pydantic request/response models
│   ├── security.py           # API key authentication (200-safe)
│   ├── session_store.py      # Thread-safe JSON session persistence
│   └── core/
│       ├── scam_detector.py  # LLM + keyword scam detection
│       ├── agent.py          # LLM-powered conversational agent
│       ├── intelligence.py   # Regex intelligence extraction engine
│       └── callback.py       # GUVI evaluation callback sender
├── llm/
│   └── llm_client.py        # Cerebras API client with fallbacks
├── requirements.txt
├── .env.example
├── .gitignore
├── railway.json
├── Procfile
└── README.md
```

## Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| `API_KEY` | Authentication key for x-api-key header | Yes |
| `CEREBRAS_API_KEY` | Cerebras Cloud LLM API key | Yes |

## Scoring Targets

| Category | Points | Our Approach |
|----------|--------|------|
| Scam Detection | 20/20 | LLM + keyword fallback + intel override |
| Intelligence Extraction | 40/40 | Regex on all scammer messages, smart UPI/email classification |
| Engagement Quality | 20/20 | Wall-clock duration tracking, 10+ message conversations |
| Response Structure | 20/20 | All required + optional fields in callback |

---

Built for the GUVI Hackathon. Uses Cerebras Cloud API for LLM inference.
