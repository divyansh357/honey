# 🛡️ Agentic HoneyPot API

A sophisticated AI-powered scam detection and engagement system built for the GUVI Hackathon. This honeypot intelligently detects scam attempts, engages with scammers through realistic conversations, and extracts actionable intelligence.

## 📋 Overview

The Agentic HoneyPot API simulates a realistic bank customer interaction to:
- **Detect** fraudulent scam attempts in real-time
- **Engage** scammers with AI-generated human-like responses
- **Extract** sensitive intelligence (bank accounts, UPI IDs, phishing links, phone numbers)
- **Report** findings to the GUVI evaluation platform

## ✨ Key Features

### 🔍 Intelligent Scam Detection
- Real-time conversation analysis using LLM-powered detection
- Confidence scoring and reasoning for each detection
- Context-aware evaluation of conversation history

### 🤖 AI-Powered Engagement
- Realistic bank customer persona that stays in character
- Dynamic conversation strategies (curious, cautious, cooperative)
- Anti-repetition mechanisms for natural dialogue
- Intelligent questioning to extract scammer intelligence

### 📊 Intelligence Extraction
- **Bank Account Numbers**: Detects 10-18 digit sequences
- **UPI IDs**: Identifies payment handler addresses
- **Phishing Links**: Captures suspicious URLs
- **Phone Numbers**: Extracts Indian mobile numbers (+91, 10-digit)
- **Keyword Analysis**: Tracks suspicious terms (OTP, verify, urgent, etc.)

### 🔐 Security Features
- API key authentication
- Session-based conversation tracking
- Thread-safe file operations
- Rate limiting protection

## 🏗️ Architecture

```
GUVI-Hackathon1/
├── app/
│   ├── main.py                 # FastAPI application & endpoints
│   ├── config.py               # Environment configuration
│   ├── schemas.py              # Pydantic models
│   ├── security.py             # API key authentication
│   ├── session_store.py        # Thread-safe session management
│   ├── core/
│   │   ├── agent.py            # AI conversation agent
│   │   ├── scam_detector.py    # Scam detection logic
│   │   ├── intelligence.py     # Intelligence extraction engine
│   │   └── callback.py         # GUVI callback integration
│   └── llm/
│       └── llm_client.py       # Groq API integration
├── Procfile                    # Deployment configuration
├── requirements.txt            # Python dependencies
└── sessions.json               # Session persistence
```

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- API Keys:
  - `API_KEY` - Your application API key
  - `CEREBRAS_API_KEY` - Cerebras LLM API key

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd GUVI-Hackathon1
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   API_KEY=your_api_key_here
   CEREBRAS_API_KEY=your_cerebras_api_key_here
   ```

### Running Locally

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API  for web testing will be available at `http://localhost:8000/docs`

### Deployment

The project includes a `Procfile` for easy deployment to platforms like Heroku:

```bash
git push heroku main
```

## 📡 API Endpoints

### POST `/honeypot`

Main endpoint for processing conversations and detecting scams.

**Headers:**
```
X-API-Key: your_api_key
Content-Type: application/json
```

**Request Body:**
```json
{
  "sessionId": "optional-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your account has been blocked. Verify immediately.",
    "timestamp": 1234567890
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Previous message",
      "timestamp": 1234567880
    }
  ],
  "metadata": {
    "channel": "whatsapp",
    "language": "en",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "I'm concerned. Can you explain what happened to my account?"
}
```

## 🧠 How It Works

### 1. **Session Management**
- Each conversation is tracked via unique `sessionId`
- Sessions persist across multiple API calls
- Conversation history rebuilt from evaluator data

### 2. **Scam Detection**
- First message triggers LLM-based scam analysis
- Detection result cached for session
- Confidence scoring with detailed reasoning

### 3. **AI Agent Engagement**
- Activates only after scam detection
- Uses sophisticated prompt engineering for realistic responses
- Varies behavior across conversation stages:
  - **Early**: Curious, asking about the issue
  - **Mid**: Probing for operational details
  - **Late**: Stalling, confirming information

### 4. **Intelligence Extraction**
- Parses each scammer message using regex patterns
- Accumulates findings across conversation
- Cleans false positives and duplicates

### 5. **Session Closure**
- Triggers when sufficient intelligence gathered OR 8+ messages exchanged
- Sends comprehensive report to GUVI callback endpoint
- Includes engagement metrics and extracted intelligence

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `API_KEY` | Authentication key for API access | ✅ |
| `CEREBRAS_API_KEY` | Cerebras LLM service API key | ✅ |

### LLM Configuration

- **Provider**: Cerebras Cloud
- **Model**: `llama3.1-8b`
- **Temperature**: 0.75 (agent), 0.6 (detection)
- **Timeout**: 20 seconds
- **Fallback**: 6 predefined responses

## 📊 Intelligence Categories

### Extracted Data Types

1. **Bank Accounts**: 10-18 digit numeric sequences
2. **UPI IDs**: Format `username@paymenthandler`
3. **Phishing Links**: URLs (http/https/www)
4. **Phone Numbers**: Indian mobile numbers (10 digits, 6-9 start)
5. **Suspicious Keywords**: urgent, verify, blocked, OTP, etc.

### Callback Payload

```json
{
  "sessionId": "session-123",
  "scamDetected": true,
  "totalMessagesExchanged": 8,
  "extractedIntelligence": {
    "bankAccounts": ["1234567890123"],
    "upiIds": ["scammer@paytm"],
    "phishingLinks": ["http://fake-bank.com"],
    "phoneNumbers": ["9876543210"],
    "suspiciousKeywords": ["urgent", "verify", "otp"]
  },
  "agentNotes": "Scammer shared suspicious UPI ID, sent phishing link, attempted OTP extraction."
}
```

## 🛠️ Tech Stack

- **Framework**: FastAPI
- **LLM Provider**: Cerebras Cloud (Llama 3.1)
- **Validation**: Pydantic
- **Server**: Uvicorn
- **Deployment**: Heroku-compatible
- **Storage**: JSON-based session persistence

## 🎯 Use Cases

- **Scam Research**: Gather intelligence on fraud tactics
- **Security Training**: Understand social engineering methods
- **Fraud Prevention**: Identify and catalog scam patterns
- **Threat Intelligence**: Build databases of scammer infrastructure

## 🔒 Security Considerations

- API key authentication on all endpoints
- Thread-safe session management
- Atomic file operations for data integrity
- Timeout protection on external API calls
- Rate limiting handling for LLM service
- Input validation with Pydantic schemas

## 📈 Performance

- **Response Time**: < 2s average (LLM dependent)
- **Concurrent Sessions**: Thread-safe handling
- **Fallback Mechanism**: Graceful degradation on LLM failures
- **Retry Logic**: 3 attempts with exponential backoff for callbacks

## 🤝 Contributing

This project was developed for the GUVI Hackathon. For contributions:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📝 License

This project is created for educational and research purposes as part of the GUVI Hackathon.

## 🙏 Acknowledgments

- **GUVI** for hosting the hackathon
- **Cerebras** for LLM API services
- **FastAPI** community for excellent documentation

## 📧 Support

For issues or questions, please open an issue on the repository.

---

**⚠️ Disclaimer**: This honeypot is designed for research and educational purposes only. It should be used responsibly within legal and ethical boundaries.
