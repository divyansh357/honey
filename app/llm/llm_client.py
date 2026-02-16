"""LLM Client Module
==================
Handles all communication with the Cerebras Cloud API for LLM inference.
Provides automatic fallback replies when the API is unavailable, rate-limited,
or returns safety refusals. This ensures the honeypot conversation never stalls.

Features:
- Timeout protection (20s)
- Rate limit handling (429)
- Server error handling (5xx)
- Safety refusal detection
- Fallback reply pool for graceful degradation
"""

import requests
import random
import logging
from app.config import CEREBRAS_API_KEY

logger = logging.getLogger(__name__)

CEREBRAS_API_URL = "https://api.cerebras.ai/v1/chat/completions"
MODEL = "llama3.1-8b"

# Fallback replies keep conversation alive if LLM fails.
# These are designed to naturally prompt the scammer for more details.
FALLBACK_REPLIES = [
    "Sorry, I didn't fully understand. Could you explain that again?",
    "Can you clarify what you mean? Maybe share more details?",
    "Why is this required? Can you explain the process?",
    "Is this something urgent? What should I do first?",
    "Can you tell me more about this issue? Who should I contact?",
    "I'm not sure I follow — could you share the details again?",
    "Before I proceed, can you give me the reference number or contact details?",
    "I want to make sure this is correct — can you repeat the important details?"
]


def call_cerebras(messages: list, temperature: float = 0.6) -> str:
    """
    Call Cerebras Cloud API for chat completion.

    Sends messages to the LLM and returns the generated text.
    Handles errors gracefully by returning fallback replies that
    keep the honeypot conversation going.

    Args:
        messages: List of message dicts with 'role' and 'content'
        temperature: Sampling temperature (0.0-1.0), higher = more creative

    Returns:
        Generated text string, or a fallback reply if API fails
    """
    headers = {
        "Authorization": f"Bearer {CEREBRAS_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": 200  # Enough for 2-3 sentence replies
    }

    try:
        response = requests.post(
            CEREBRAS_API_URL,
            headers=headers,
            json=payload,
            timeout=20  # 🔥 Prevent hanging
        )

        # HANDLE RATE LIMIT
        if response.status_code == 429:
            print("⚠️ Cerebras Rate Limited — Using fallback reply")
            return random.choice(FALLBACK_REPLIES)

        # Handle server errors safely
        if response.status_code >= 500:
            print("⚠️ Cerebras Server Error — Using fallback reply")
            return random.choice(FALLBACK_REPLIES)

        response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"].strip()

        # GUARD AGAINST SAFETY REFUSALS
        refusal_phrases = [
            "cannot assist",
            "can't assist",
            "cannot help",
            "cannot provide",
            "not allowed",
            "against policy",
            "i'm unable",
            "i cannot",
            "i can’t"
        ]

        if any(p in content.lower() for p in refusal_phrases):
            print("⚠️ LLM Refusal Detected — Using fallback reply")
            return random.choice(FALLBACK_REPLIES)

        return content

    except requests.exceptions.Timeout:
        print("⚠️ Cerebras Timeout — Using fallback reply")
        return random.choice(FALLBACK_REPLIES)

    except requests.exceptions.RequestException as e:
        print("⚠️ Cerebras Request Failed:", str(e))
        return random.choice(FALLBACK_REPLIES)

    except Exception as e:
        print("⚠️ Unexpected LLM Error:", str(e))
        return random.choice(FALLBACK_REPLIES)
