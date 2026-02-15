import requests
import random
from app.config import CEREBRAS_API_KEY

CEREBRAS_API_URL = "https://api.cerebras.ai/v1/chat/completions"
MODEL = "llama3.1-8b"

# Fallback replies keep conversation alive if LLM fails
FALLBACK_REPLIES = [
    "Sorry, I didn't fully understand. Could you explain that again?",
    "Can you clarify what you mean?",
    "Why is this required?",
    "Is this something urgent?",
    "Can you tell me more about the issue?",
    "I'm not sure I follow — could you explain a bit more?"
]


def call_cerebras(messages, temperature=0.6):

    headers = {
        "Authorization": f"Bearer {CEREBRAS_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": messages,
        "temperature": temperature
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
