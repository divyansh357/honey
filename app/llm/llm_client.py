import requests
from app.config import GROQ_API_KEY

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama3-8b-8192"

def call_groq(messages, temperature=0.2):
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": messages,
        "temperature": temperature
    }

    response = requests.post(
        GROQ_API_URL,
        headers=headers,
        json=payload,
        timeout=10
    )

    if response.status_code != 200:
        print("Groq Error Status:", response.status_code)
        print("Groq Error Body:", response.text)

    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]

