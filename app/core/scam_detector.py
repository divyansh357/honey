import json
from app.llm.llm_client import call_cerebras

SYSTEM_PROMPT = """
You are a scam detection system.

Analyze the conversation and decide if it contains scam intent.
Return ONLY valid JSON in this format:

{
  "scamDetected": true or false,
  "confidence": number between 0 and 1,
  "reasons": ["reason1", "reason2"]
}

Do not add explanations.
"""

def detect_scam(conversation):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": conversation}
    ]

    raw_output = call_cerebras(messages)

    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        return {
            "scamDetected": False,
            "confidence": 0.0,
            "reasons": ["LLM parsing failed"]
        }
