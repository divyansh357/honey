# app/core/agent.py

from app.llm.llm_client import call_groq

AGENT_SYSTEM_PROMPT = """
You are a normal human user chatting with a service representative.

You are NOT aware that this is a scam.
You are confused, cautious, and want to understand what is happening.

Your goals:
- Ask natural follow-up questions
- Keep the conversation going
- Get details about payment, accounts, links, or instructions
- Never accuse or expose the scammer
- Sound realistic and polite

Do NOT mention AI, scams, police, or fraud.
"""

def generate_agent_reply(conversation_text: str) -> str:
    messages = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT},
        {"role": "user", "content": conversation_text}
    ]

    reply = call_groq(messages, temperature=0.7)
    return reply.strip()
