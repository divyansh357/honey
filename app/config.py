"""
Configuration Module
=====================
Loads environment variables from .env file for:
- API_KEY: Authentication key for incoming requests
- CEREBRAS_API_KEY: API key for Cerebras Cloud LLM service (fallback)
- GROQ_API_KEY: API key for Groq Cloud LLM service (primary, optional)

Uses a dual-LLM strategy: Groq (llama-3.3-70b) for high-quality agent
replies, Cerebras (llama3.1-8b) as fallback for reliability.

Raises RuntimeError at startup if required variables are missing,
preventing the app from starting in an unconfigured state.
"""

import os
from dotenv import load_dotenv

load_dotenv()

API_KEY: str = os.getenv("API_KEY", "")
CEREBRAS_API_KEY: str = os.getenv("CEREBRAS_API_KEY", "")
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")

if not API_KEY:
    raise RuntimeError("API_KEY not set in environment — check .env file")

if not CEREBRAS_API_KEY:
    raise RuntimeError("CEREBRAS_API_KEY not set in environment — check .env file")

# GROQ_API_KEY is optional — system falls back to Cerebras if not set
