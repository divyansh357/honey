"""
Configuration Module
=====================
Loads environment variables from .env file for:
- API_KEY: Authentication key for incoming requests
- CEREBRAS_API_KEY: API key for Cerebras Cloud LLM service

Raises RuntimeError at startup if required variables are missing,
preventing the app from starting in an unconfigured state.
"""

import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY")
CEREBRAS_API_KEY = os.getenv("CEREBRAS_API_KEY")

if not API_KEY:
    raise RuntimeError("API_KEY not set in environment — check .env file")

if not CEREBRAS_API_KEY:
    raise RuntimeError("CEREBRAS_API_KEY not set in environment — check .env file")
