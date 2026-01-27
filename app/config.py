# app/config.py
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not API_KEY:
    raise RuntimeError("API_KEY not set in environment")

if not GROQ_API_KEY:
    raise RuntimeError("GROQ_API_KEY not set in environment")
