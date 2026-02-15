# app/config.py
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY")
CEREBRAS_API_KEY = os.getenv("CEREBRAS_API_KEY")

if not API_KEY:
    raise RuntimeError("API_KEY not set in environment")

if not CEREBRAS_API_KEY:
    raise RuntimeError("CEREBRAS_API_KEY not set in environment")
