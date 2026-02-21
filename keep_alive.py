"""
Keep-Alive Pinger
==================
Prevents Railway/Render from sleeping the deployment during evaluation.
Pings the health endpoint every 10 minutes.

Run as a background thread on startup — zero impact on request handling.
"""

import threading
import time
import os
import logging
import requests

logger = logging.getLogger(__name__)

PING_INTERVAL = 600  # 10 minutes


def _get_self_url() -> str:
    """Get the deployed URL from environment, or localhost as fallback."""
    url = os.getenv("RAILWAY_PUBLIC_DOMAIN") or os.getenv("RENDER_EXTERNAL_URL") or ""
    if url:
        # Railway gives just the domain, not the full URL
        if not url.startswith("http"):
            url = f"https://{url}"
        return url.rstrip("/")
    return "http://localhost:8000"


def _ping_loop():
    """Background thread that pings the health endpoint at fixed intervals."""
    # Wait 2 minutes after startup before first ping
    time.sleep(120)

    url = _get_self_url()
    health_url = f"{url}/"

    while True:
        try:
            r = requests.get(health_url, timeout=10)
            logger.info(f"[KEEP-ALIVE] Pinged {health_url} → {r.status_code}")
        except Exception as e:
            logger.warning(f"[KEEP-ALIVE] Ping failed: {e}")

        time.sleep(PING_INTERVAL)


def start_keep_alive():
    """Start the keep-alive pinger as a daemon thread."""
    t = threading.Thread(target=_ping_loop, daemon=True, name="keep-alive")
    t.start()
    logger.info("[KEEP-ALIVE] Background pinger started (interval=10min)")
