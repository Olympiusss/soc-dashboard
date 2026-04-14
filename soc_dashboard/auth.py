"""
Sentrium Integrated SOC Dashboard — Authentication
TOTP (Google Authenticator) based authentication with session management.
"""

from __future__ import annotations
import secrets
import time
import logging
from typing import Optional
import pyotp
from config import settings

logger = logging.getLogger("soc_dashboard.auth")

# ── In-memory session store ──────────────────────────────────
# { token: { "created_at": float, "last_active": float } }
_sessions: dict[str, dict] = {}


def verify_totp(code: str) -> bool:
    """Verify a 6-digit TOTP code against the configured secret."""
    if not settings.totp_configured():
        logger.warning("TOTP not configured — authentication bypassed")
        return True  # Allow access if TOTP not configured (dev mode)

    try:
        totp = pyotp.TOTP(settings.TOTP_SECRET)
        return totp.verify(code, valid_window=1)  # ±30s window
    except Exception as e:
        logger.error(f"TOTP verification error: {e}")
        return False


def create_session() -> str:
    """Create a new session and return the token."""
    token = secrets.token_urlsafe(48)
    _sessions[token] = {
        "created_at": time.time(),
        "last_active": time.time(),
    }
    _cleanup_expired()
    logger.info(f"Session created. Active sessions: {len(_sessions)}")
    return token


def validate_session(token: Optional[str]) -> bool:
    """Check if a session token is valid and not expired."""
    if not token:
        return False

    session = _sessions.get(token)
    if not session:
        return False

    # Check timeout
    timeout_secs = settings.SESSION_TIMEOUT_MINUTES * 60
    if timeout_secs > 0:
        elapsed = time.time() - session["last_active"]
        if elapsed > timeout_secs:
            _sessions.pop(token, None)
            logger.info("Session expired due to inactivity")
            return False

    # Update last active
    session["last_active"] = time.time()
    return True


def destroy_session(token: Optional[str]):
    """Destroy a session."""
    if token:
        _sessions.pop(token, None)
        logger.info(f"Session destroyed. Active sessions: {len(_sessions)}")


def _cleanup_expired():
    """Remove all expired sessions from memory."""
    if settings.SESSION_TIMEOUT_MINUTES <= 0:
        return

    cutoff = time.time() - (settings.SESSION_TIMEOUT_MINUTES * 60)
    expired = [k for k, v in _sessions.items() if v["last_active"] < cutoff]
    for k in expired:
        del _sessions[k]
