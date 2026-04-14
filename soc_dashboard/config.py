"""
Sentrium Integrated SOC Dashboard — Configuration
All settings loaded from environment variables / .env file.
"""
import os
import logging
from pathlib import Path
from dotenv import load_dotenv
logger = logging.getLogger("soc_dashboard.config")
# Load .env for LOCAL development only.
# override=False means Railway's injected env vars ALWAYS take precedence.
_env_path = Path(__file__).parent / ".env"
load_dotenv(_env_path, override=False)
class Settings:
    """Application settings — sourced from environment variables."""
    @property
    def S1_BASE_URL(self) -> str:
        return os.getenv("S1_BASE_URL", "https://euce1-exclusive.sentinelone.net/web/api/v2.1")
    @property
    def S1_API_TOKEN(self) -> str:
        return os.getenv("S1_API_TOKEN", "").strip().strip('"').strip("'")
    @property
    def AV_SUBDOMAIN(self) -> str:
        return os.getenv("AV_SUBDOMAIN", "cybervergent-nfr.alienvault.cloud")
    @property
    def AV_CLIENT_ID(self) -> str:
        return os.getenv("AV_CLIENT_ID", "").strip().strip('"').strip("'")
    @property
    def AV_CLIENT_SECRET(self) -> str:
        return os.getenv("AV_CLIENT_SECRET", "").strip().strip('"').strip("'")
    @property
    def TOTP_SECRET(self) -> str:
        return os.getenv("TOTP_SECRET", "").strip().strip('"').strip("'")
    TOTP_APP_NAME: str = "Sentrium SOC Dashboard"
    TOTP_ISSUER: str = "Sentrium Security"
    @property
    def SESSION_TIMEOUT_MINUTES(self) -> int:
        return int(os.getenv("SESSION_TIMEOUT_MINUTES", "480"))
    @property
    def REFRESH_INTERVAL(self) -> int:
        return int(os.getenv("REFRESH_INTERVAL", "30"))
    @property
    def HOST(self) -> str:
        return os.getenv("HOST", "0.0.0.0")
    @property
    def PORT(self) -> int:
        return int(os.getenv("PORT", "8080"))
    @property
    def SECRET_KEY(self) -> str:
        return os.getenv("SECRET_KEY", "sentrium-soc-dashboard-secret-key-change-me")
    def s1_configured(self) -> bool:
        return bool(self.S1_API_TOKEN)
    def av_configured(self) -> bool:
        return bool(self.AV_CLIENT_ID and self.AV_CLIENT_SECRET)
    def totp_configured(self) -> bool:
        return bool(self.TOTP_SECRET)
settings = Settings()
# ── Startup Diagnostics ─────────────────────────────────────
_diag_logger = logging.getLogger("soc_dashboard.config")
_diag_logger.info(f"S1 configured: {settings.s1_configured()} | URL: {settings.S1_BASE_URL}")
_diag_logger.info(f"AV configured: {settings.av_configured()} | Subdomain: {settings.AV_SUBDOMAIN}")
_diag_logger.info(f"TOTP configured: {settings.totp_configured()}")
