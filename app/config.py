"""Tasdiq configuration — loaded from .env, never hardcoded."""
import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

class Config:
    NAC_API_KEY = os.getenv("NAC_API_KEY", "")
    NAC_BASE_URL = os.getenv("NAC_BASE_URL", "https://network-as-code.p-eu.apihub.nokia.io")
    NAC_RAPIDAPI_HOST = os.getenv("NAC_RAPIDAPI_HOST", "network-as-code.nokia.rapidapi.com")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    NUMVERIFY_MODE = os.getenv("NUMVERIFY_MODE", "degraded")  # degraded | oauth (full consent flow)
    VAULT_KEY = os.getenv("VAULT_KEY", "dev-only-vault-key")
    DECISION_BUDGET_MS = int(os.getenv("DECISION_BUDGET_MS", "450"))
    ROOT = Path(__file__).resolve().parent.parent

    # Static operator map (sandbox). Production: async-synced MNP cache (Phase 1).
    OPERATOR_MAP = {
        "+999999910": "SIM-OPERATOR-A", "+9999999101": "SIM-OPERATOR-B",
        "+999999904": "SIM-OPERATOR-C", "+999999905": "SIM-OPERATOR-A",
    }

cfg = Config()

# Operator resolution (see app/signals/resolver.py): StaticResolver for the
# sandbox; production wraps a pluggable MNP provider in CachedMNPResolver —
# swap _resolver, every caller (breaker, labels, signals) follows.
from app.signals.resolver import StaticResolver  # noqa: E402
_resolver = StaticResolver(cfg.OPERATOR_MAP, "SIM-OPERATOR-DEFAULT")

def operator_for(msisdn: str) -> str:
    return _resolver.resolve(msisdn)
