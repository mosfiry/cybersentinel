from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

from security.runtime_secrets import secret_env

load_dotenv()


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


BRIDGE_HOST = env("BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT = int(env("BRIDGE_PORT", "8787"))
BRIDGE_TOKEN = secret_env("BRIDGE_TOKEN")
BRIDGE_ALLOW_NON_LOOPBACK_BIND = env(
    "BRIDGE_ALLOW_NON_LOOPBACK_BIND", "false"
).lower() in {"1", "true", "yes"}
PUBLIC_WEB_ENABLED = env("PUBLIC_WEB_ENABLED", "false").lower() in {"1", "true", "yes"}
PUBLIC_SESSION_COOKIE = env("PUBLIC_SESSION_COOKIE", "cs_public_session")
PUBLIC_SESSION_TTL_SECONDS = int(env("PUBLIC_SESSION_TTL_SECONDS", "1800"))
PUBLIC_WEB_ORIGIN = env("PUBLIC_WEB_ORIGIN")
DB_PATH = Path(env("DB_PATH", "~/.cybersentinel-x/intel.db")).expanduser()

LLM_BASE_URL = env("LLM_BASE_URL").rstrip("/")
LLM_API_KEY = secret_env("LLM_API_KEY")
LLM_MODEL = env("LLM_MODEL")

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RSS_FEEDS = {
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}

if BRIDGE_HOST == "127.0.0.1":
    pass
elif BRIDGE_HOST == "0.0.0.0":
    if not BRIDGE_ALLOW_NON_LOOPBACK_BIND:
        raise RuntimeError(
            "BRIDGE_HOST=0.0.0.0 requires BRIDGE_ALLOW_NON_LOOPBACK_BIND=true."
        )
    token_lower = BRIDGE_TOKEN.lower()
    if len(BRIDGE_TOKEN) < 32 or any(
        marker in token_lower
        for marker in ("replace_with", "change_me", "your_", "placeholder")
    ):
        raise RuntimeError(
            "A non-loopback bind requires a non-placeholder BRIDGE_TOKEN of at least 32 characters."
        )
else:
    raise RuntimeError(
        "BRIDGE_HOST must be 127.0.0.1 or explicitly opted-in 0.0.0.0."
    )
