from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

BRIDGE_HOST = env("BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT = int(env("BRIDGE_PORT", "8787"))
BRIDGE_TOKEN = env("BRIDGE_TOKEN")
DB_PATH = Path(env("DB_PATH", "~/.cybersentinel-x/intel.db")).expanduser()

LLM_BASE_URL = env("LLM_BASE_URL").rstrip("/")
LLM_API_KEY = env("LLM_API_KEY")
LLM_MODEL = env("LLM_MODEL")

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RSS_FEEDS = {
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}

if BRIDGE_HOST != "127.0.0.1":
    raise RuntimeError("BRIDGE_HOST must remain 127.0.0.1.")
