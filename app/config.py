"""Central settings. Override any value with an environment variable of the same name."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
JOB_DIR = DATA_DIR / "jobs"
for d in (UPLOAD_DIR, JOB_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Local llama.cpp server (llama-server). Nothing leaves the machine.
LLM_URL = os.getenv("LLM_URL", "http://127.0.0.1:8080")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "180"))      # seconds per model call
LLM_RETRIES = int(os.getenv("LLM_RETRIES", "2"))          # extra attempts after the first

# ---- Token budget (all counted with the model's own tokenizer via /tokenize) ----
CTX_LIMIT = int(os.getenv("CTX_LIMIT", "2048"))           # hard model context per call
OUTPUT_RESERVE = int(os.getenv("OUTPUT_RESERVE", "448"))  # max tokens the model may write
CARRY_BUDGET = int(os.getenv("CARRY_BUDGET", "220"))      # facts carried from earlier parts
SAFETY_MARGIN = int(os.getenv("SAFETY_MARGIN", "64"))     # template / rounding slack

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
ALLOWED_EXT = {".log", ".txt"}

# Cross-part correlation thresholds
BRUTE_FORCE_MIN_FAILS = int(os.getenv("BRUTE_FORCE_MIN_FAILS", "5"))
