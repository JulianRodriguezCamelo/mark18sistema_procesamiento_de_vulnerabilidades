import os
from dotenv import load_dotenv

# Cargar variables del .env
load_dotenv()


def get_env_var(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Missing environment variable: {name}")
    return value


# ── API Keys ─────────────────────────────────
GROQ_API_KEY_CRITICAL = get_env_var("GROQ_API_KEY_CRITICAL")
GROQ_API_KEY_HIGH     = get_env_var("GROQ_API_KEY_HIGH")
GROQ_API_KEY_MEDIUM   = get_env_var("GROQ_API_KEY_MEDIUM")
GROQ_API_KEY_LOW      = get_env_var("GROQ_API_KEY_LOW")

GROQ_KEYS_BY_SEVERITY = {
    "critical": GROQ_API_KEY_CRITICAL,
    "high":     GROQ_API_KEY_HIGH,
    "medium":   GROQ_API_KEY_MEDIUM,
    "low":      GROQ_API_KEY_LOW,
}

GROQ_MODEL = "llama-3.1-8b-instant"

DRIVE_FOLDER_ID = get_env_var("DRIVE_FOLDER_ID")


# ── Rutas ────────────────────────────────────
BASE_DIR    = os.path.dirname(__file__)
INPUT_DIR   = os.path.join(BASE_DIR, "input")
OUTPUT_DIR  = os.path.join(BASE_DIR, "output")
DONE_DIR    = os.path.join(BASE_DIR, "processed")


# ── Estilos ──────────────────────────────────
COLOR_HEADER_BG  = "6D1A36"
COLOR_HEADER_FG  = "FFFFFF"
COLOR_LABEL_BG   = "F2E0E5"
COLOR_LABEL_FG   = "6D1A36"
COLOR_BORDER     = "6D1A36"
COLOR_TITLE      = "6D1A36"