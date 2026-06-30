"""
Módulo de autenticación: bcrypt + JWT.
Los usuarios se almacenan en users.json (creado automáticamente al primer arranque).
"""
import os
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt as _bcrypt
from jose import JWTError, jwt
import pyotp

SECRET_KEY  = os.getenv("JWT_SECRET", "caronte-dev-secret-CHANGE-IN-PRODUCTION")
ALGORITHM   = "HS256"
TOKEN_HOURS = 24


def _hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12)).decode()


def _verify(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


# Alias usado en server.py para verificar contraseña actual
class _PwdCompat:
    def verify(self, plain: str, hashed: str) -> bool:
        return _verify(plain, hashed)

pwd = _PwdCompat()

USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

# Usuarios por defecto — solo se crean si users.json no existe
_DEFAULTS = [
    {"email": "admin@empresa.com",             "name": "Admin",      "password": "admin123",    "role": "admin"},
    {"email": "admin@fiduprevisora.com.co",     "name": "Admin FP",   "password": "caronte2025", "role": "admin"},
    {"email": "seguridad@fiduprevisora.com.co", "name": "Seguridad",  "password": "caronte2025", "role": "user"},
]


def _load() -> dict:
    with open(USERS_FILE, encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def init_users():
    """Crea users.json con usuarios por defecto si no existe."""
    if not os.path.exists(USERS_FILE):
        data = {
            u["email"]: {
                "email":           u["email"],
                "name":            u["name"],
                "hashed_password": _hash(u["password"]),
                "role":            u["role"],
                "totp_secret":     None,
                "totp_enabled":    False,
            }
            for u in _DEFAULTS
        }
        _save(data)
        print("[Auth] users.json creado con usuarios por defecto.")
    return _load()


# ── CRUD de usuarios ──────────────────────────────────────────────────────────

def get_user(email: str) -> Optional[dict]:
    return _load().get(email.lower())


def list_users() -> list[dict]:
    return [
        {"email": u["email"], "name": u["name"], "role": u["role"]}
        for u in _load().values()
    ]


def create_user(email: str, name: str, password: str, role: str = "user") -> bool:
    data = _load()
    key  = email.lower()
    if key in data:
        return False
    data[key] = {
        "email":           key,
        "name":            name,
        "hashed_password": _hash(password),
        "role":            role,
        "totp_secret":     None,
        "totp_enabled":    False,
    }
    _save(data)
    return True


def delete_user(email: str) -> bool:
    data = _load()
    key  = email.lower()
    if key not in data:
        return False
    del data[key]
    _save(data)
    return True


def change_password(email: str, new_password: str) -> bool:
    data = _load()
    key  = email.lower()
    if key not in data:
        return False
    data[key]["hashed_password"] = _hash(new_password)
    _save(data)
    return True


# ── Autenticación ─────────────────────────────────────────────────────────────

def authenticate(email: str, password: str) -> Optional[dict]:
    user = get_user(email.lower())
    if not user:
        return None
    if not _verify(password, user["hashed_password"]):
        return None
    return user


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_token(user: dict) -> str:
    expire  = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    payload = {
        "sub":  user["email"],
        "name": user["name"],
        "role": user["role"],
        "exp":  expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def setup_totp(email: str) -> str:
    secret = pyotp.random_base32()

    data = _load()
    data[email]["totp_secret"] = secret
    _save(data)

    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="CARONTE")
    return uri

def verify_totp(email: str, code: str) -> bool:
    user = get_user(email)
    if not user or not user.get("totp_secret"):
        return False

    totp = pyotp.TOTP(user["totp_secret"])
    return totp.verify(code, valid_window=1)  

def enable_totp(email: str):
    data = _load()
    data[email]["totp_enabled"] = True
    _save(data)

def create_temp_token(email: str) -> str:

    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    payload = {
        "sub":  email,
        "type": "totp_pending",   # campo clave — distingue este token del JWT real
        "exp":  expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Inicializar al importar
init_users()
