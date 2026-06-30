"""
CARONTE — Servidor API FastAPI
  POST   /api/auth/login               — Login → JWT
  GET    /api/auth/me                  — Perfil del usuario autenticado
  POST   /api/auth/change-password     — Cambiar contraseña (auth requerida)
  GET    /api/auth/users               — Listar usuarios (solo admin)
  POST   /api/auth/users               — Crear usuario  (solo admin)
  DELETE /api/auth/users/{email}       — Eliminar usuario (solo admin)
  POST   /api/upload                   — Recibe Excel, lanza procesamiento (auth)
  GET    /api/tasks/{id}/stream        — SSE con progreso en tiempo real (auth)
  GET    /api/tasks/{id}/status        — Estado actual (auth)
  GET    /api/tasks/{id}/download      — ZIP con .docx generados (auth)
  GET    /api/health                   — Estado de la API (público)
"""
import os
import sys
import uuid
import threading
import json
import time
import zipfile
import io
import shutil

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status, Query
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

# UTF-8 en Windows
if sys.stdout and sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import auth as auth_module
from config import INPUT_DIR, OUTPUT_DIR, DONE_DIR
from parser import parse_excel, agrupar_por_ip_proyecto
from groq_analyzer import analizar_grupo
from docx_generator import generar_docx_por_grupo

app = FastAPI(title="CARONTE API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:3001", "http://127.0.0.1:3001",
        "http://localhost:3002", "http://127.0.0.1:3002",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Seguridad ─────────────────────────────────────────────────────────────────

_bearer = HTTPBearer(auto_error=False)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    if not credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token requerido")
    payload = auth_module.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido o expirado")
    if payload.get("type") == "totp_pending":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2FA pendiente de verificación")
    return payload


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Se requiere rol admin")
    return user


def get_current_user_flexible(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    token: str | None = Query(default=None),
) -> dict:
    raw = credentials.credentials if credentials else token
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token requerido")
    payload = auth_module.verify_token(raw)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido o expirado")
    return payload


# ── Modelos Pydantic ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    email: str
    name: str
    password: str
    role: str = "user"


# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    user = auth_module.authenticate(req.email.strip(), req.password)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Correo o contraseña incorrectos")

    if user.get("totp_enabled"):
        temp_token = auth_module.create_temp_token(user["email"])
        return {
            "require_totp": True,
            "temp_token": temp_token,
        }

    token = auth_module.create_token(user)
    return {
        "require_totp": False,
        "access_token": token,
        "token_type": "bearer",
        "user": {"email": user["email"], "name": user["name"], "role": user["role"]},
    }
class VerifyTotpRequest(BaseModel):
    temp_token: str
    code: str

@app.post("/api/auth/verify-totp")
async def verify_totp(req: VerifyTotpRequest):
    # 1. Decodificar el token temporal
    payload = auth_module.verify_token(req.temp_token)

    # 2. Rechazar si no es un token temporal válido
    if not payload or payload.get("type") != "totp_pending":
        raise HTTPException(401, "Token inválido o expirado")

    email = payload["sub"]
    user = auth_module.get_user(email)

    # 3. Bloquear si el usuario no ha configurado el 2FA aún
    if not user or not user.get("totp_enabled"):
        raise HTTPException(403, "Debes activar el 2FA antes de iniciar sesión. Contacta al administrador.")

    # 4. Verificar el código de 6 dígitos
    if not auth_module.verify_totp(email, req.code):
        raise HTTPException(401, "Código incorrecto")

    # 4. Todo ok → emitir JWT definitivo
    user = auth_module.get_user(email)
    token = auth_module.create_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"email": user["email"], "name": user["name"], "role": user["role"]},
    }

@app.get("/api/auth/me")
async def me(current_user: dict = Depends(get_current_user)):
    user = auth_module.get_user(current_user["sub"])
    return {
        "email":        current_user["sub"],
        "name":         current_user["name"],
        "role":         current_user["role"],
        "totp_enabled": user.get("totp_enabled", False) if user else False,
    }


@app.post("/api/auth/change-password")
async def change_password(req: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    email = current_user["sub"]
    user  = auth_module.get_user(email)
    if not user or not auth_module.pwd.verify(req.current_password, user["hashed_password"]):
        raise HTTPException(400, "La contraseña actual es incorrecta")
    if len(req.new_password) < 6:
        raise HTTPException(400, "La nueva contraseña debe tener al menos 6 caracteres")
    auth_module.change_password(email, req.new_password)
    return {"message": "Contraseña actualizada correctamente"}


@app.get("/api/auth/users")
async def list_users(_admin: dict = Depends(require_admin)):
    return auth_module.list_users()


@app.post("/api/auth/users", status_code=201)
async def create_user(req: CreateUserRequest, _admin: dict = Depends(require_admin)):
    if len(req.password) < 6:
        raise HTTPException(400, "La contraseña debe tener al menos 6 caracteres")
    ok = auth_module.create_user(req.email.strip().lower(), req.name.strip(), req.password, req.role)
    if not ok:
        raise HTTPException(409, f"Ya existe un usuario con el correo {req.email}")
    return {"message": f"Usuario {req.email} creado correctamente"}


@app.delete("/api/auth/users/{email}")
async def delete_user(email: str, current_user: dict = Depends(require_admin)):
    if email.lower() == current_user["sub"]:
        raise HTTPException(400, "No puedes eliminar tu propia cuenta")
    ok = auth_module.delete_user(email)
    if not ok:
        raise HTTPException(404, "Usuario no encontrado")
    return {"message": f"Usuario {email} eliminado"}

@app.post("/api/auth/2fa/setup")
async def setup_2fa(current_user: dict = Depends(get_current_user)):
    """Genera el QR. El frontend lo muestra para que el usuario escanee."""
    email = current_user["sub"]
    uri = auth_module.setup_totp(email)

    # Convertir la URI en imagen QR en base64 para el frontend
    import qrcode, base64
    from io import BytesIO
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    return {"qr_image": f"data:image/png;base64,{qr_base64}"}


class ConfirmTotpRequest(BaseModel):
    code: str

@app.post("/api/auth/2fa/confirm")
async def confirm_2fa(req: ConfirmTotpRequest, current_user: dict = Depends(get_current_user)):
    """El usuario escanea el QR y envía el primer código para confirmar que funciona."""
    email = current_user["sub"]

    if not auth_module.verify_totp(email, req.code):
        raise HTTPException(400, "Código incorrecto. Intenta de nuevo.")

    auth_module.enable_totp(email)   # solo activa si el código fue correcto
    return {"message": "Autenticación de dos factores activada correctamente"}


# ── Constantes de severidad ───────────────────────────────────────────────────

SEVERIDADES = ["critical", "high", "medium", "low"]

_CRITICIDAD_MAP = {
    "critica": "critical", "crítica": "critical", "critical": "critical",
    "critico": "critical", "crítico": "critical",
    "alta": "high", "alto": "high", "high": "high",
    "media": "medium", "medio": "medium", "medium": "medium", "moderate": "medium",
    "baja": "low", "bajo": "low", "low": "low",
    "informational": "low", "info": "low",
}


def _normalizar_severidad(criticidad: str | None) -> str:
    if not criticidad:
        return "low"
    return _CRITICIDAD_MAP.get(criticidad.strip().lower(), "low")


def _expandir_por_severidad(grupos: dict) -> list[tuple]:
    resultado = []
    for (ip, proyecto), vulns in grupos.items():
        por_sev: dict[str, list] = {}
        for vuln in vulns:
            sev = _normalizar_severidad(vuln.get("criticidad"))
            por_sev.setdefault(sev, []).append(vuln)
        for sev in SEVERIDADES:
            if sev in por_sev:
                resultado.append((ip, proyecto, sev, por_sev[sev]))
    return resultado


def _dedup_vulns(vulns: list[dict]) -> list[dict]:
    vistas: set = set()
    resultado = []
    for v in vulns:
        clave = (
            v.get("ip") or "",
            v.get("nombre_activo") or "",
            v.get("plugin_id") or v.get("nombre_vulnerabilidad") or "",
        )
        if clave not in vistas:
            vistas.add(clave)
            resultado.append(v)
    return resultado


def _nombre_carpeta(ip: str, proyecto: str) -> str:
    raw = f"{ip}_{proyecto}"
    for ch in (" ", "/", ":", "*", "?", '"', "<", ">", "|", "\n", "\r", "\t"):
        raw = raw.replace(ch, "-")
    return raw


def _nombre_docx(ip: str, proyecto: str, severidad: str) -> str:
    return f"Plan_Remediacion_{_nombre_carpeta(ip, proyecto)}_{severidad.upper()}.docx"


# ── Task store (in-memory) ────────────────────────────────────────────────────

tasks: dict[str, dict] = {}


def _init_task(task_id: str, filename: str) -> dict:
    task = {
        "task_id": task_id, "status": "processing", "progress": 0,
        "file": filename, "projects": [], "total_docs": 0,
        "total_folders": 0, "completed_docs": 0,
        "start_time": time.time(), "elapsed_seconds": 0,
        "message": "Iniciando procesamiento...", "error": None,
    }
    tasks[task_id] = task
    return task


def _update_vuln_status(task: dict, ip: str, proyecto: str, severity: str, st: str):
    for project in task["projects"]:
        if project["ip"] == ip and project["name"] == proyecto:
            for vuln in project["vulnerabilities"]:
                if vuln["severity"] == severity:
                    vuln["status"] = st
                    return


def _process_excel_task(task_id: str, excel_path: str):
    task = tasks[task_id]
    try:
        for sev in SEVERIDADES:
            os.makedirs(os.path.join(OUTPUT_DIR, sev), exist_ok=True)
        os.makedirs(DONE_DIR, exist_ok=True)

        task["message"] = "Parseando Excel..."; task["progress"] = 5
        vulnerabilidades, _ = parse_excel(excel_path)

        if not vulnerabilidades:
            task["status"] = "error"
            task["error"]  = "No se encontraron vulnerabilidades en el archivo."
            return

        vulnerabilidades = _dedup_vulns(vulnerabilidades)

        task["message"] = "Agrupando vulnerabilidades..."; task["progress"] = 10
        grupos_base     = agrupar_por_ip_proyecto(vulnerabilidades)
        grupos_exp      = _expandir_por_severidad(grupos_base)
        total           = len(grupos_exp)

        task["total_docs"]    = total
        task["total_folders"] = len(grupos_base)

        projects_map: dict[tuple, dict] = {}
        for ip, proyecto, sev, _ in grupos_exp:
            key = (ip, proyecto)
            if key not in projects_map:
                projects_map[key] = {"ip": ip, "name": proyecto, "expanded": True, "vulnerabilities": []}
            projects_map[key]["vulnerabilities"].append({"severity": sev.upper(), "status": "pending", "documents": 1})

        task["projects"] = list(projects_map.values())
        task["progress"] = 15

        completed = 0
        for ip, proyecto, severidad, vulns in grupos_exp:
            carpeta     = _nombre_carpeta(ip, proyecto)
            docx_nombre = _nombre_docx(ip, proyecto, severidad)
            output_path = os.path.join(OUTPUT_DIR, severidad, carpeta, docx_nombre)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            task["message"] = f"[{severidad.upper()}] {ip} | {proyecto}"
            _update_vuln_status(task, ip, proyecto, severidad.upper(), "processing")

            vulns_e = analizar_grupo(ip, proyecto, vulns, severidad)
            generar_docx_por_grupo(ip, proyecto, vulns_e, output_path)

            _update_vuln_status(task, ip, proyecto, severidad.upper(), "completed")
            completed += 1
            task["completed_docs"]   = completed
            task["progress"]         = 15 + int((completed / total) * 82)
            task["elapsed_seconds"]  = int(time.time() - task["start_time"])

        done_path = os.path.join(DONE_DIR, os.path.basename(excel_path))
        shutil.move(excel_path, done_path)

        task["status"]          = "completed"
        task["progress"]        = 100
        task["message"]         = "¡Procesamiento completado!"
        task["elapsed_seconds"] = int(time.time() - task["start_time"])

    except Exception as e:
        task["status"] = "error"
        task["error"]  = str(e)
        task["message"] = f"Error: {e}"
        print(f"[ERROR] Task {task_id}: {e}")


# ── Endpoints protegidos ──────────────────────────────────────────────────────

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), _user: dict = Depends(get_current_user)):
    if not file.filename or not file.filename.lower().endswith((".xlsx", ".xls")):
        raise HTTPException(400, "Solo se aceptan archivos Excel (.xlsx, .xls)")

    os.makedirs(INPUT_DIR, exist_ok=True)
    task_id   = str(uuid.uuid4())
    safe_name = os.path.basename(file.filename)
    file_path = os.path.join(INPUT_DIR, safe_name)

    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    _init_task(task_id, safe_name)
    threading.Thread(target=_process_excel_task, args=(task_id, file_path), daemon=True).start()
    return {"task_id": task_id, "filename": safe_name}


@app.get("/api/tasks/{task_id}/stream")
async def stream_progress(task_id: str, _user: dict = Depends(get_current_user_flexible)):
    if task_id not in tasks:
        raise HTTPException(404, "Tarea no encontrada")

    def generate():
        while True:
            task = tasks.get(task_id, {})
            snapshot = {**task, "elapsed_seconds": int(time.time() - task.get("start_time", time.time()))}
            yield f"data: {json.dumps(snapshot, default=str)}\n\n"
            if task.get("status") in ("completed", "error"):
                break
            time.sleep(0.5)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/tasks/{task_id}/status")
async def get_status(task_id: str, _user: dict = Depends(get_current_user)):
    if task_id not in tasks:
        raise HTTPException(404, "Tarea no encontrada")
    task = tasks[task_id]
    return {**task, "elapsed_seconds": int(time.time() - task.get("start_time", time.time()))}


@app.get("/api/tasks/{task_id}/download")
async def download_results(task_id: str, _user: dict = Depends(get_current_user)):
    # Si la tarea existe en memoria, verificar que esté completada
    if task_id in tasks and tasks[task_id]["status"] != "completed":
        raise HTTPException(400, "El procesamiento no ha terminado")

    # Recopilar archivos .docx del directorio de salida
    docx_files = []
    for root, _, files in os.walk(OUTPUT_DIR):
        for fname in files:
            if fname.endswith(".docx"):
                docx_files.append(os.path.join(root, fname))

    if not docx_files:
        raise HTTPException(404, "No hay documentos generados para descargar")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for fpath in docx_files:
            arcname = os.path.relpath(fpath, OUTPUT_DIR)
            zf.write(fpath, arcname)
    zip_buffer.seek(0)

    base = tasks[task_id]["file"].replace(".xlsx", "").replace(".xls", "") if task_id in tasks else "documentos"
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="remediacion_{base}.zip"'},
    )


@app.get("/api/health")
async def health_check():
    groq_ok = bool(os.getenv("GROQ_API_KEY_CRITICAL") or os.getenv("GROQ_API_KEY_HIGH"))
    return {"status": "ok", "groq_connected": groq_ok}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
