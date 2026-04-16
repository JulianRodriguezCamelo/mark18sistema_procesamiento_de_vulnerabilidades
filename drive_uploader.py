"""
Sube el .docx generado a Google Drive.
Primera ejecución: abre el navegador para que el usuario autorice con su cuenta Google.
El token se guarda en credentials/token.json para las siguientes ejecuciones.
"""
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from config import CREDENTIALS_FILE, DRIVE_FOLDER_ID

SCOPES = ["https://www.googleapis.com/auth/drive.file"]
TOKEN_PATH = os.path.join(os.path.dirname(CREDENTIALS_FILE), "token.json")


def _get_credentials() -> Credentials:
    creds = None

    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                raise FileNotFoundError(
                    f"No se encontró el archivo de credenciales en:\n  {CREDENTIALS_FILE}\n"
                    "Descárgalo desde Google Cloud Console → APIs → Credenciales → "
                    "OAuth 2.0 → Descargar JSON\ny renómbralo a 'client_secrets.json'."
                )
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(TOKEN_PATH, "w") as f:
            f.write(creds.to_json())

    return creds


def _get_service():
    creds = _get_credentials()
    return build("drive", "v3", credentials=creds)


def _crear_carpeta(service, nombre: str, parent_id: str) -> str:
    """Crea una carpeta en Drive dentro de parent_id. Retorna el ID."""
    # Verificar si ya existe
    query = (
        f"name='{nombre}' and mimeType='application/vnd.google-apps.folder' "
        f"and '{parent_id}' in parents and trashed=false"
    )
    results = service.files().list(q=query, fields="files(id)").execute()
    files = results.get("files", [])
    if files:
        return files[0]["id"]

    metadata = {
        "name": nombre,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [parent_id],
    }
    folder = service.files().create(body=metadata, fields="id").execute()
    return folder["id"]


def subir_a_drive(file_path: str, subfolder_name: str = None) -> str:
    """
    Sube el archivo a Drive.
    Si subfolder_name está definido, crea (o reutiliza) esa subcarpeta
    dentro de DRIVE_FOLDER_ID y sube ahí el archivo.
    Retorna la URL del archivo subido.
    """
    service = _get_service()

    parent_id = DRIVE_FOLDER_ID
    if subfolder_name:
        parent_id = _crear_carpeta(service, subfolder_name, DRIVE_FOLDER_ID)

    file_name = os.path.basename(file_path)
    media = MediaFileUpload(
        file_path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    metadata = {
        "name": file_name,
        "parents": [parent_id],
    }

    uploaded = service.files().create(
        body=metadata,
        media_body=media,
        fields="id, webViewLink",
    ).execute()

    link = uploaded.get("webViewLink", "")
    return link
