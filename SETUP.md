# Setup del sistema

## 1. Instalar dependencias
```bash
pip install -r requirements.txt
```

## 2. Configurar Groq API Key
En `config.py`, reemplaza:
```python
GROQ_API_KEY = "PEGA_TU_GROQ_API_KEY_AQUI"
```
O usa variable de entorno:
```bash
set GROQ_API_KEY=tu_clave_aqui     # Windows
```

## 3. Configurar Google Drive

### 3a. Crear credenciales OAuth en Google Cloud Console
1. Ve a: https://console.cloud.google.com/
2. Crea un proyecto (o usa uno existente)
3. Activa la API: **Google Drive API**
4. Ve a "Credenciales" → "Crear credenciales" → "ID de cliente OAuth 2.0"
5. Tipo de aplicación: **Aplicación de escritorio**
6. Descarga el JSON → renómbralo `client_secrets.json`
7. Cópialo a: `credentials/client_secrets.json`

### 3b. Obtener el ID de la carpeta de Drive
1. Abre la carpeta en Google Drive
2. Copia el ID de la URL:
   `https://drive.google.com/drive/folders/**ESTE_ES_EL_ID**`
3. Pégalo en `config.py`:
```python
DRIVE_FOLDER_ID = "ESTE_ES_EL_ID"
```

## 4. Ejecutar
```bash
# Pon el Excel en la carpeta input/
# Luego ejecuta:
python main.py

# Si no quieres subir a Drive todavía:
python main.py --skip-drive
```

## Estructura de carpetas
```
input/        ← pon el Excel aquí
output/       ← el .docx generado aparece aquí
processed/    ← el Excel se mueve aquí al terminar
credentials/  ← credenciales de Google Drive
```
