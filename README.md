# 🛡️ Sistema de Procesamiento de Vulnerabilidades

> Automatización inteligente del análisis y remediación de vulnerabilidades de seguridad mediante IA generativa (Groq LLM) con generación de Planes de Remediación en formato Word.

---

## 📋 Descripción

El **Sistema de Procesamiento de Vulnerabilidades** es una herramienta de automatización en Python que transforma reportes de vulnerabilidades en formato Excel (exportados desde Nessus/Tenable) en **Planes de Remediación detallados en formato `.docx`**, enriquecidos con análisis de IA.

El sistema procesa cada vulnerabilidad con el modelo `llama-3.1-8b-instant` de Groq, generando para cada activo afectado:
- Descripción técnica enriquecida (origen, impacto CIA, vectores de ataque)
- Plan de acción de **10 pasos concretos** con comandos específicos por SO
- Tiempo estimado, responsable sugerido y prioridad

---

## 🔄 Flujo del Sistema

```
input/*.xlsx
     │
     ▼
[1] Parser (parser.py)
     │  Detecta hoja "CUADRO DE MANDO"
     │  Mapea columnas por regex flexible
     │  Deduplica registros (IP + activo + plugin_id)
     │
     ▼
[2] Agrupación (main.py)
     │  Agrupa por (IP, Proyecto)
     │  Separa por nivel de severidad → Critical / High / Medium / Low
     │
     ▼
[3] Análisis LLM (groq_analyzer.py)
     │  Cache 3 niveles: plugin_id → CVE → nombre normalizado
     │  Llama a Groq en chunks de 3 vulns únicas
     │  Rate limiting: 32s entre chunks (≤ 6000 TPM/key)
     │  Key dedicada por nivel de severidad
     │
     ▼
[4] Generación de documentos (docx_generator.py)
     │  Portada + encabezado por grupo
     │  Tabla de información técnica
     │  Tabla de Plan de Acción (10 pasos)
     │  Guardado en output/{severidad}/{ip_proyecto}/
     │
     ▼
[5] Archivado
     └─ Excel original movido a processed/
```

---

## 📁 Estructura del Proyecto

```
mark18sistema_procesamiento_de_vulnerabilidades/
│
├── main.py                # Punto de entrada principal
├── config.py              # Configuración, API keys y rutas
├── parser.py              # Parser flexible de Excel de vulnerabilidades
├── groq_analyzer.py       # Motor de análisis con Groq LLM
├── docx_generator.py      # Generador de documentos Word (.docx)
├── drive_uploader.py      # Módulo de subida a Google Drive (opcional)
│
├── requirements.txt       # Dependencias Python
├── .env                   # Variables de entorno (API Keys) — NO subir a Git
├── .gitignore
│
├── input/                 # ← Colocar aquí los Excel a procesar
├── output/                # ← Documentos generados
│   ├── critical/
│   ├── high/
│   ├── medium/
│   └── low/
├── processed/             # ← Excel procesados (archivados automáticamente)
└── credentials/           # ← Credenciales de Google Drive (NO subir a Git)
    ├── client_secrets.json
    └── token.json
```

---

## ⚙️ Requisitos

- **Python** 3.10 o superior
- **Cuenta Groq** con API keys (se recomienda una key por nivel de severidad)
- **Google Cloud Project** con Drive API habilitada *(opcional)*

---

## 🚀 Instalación y Configuración

### 1. Clonar el repositorio

```bash
git clone https://github.com/JulianRodriguezCamelo/mark18sistema_procesamiento_de_vulnerabilidades.git
cd mark18sistema_procesamiento_de_vulnerabilidades
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 3. Configurar variables de entorno

Crea un archivo `.env` en la raíz del proyecto con el siguiente contenido:

```env
# Groq API Keys — una por nivel de severidad para distribución de rate limit
GROQ_API_KEY_CRITICAL=gsk_xxxxxxxxxxxxxxxxxxxxxxxx
GROQ_API_KEY_HIGH=gsk_xxxxxxxxxxxxxxxxxxxxxxxx
GROQ_API_KEY_MEDIUM=gsk_xxxxxxxxxxxxxxxxxxxxxxxx
GROQ_API_KEY_LOW=gsk_xxxxxxxxxxxxxxxxxxxxxxxx
```

> **Nota:** Puedes obtener API keys gratuitas en [console.groq.com](https://console.groq.com). Usar una key diferente por nivel de severidad maximiza el throughput respetando los límites de tasa.

### 4. Configurar Google Drive *(opcional)*

Si deseas subir los documentos generados a Google Drive:

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Crea o selecciona un proyecto → activa la **Google Drive API**
3. Ve a **Credenciales** → **Crear credenciales** → **ID de cliente OAuth 2.0**
4. Selecciona tipo: **Aplicación de escritorio**
5. Descarga el JSON y renómbralo `client_secrets.json`
6. Cópialo en: `credentials/client_secrets.json`

---

## ▶️ Uso

### Ejecución estándar

```bash
# 1. Coloca tu archivo Excel en la carpeta input/
#    (debe contener una hoja llamada "CUADRO DE MANDO")

# 2. Ejecuta el sistema
python main.py
```

El sistema procesará todos los `.xlsx` / `.xls` encontrados en `input/` y generará los documentos en `output/{severidad}/{ip_proyecto}/`.

### Salida en consola

```
[INFO] 1 archivo(s) encontrado(s) en input/

============================================================
  Procesando: vulnerabilidades_Q1_2025.xlsx
============================================================
  [1/4] Parseando Excel...
  [OK] Hoja encontrada: 'CUADRO DE MANDO'
  [OK] 2645 registros → 164 únicos (2481 duplicados eliminados por IP+activo+plugin).
  [OK] 87 activos → 213 documentos a generar.
  [OK] Distribución: CRITICAL:12 | HIGH:45 | MEDIUM:98 | LOW:58

  [1/213] [CRITICAL] 192.168.1.100 | Proyecto-A (3 vulns)
    [Groq] Analizando con key de nivel CRITICAL...
    [Cache] 0/3 vuln(s) resueltas desde cache.
    [Groq-CRITICAL] 3 pendientes → 3 únicos (0 llamadas ahorradas, key CRITICAL).
    [OK] Documento: Plan_Remediacion_192.168.1.100_Proyecto-A_CRITICAL.docx
  ...

[DONE] Proceso completado.
```

---

## 📄 Formato del Excel de Entrada

El archivo Excel debe contener una hoja llamada **`CUADRO DE MANDO`** con columnas que incluyan (se detectan automáticamente por nombre):

| Campo requerido | Ejemplos de nombre de columna aceptados |
|---|---|
| IP del activo | `Dirección IP`, `IP`, `ip` |
| Nombre vulnerabilidad | `Nombre Vulnerabilidad`, `Vulnerabilidad` |
| Criticidad | `Criticidad`, `Criticidad Técnica` |
| CVE | `CVE`, `Código CVE`, `Identificador CVE` |
| Plugin ID | `Plugin ID`, `Plugin` |
| Descripción | `Descripción`, `Descripción Vulnerabilidad` |
| Solución | `Posible Solución`, `Solución` |
| Grupos/Proyecto | `Grupos`, `Grupo` |
| CVSS Score | `CVSS Score`, `CVSS`, `Score` |
| Sistema Operativo | `Sistema Operativo`, `SO` |
| Puerto | `Puerto`, `Port` |

> El parser es **flexible**: reconoce variaciones en mayúsculas/minúsculas, acentos y orden de palabras mediante expresiones regulares.

---

## 📊 Niveles de Severidad

Los documentos se organizan por severidad. El sistema acepta los siguientes valores en el campo de criticidad:

| Nivel | Valores reconocidos |
|---|---|
| **Critical** | `Crítica`, `Critica`, `Critical`, `Critico` |
| **High** | `Alta`, `Alto`, `High` |
| **Medium** | `Media`, `Medio`, `Medium`, `Moderate` |
| **Low** | `Baja`, `Bajo`, `Low`, `Informational`, `Info` |

---

## 🤖 Optimización del Uso de la API de Groq

El módulo `groq_analyzer.py` implementa varias estrategias para minimizar el consumo de tokens y respetar los límites de la API gratuita:

| Optimización | Descripción |
|---|---|
| **Cache 3 niveles** | `plugin_id` → `CVE` → nombre normalizado. Evita re-llamar por vulnerabilidades ya procesadas |
| **Deduplicación** | Solo envía vulnerabilidades únicas a Groq (reduce hasta ~94% los tokens) |
| **Chunks de 3** | Agrupa 3 vulnerabilidades únicas por llamada para maximizar eficiencia |
| **Rate limiting** | Espera 32s entre chunks (≤ 6000 TPM por key) |
| **Key por severidad** | Distribuye la carga entre 4 keys independientes |
| **Retry con backoff** | Reintenta automáticamente en errores 429 / rate limit con espera incremental |
| **JSON tolerante** | Repara JSON malformado del LLM con 4 niveles de fallback |

---

## 📝 Estructura del Documento Generado

Cada archivo `.docx` contiene:

1. **Portada** — Título "Plan de Remediación de Vulnerabilidades", Dirección de Ciberseguridad y fecha de generación
2. **Encabezado de grupo** — IP y Proyecto al que pertenecen las vulnerabilidades
3. **Por cada vulnerabilidad:**
   - **Tabla de Información Técnica**: nombre del activo, IP, descripción enriquecida, impacto, CVE, Plugin ID, CVSS Score, puerto/protocolo, SO, solución detallada
   - **Tabla de Plan de Acción**: objetivo, tiempo estimado, fecha de escaneo, 10 pasos de remediación con comandos exactos, responsable, prioridad y fecha objetivo

---

## 🧪 Pruebas

El proyecto incluye un script de prueba para verificar el funcionamiento con un conjunto de 5 vulnerabilidades de ejemplo:

```bash
python test_5vulns.py
```

---

## 🔒 Seguridad

- **Nunca** incluyas API keys directamente en el código fuente ni en commits de Git
- El archivo `.env` y la carpeta `credentials/` están incluidos en `.gitignore`
- Las API keys se cargan exclusivamente desde variables de entorno usando `python-dotenv`

---

## 📦 Dependencias

| Paquete | Versión mínima | Uso |
|---|---|---|
| `pandas` | ≥ 2.0.0 | Lectura y procesamiento de Excel |
| `openpyxl` | ≥ 3.1.0 | Motor de lectura de `.xlsx` |
| `python-docx` | ≥ 1.1.0 | Generación de documentos Word |
| `groq` | ≥ 0.9.0 | Cliente oficial de la API de Groq |
| `google-api-python-client` | ≥ 2.100.0 | API de Google Drive |
| `google-auth-httplib2` | ≥ 0.2.0 | Autenticación HTTP para Google |
| `google-auth-oauthlib` | ≥ 1.1.0 | Flujo OAuth 2.0 para Google |

---

## 🤝 Contribución

1. Haz un fork del repositorio
2. Crea una rama para tu feature: `git checkout -b feature/nueva-funcionalidad`
3. Haz commit de tus cambios: `git commit -m "feat: descripción del cambio"`
4. Push a la rama: `git push origin feature/nueva-funcionalidad`
5. Abre un Pull Request

---

## 📄 Licencia

Este proyecto es de uso interno. Todos los derechos reservados.

---

*Desarrollado por la Dirección de Ciberseguridad — Sistema de automatización de análisis y remediación de vulnerabilidades.*
