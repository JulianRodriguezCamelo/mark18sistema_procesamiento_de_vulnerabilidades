"""
Parser de Excel de vulnerabilidades.
Adaptado del parser flexible de hallazgos: mapeo por regex sobre nombres de columna.
"""
import re
from datetime import datetime
import pandas as pd

# ── Mapeo columna Excel → campo interno ──────────────────────────────────────
COLUMN_MAP = {
    # Identificación
    r"^id$":                            "id",
    r"^periodo$":                       "periodo",
    r"^grupos?$":                       "grupos",
    r"plugin.*id|^plugin$":             "plugin_id",

    # Fecha escaneo
    r"fecha.*escaneo|host.*start":      "fecha_escaneo",

    # Fuente
    r"fuente|nombre.*fuente":           "fuente",

    # Vulnerabilidad
    r"sinopsis":                        "sinopsis",
    r"nombre.*vulnerabilidad|^vulnerabilidad$": "nombre_vulnerabilidad",
    r"^descripci[oó]n$|descripci[oó]n.*vulnerabilidad": "descripcion",
    r"posible.*soluci[oó]n|soluci[oó]n": "posible_solucion",

    # CVE / explotación
    r"c[oó]digo.*cve|identificador.*cve|^cve$": "cve",
    r"explotaci[oó]n.*activa|explotaci[oó]n$":  "explotacion_activa",
    r"criticidad.*t[eé]cnica|criticidad$":       "criticidad",

    # Red / activo
    r"direcci[oó]n.*ip|^ip$":          "ip",
    r"tipo.*activo":                    "tipo_activo",
    r"funcionalidad":                   "funcionalidad",
    r"nombre.*activo|^activo$":        "nombre_activo",
    r"sistema.*operativo|^so$":        "sistema_operativo",
    r"aplicaci[oó]n|^app$":            "aplicacion",

    # Puerto / protocolo
    r"^puerto$|^port$":                "puerto",
    r"^protocolo$|^protocol$":         "protocolo",

    # CVSS
    r"cvss.*score|^cvss$|^score$":     "cvss_score",

    # Malware / estado
    r"explotado.*malware|malware":     "explotado_malware",
    r"estado.*vulnerabilidad|^estado$": "estado",
}

DATE_FIELDS = {"fecha_escaneo"}


def _normalize(col: str) -> str:
    return str(col).strip().lower()


def _map_columns(df_columns: list) -> dict:
    """Retorna {columna_excel: campo_interno}. Primer match gana."""
    mapping: dict[str, str] = {}
    used_fields: set[str] = set()
    for col in df_columns:
        col_norm = _normalize(col)
        for pattern, field in COLUMN_MAP.items():
            if re.search(pattern, col_norm) and field not in used_fields:
                mapping[col] = field
                used_fields.add(field)
                break
    return mapping


def _parse_date(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    s = str(value).strip()
    if not s or s.lower() in ("nan", "none", "nat", ""):
        return None
    formats = [
        "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M",
        "%d/%m/%Y %H:%M", "%d/%m/%Y",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _clean(value) -> str | None:
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    s = str(value).strip()
    return s if s and s.lower() not in ("nan", "none", "nat") else None


def _bool_clean(value) -> str:
    """Normaliza VERDADERO/FALSO/TRUE/FALSE a 'Sí' / 'No'."""
    s = str(value).strip().lower()
    if s in ("verdadero", "true", "1", "sí", "si"):
        return "Sí"
    if s in ("falso", "false", "0", "no"):
        return "No"
    return _clean(value) or "No"


TARGET_SHEET = "CUADRO DE MANDO WEXLER"

# Palabras clave que identifican la fila real de encabezados
HEADER_KEYWORDS = {
    "id", "periodo", "grupo", "plugin", "fecha", "fuente", "sinopsis",
    "vulnerabilidad", "descripcion", "descripción", "solucion", "solución",
    "cve", "criticidad", "ip", "activo", "puerto", "protocolo", "cvss", "estado"
}


def _is_header_like(row: pd.Series) -> bool:
    vals = [str(v).strip() for v in row if str(v).strip()]
    if not vals:
        return False
    numeric_count = sum(
        1 for v in vals
        if v.replace(".", "").replace("-", "").replace("/", "").isdigit()
    )
    return numeric_count < len(vals) * 0.5


def _find_header_row(df: pd.DataFrame) -> int:
    """
    Busca el índice de la fila que contiene los encabezados reales.
    Salta filas decorativas (título, logo, etc.) que aparecen antes.
    Retorna el índice de la primera fila que coincida con HEADER_KEYWORDS.
    """
    for i, row in df.iterrows():
        vals = [str(v).strip().lower() for v in row if str(v).strip()]
        matches = sum(1 for v in vals if any(kw in v for kw in HEADER_KEYWORDS))
        if matches >= 2:
            return int(i)
    return 0  # fallback: usar la primera fila


def _read_all_sheets(file_path: str) -> tuple[pd.DataFrame | None, str | None]:
    try:
        sheets: dict = pd.read_excel(file_path, dtype=str, header=None, sheet_name=None)
    except Exception as e:
        return None, f"No se pudo leer el archivo: {e}"

    # Buscar la hoja objetivo (insensible a mayúsculas/espacios)
    target_df = None
    for sheet_name, df_sheet in sheets.items():
        if sheet_name.strip().upper() == TARGET_SHEET.upper():
            target_df = df_sheet
            print(f"  [OK] Hoja encontrada: '{sheet_name}'")
            break

    if target_df is None:
        hojas = list(sheets.keys())
        return None, (
            f"No se encontró la hoja '{TARGET_SHEET}'.\n"
            f"Hojas disponibles: {hojas}"
        )

    df_sheet = target_df.dropna(how="all").reset_index(drop=True)
    if df_sheet.empty:
        return None, f"La hoja '{TARGET_SHEET}' está vacía."

    # Detectar fila de encabezado real (saltar filas decorativas)
    header_idx = _find_header_row(df_sheet)
    header_row = df_sheet.iloc[header_idx].fillna("")

    # Verificar si la fila siguiente también es encabezado (doble encabezado)
    if header_idx + 1 < len(df_sheet):
        next_row = df_sheet.iloc[header_idx + 1].fillna("")
        if _is_header_like(next_row):
            combined = []
            for c0, c1 in zip(header_row, next_row):
                c0s, c1s = str(c0).strip(), str(c1).strip()
                if c0s and not c0s.startswith("Unnamed"):
                    combined.append(c0s)
                elif c1s and not c1s.startswith("Unnamed"):
                    combined.append(c1s)
                else:
                    combined.append(c0s or c1s or "")
            df_sheet.columns = combined
            df_sheet = df_sheet.iloc[header_idx + 2:].reset_index(drop=True)
        else:
            df_sheet.columns = [str(c).strip() for c in header_row]
            df_sheet = df_sheet.iloc[header_idx + 1:].reset_index(drop=True)
    else:
        df_sheet.columns = [str(c).strip() for c in header_row]
        df_sheet = df_sheet.iloc[header_idx + 1:].reset_index(drop=True)

    df_sheet = df_sheet.dropna(how="all")

    if df_sheet.empty:
        return None, "La hoja no tiene filas de datos después del encabezado."

    return df_sheet, None


def parse_excel(file_path: str) -> tuple[list[dict], list[str]]:
    """
    Lee el Excel y retorna (vulnerabilidades, errores).

    Cada vulnerabilidad es un dict con los campos normalizados.
    Agrupa por (ip, grupos) en el dict de retorno para uso posterior.
    """
    df, read_error = _read_all_sheets(file_path)
    if read_error:
        return [], [read_error]

    col_mapping = _map_columns(list(df.columns))
    if not col_mapping:
        return [], [
            "No se reconocieron columnas válidas. "
            "Verifique que la primera fila tenga los encabezados correctos."
        ]

    vulnerabilidades: list[dict] = []
    errors: list[str] = []

    for idx, row in df.iterrows():
        row_num = int(idx) + 2
        try:
            record: dict = {}
            for excel_col, field in col_mapping.items():
                raw = row.get(excel_col)
                if field in DATE_FIELDS:
                    record[field] = _parse_date(raw)
                elif field in ("explotacion_activa", "explotado_malware"):
                    record[field] = _bool_clean(raw) if raw is not None else "No"
                else:
                    record[field] = _clean(raw)

            # Descartar filas vacías
            if not any(v for v in record.values() if v not in (None, "")):
                continue

            vulnerabilidades.append(record)
        except Exception as e:
            errors.append(f"Fila {row_num}: {e}")

    return vulnerabilidades, errors


def agrupar_por_ip_proyecto(vulnerabilidades: list[dict]) -> dict:
    """
    Retorna un dict anidado:
    {
      (ip, grupos): [vuln1, vuln2, ...],
      ...
    }
    """
    grupos: dict[tuple, list] = {}
    for vuln in vulnerabilidades:
        ip      = vuln.get("ip") or "Sin IP"
        proyecto = vuln.get("grupos") or "Sin Proyecto"
        key = (ip, proyecto)
        grupos.setdefault(key, []).append(vuln)
    return grupos
