"""
Módulo de análisis con Groq LLM.
Recibe un grupo de vulnerabilidades (misma IP + proyecto + severidad) y retorna
un plan de remediación enriquecido como lista de dicts.

Estrategia de optimización de tokens (reducción ~94%):
  - Cache 3 niveles: plugin_id (primario) > cve (secundario) > nombre normalizado (fallback)
  - Pre-deduplicación: de N registros extrae solo los M únicos (164 vs 2645)
  - Groq solo procesa vulnerabilidades únicas; el plan se re-aplica a todos los hosts iguales
  - MAX_CHUNK = 3 (3 vulns únicas por llamada, max_tokens adaptativo)
  - Retry automático en 429 / rate limit con backoff
  - Rate limiting de 1.5s entre chunks (~2400 tokens/min por key, bajo el límite de 6000 TPM)
"""
import json
import re
import time
from groq import Groq
from config import GROQ_KEYS_BY_SEVERITY, GROQ_MODEL

# ── Clientes Groq por severidad ───────────────────────────────────────────────
_clients: dict[str, Groq] = {
    sev: Groq(api_key=key)
    for sev, key in GROQ_KEYS_BY_SEVERITY.items()
}


def _get_client(severidad: str) -> Groq:
    return _clients.get(severidad.lower(), _clients["medium"])


# ── Cache de 3 niveles ────────────────────────────────────────────────────────
_cache_plugin: dict[str, dict] = {}   # plugin_id   → plan
_cache_cve:    dict[str, dict] = {}   # cve         → plan
_cache_nombre: dict[str, dict] = {}   # nombre norm → plan

MAX_CHUNK  = 3      # vulns únicas por llamada a Groq
# 6000 TPM ÷ ~3150 tokens/req (450 input + 2700 max_output) = ~1.9 req/min → 32s mínimo
RATE_SLEEP = 32.0   # segundos entre chunks — evita rate limit sin necesidad de retries


# ── JSON tolerante a escapes inválidos ───────────────────────────────────────

def _safe_json_loads(raw: str):
    """json.loads con múltiples fallbacks para reparar JSON malformado de LLMs."""
    # Intento 1: parse directo
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Intento 2: reparar escapes inválidos (\e, \s, \p, etc.)
    try:
        fixed = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw)
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass

    # Intento 3: extraer solo el array JSON con regex y reparar escapes
    try:
        match = re.search(r'\[.*\]', raw, re.DOTALL)
        if match:
            fragment = match.group(0)
            fragment = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', fragment)
            return json.loads(fragment)
    except json.JSONDecodeError:
        pass

    # Intento 4: eliminar todos los backslashes problemáticos
    try:
        cleaned = re.sub(r'\\(?!["\\/nrtbfu])', '', raw)
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Sin más opciones: relanzar para que el caller use _plan_basico
    raise ValueError(f"No se pudo reparar el JSON de Groq (primeros 200 chars): {raw[:200]}")


# ── Helpers de cache ──────────────────────────────────────────────────────────

def _cache_key(vuln: dict) -> tuple[str, str]:
    """Retorna (tipo, valor) del mejor identificador disponible."""
    if pid := vuln.get("plugin_id"):
        return ("plugin", str(pid).strip())
    cve = vuln.get("cve") or ""
    if cve and cve.upper() not in ("N/A", "NONE", ""):
        return ("cve", cve.strip())
    nombre = (vuln.get("nombre_vulnerabilidad") or "").strip().lower()
    return ("nombre", nombre)


def _lookup_cache(vuln: dict) -> dict | None:
    tipo, val = _cache_key(vuln)
    if tipo == "plugin":
        return _cache_plugin.get(val)
    if tipo == "cve":
        return _cache_cve.get(val)
    return _cache_nombre.get(val)


def _save_cache(vuln: dict, plan: dict):
    pid    = vuln.get("plugin_id")
    cve    = vuln.get("cve") or ""
    nombre = (vuln.get("nombre_vulnerabilidad") or "").strip().lower()
    if pid:
        _cache_plugin[str(pid).strip()] = plan
    if cve and cve.upper() not in ("N/A", "NONE", ""):
        _cache_cve[cve] = plan
    if nombre:
        _cache_nombre[nombre] = plan


# ── Prompt ────────────────────────────────────────────────────────────────────

def _build_prompt(vulnerabilidades: list[dict], severidad: str) -> str:
    nivel_label = {
        "critical": "CRÍTICA", "high": "ALTA",
        "medium": "MEDIA", "low": "BAJA",
    }.get(severidad.lower(), "MEDIA")

    vulns_text = ""
    for i, v in enumerate(vulnerabilidades, 1):
        so = v.get("sistema_operativo", "N/A")
        vulns_text += (
            f"{i}. {v.get('nombre_vulnerabilidad','N/A')} | "
            f"CVE:{v.get('cve','N/A')} | CVSS:{v.get('cvss_score','N/A')} | "
            f"Nivel:{nivel_label} | Explotacion:{v.get('explotacion_activa','No')} | "
            f"SO:{so} | Puerto:{v.get('puerto','N/A')} | "
            f"Solucion: {v.get('posible_solucion','N/A')}\n"
        )

    so_ref = vulnerabilidades[0].get("sistema_operativo", "Windows") if vulnerabilidades else "Windows"

    return (
        f"Experto ciberseguridad. TODO en español. Nivel:{nivel_label} SO:{so_ref}\n"
        f"Vulnerabilidades:\n{vulns_text}\n"
        f"Responde SOLO JSON array {len(vulnerabilidades)} objetos, sin markdown:\n"
        f'[{{"nombre_vulnerabilidad":"...","descripcion_enriquecida":"4 oraciones: origen tecnico, '
        f'como afecta al SO, que logra el atacante, impacto CIA","impacto":"consecuencia concreta: '
        f'RCE/fuga datos/escalada privilegios/movimiento lateral — sistemas afectados",'
        f'"solucion_detallada":"comandos exactos para {so_ref} con version de parche",'
        f'"objetivo":"objetivo medible en 1 oracion",'
        f'"tareas":["Paso 1: inventariar hosts afectados","Paso 2: crear backup/snapshot",'
        f'"Paso 3: obtener parche oficial","Paso 4: aplicar parche con comando exacto",'
        f'"Paso 5: ajustar config de seguridad post-parche","Paso 6: reiniciar servicio afectado",'
        f'"Paso 7: verificar version/config activa","Paso 8: prueba funcional del servicio",'
        f'"Paso 9: escaneo validacion Nessus/Tenable","Paso 10: documentar en ITSM"],'
        f'"prioridad":"Critica|Alta|Media|Baja","tiempo_estimado":"Xh",'
        f'"responsable_sugerido":"Equipo X"}}]'
    )


# ── Llamada a Groq con retry ──────────────────────────────────────────────────

def _llamar_con_retry(client: Groq, prompt: str, max_tokens: int,
                      nivel: str, max_retries: int = 3) -> str:
    for intento in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=max_tokens,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            msg = str(e)
            if "429" in msg or "rate_limit" in msg.lower() or "413" in msg:
                wait = 60 * (intento + 1)
                print(f"    [RateLimit-{nivel}] Intento {intento+1}/{max_retries} — esperando {wait}s...")
                time.sleep(wait)
            else:
                raise
    raise RuntimeError(f"Groq: agotados {max_retries} reintentos para nivel {nivel}")


# ── Procesamiento de únicos ───────────────────────────────────────────────────

def _procesar_unicos(unicos: list[tuple[str, dict]],
                     severidad: str) -> dict[str, dict]:
    """
    Recibe lista de (clave_cache, vuln_representante) únicos.
    Llama a Groq en chunks de MAX_CHUNK.
    Retorna {clave_cache: plan_enriquecido}.
    """
    resultado: dict[str, dict] = {}
    nivel = severidad.upper()
    client = _get_client(severidad)
    total = len(unicos)
    total_chunks = (total + MAX_CHUNK - 1) // MAX_CHUNK

    for inicio in range(0, total, MAX_CHUNK):
        chunk = unicos[inicio: inicio + MAX_CHUNK]
        claves_chunk  = [c for c, _ in chunk]
        vulns_chunk   = [v for _, v in chunk]
        num_chunk = inicio // MAX_CHUNK + 1

        if total_chunks > 1:
            print(f"    [Groq-{nivel}] Chunk {num_chunk}/{total_chunks} ({len(vulns_chunk)} vulns únicas)...")

        # max_tokens adaptativo: 900 por vuln, máx 2700
        max_tok = min(900 * len(vulns_chunk), 2700)
        prompt  = _build_prompt(vulns_chunk, severidad)

        try:
            raw = _llamar_con_retry(client, prompt, max_tok, nivel)
            raw = re.sub(r"^```(?:json)?", "", raw).rstrip("`").strip()
            planes = _safe_json_loads(raw)
            if not isinstance(planes, list):
                raise ValueError("Respuesta no es JSON array")

            for (clave, vuln), plan in zip(chunk, planes):
                tareas = plan.get("tareas") or []
                if len(tareas) < 10:
                    tareas = _completar_tareas(tareas, vuln)
                plan["tareas"] = tareas[:10]
                _save_cache(vuln, plan)
                resultado[clave] = plan

        except Exception as e:
            print(f"    [WARN] Chunk {num_chunk} falló ({nivel}): {e}. Usando plan básico.")
            for clave, vuln in chunk:
                plan = _plan_basico(vuln)
                resultado[clave] = plan

        time.sleep(RATE_SLEEP)

    return resultado


# ── Función principal ─────────────────────────────────────────────────────────

def analizar_grupo(ip: str, proyecto: str, vulnerabilidades: list[dict],
                   severidad: str = "medium") -> list[dict]:
    """
    Retorna lista de planes enriquecidos para el grupo (ip, proyecto, severidad).

    Optimización:
      1. Consulta cache por plugin_id / cve / nombre
      2. De los pendientes extrae solo los M únicos (M << N)
      3. Llama a Groq solo por los únicos (chunks de MAX_CHUNK)
      4. Re-aplica el plan de cada único a todos los registros que lo comparten
    """
    nivel = severidad.upper()

    resultado: list[dict | None] = [None] * len(vulnerabilidades)
    pendientes: list[tuple[int, dict]] = []

    # ── Paso 1: resolver desde cache ─────────────────────────────────────────
    hits = 0
    for i, vuln in enumerate(vulnerabilidades):
        plan = _lookup_cache(vuln)
        if plan:
            resultado[i] = {**vuln, **plan}
            hits += 1
        else:
            pendientes.append((i, vuln))

    if hits:
        print(f"    [Cache] {hits}/{len(vulnerabilidades)} vuln(s) resueltas desde cache.")

    if not pendientes:
        return resultado  # type: ignore

    # ── Paso 2: deduplicar pendientes ─────────────────────────────────────────
    unicos: dict[str, tuple[int, dict]] = {}  # clave → (primer_idx, vuln)
    for idx, vuln in pendientes:
        tipo, val = _cache_key(vuln)
        clave = f"{tipo}:{val}"
        if clave not in unicos:
            unicos[clave] = (idx, vuln)

    total_pend  = len(pendientes)
    total_unico = len(unicos)
    ahorro = total_pend - total_unico
    print(f"    [Groq-{nivel}] {total_pend} pendientes → {total_unico} únicos "
          f"({ahorro} llamadas ahorradas, key {nivel}).")

    # ── Paso 3: llamar Groq solo por los únicos ───────────────────────────────
    lista_unicos = [(clave, vuln) for clave, (_, vuln) in unicos.items()]
    planes_unicos = _procesar_unicos(lista_unicos, severidad)

    # ── Paso 4: re-aplicar a todos los pendientes ─────────────────────────────
    for idx, vuln in pendientes:
        tipo, val = _cache_key(vuln)
        clave = f"{tipo}:{val}"
        plan = planes_unicos.get(clave) or _plan_basico(vuln)
        resultado[idx] = {**vuln, **plan}

    return resultado  # type: ignore


# ── Helpers ───────────────────────────────────────────────────────────────────

def _completar_tareas(tareas: list, vuln: dict) -> list:
    """Rellena hasta 10 pasos si Groq devolvió menos."""
    nombre   = vuln.get("nombre_vulnerabilidad", "la vulnerabilidad")
    solucion = vuln.get("posible_solucion", "aplicar el parche correspondiente")
    plantilla = [
        f"Paso 1: Identificar y listar todos los hosts afectados por {nombre}.",
        f"Paso 2: Crear respaldo/snapshot del sistema antes de realizar cambios.",
        f"Paso 3: Obtener el parche o actualización oficial del fabricante.",
        f"Paso 4: Aplicar la solución: {solucion}.",
        f"Paso 5: Ajustar configuraciones de seguridad adicionales post-remediación.",
        f"Paso 6: Reiniciar los servicios afectados para aplicar los cambios.",
        f"Paso 7: Verificar que la versión o configuración corregida esté activa.",
        f"Paso 8: Realizar pruebas funcionales para confirmar operación normal.",
        f"Paso 9: Ejecutar escaneo de validación con Nessus/Tenable para confirmar cierre.",
        f"Paso 10: Registrar el cambio en el sistema ITSM y actualizar el inventario.",
    ]
    for i, paso in enumerate(plantilla):
        if i >= len(tareas):
            tareas.append(paso)
    return tareas


def _plan_basico(v: dict) -> dict:
    nombre   = v.get("nombre_vulnerabilidad", "vulnerabilidad detectada")
    solucion = v.get("posible_solucion", "Ver documentación del fabricante")
    return {
        **v,
        "descripcion_enriquecida": (
            v.get("descripcion") or
            f"{nombre} fue detectada en el activo {v.get('ip','N/A')}. "
            f"Puede comprometer la confidencialidad, integridad o disponibilidad del sistema."
        ),
        "impacto": (
            f"Explotación de {nombre} puede resultar en acceso no autorizado, "
            f"fuga de información o interrupción del servicio."
        ),
        "solucion_detallada": solucion,
        "objetivo": (
            f"Eliminar el riesgo de {nombre} y verificar cierre con escaneo Tenable."
        ),
        "tareas": _completar_tareas([], v),
        "prioridad": v.get("criticidad", "Media"),
        "tiempo_estimado": "A definir con el equipo responsable",
        "responsable_sugerido": "Equipo de Infraestructura y Seguridad",
    }
