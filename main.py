"""
Punto de entrada del sistema de procesamiento de vulnerabilidades.

Flujo:
  1. Lee todos los .xlsx de la carpeta input/
  2. Parsea y agrupa por (IP, Proyecto, Severidad)  ← cada nivel = doc propio
  3. Llama a Groq para enriquecer cada grupo (cache CVE + rate limiting)
  4. Genera .docx dentro de output/{severidad}/{ip_proyecto}/
  5. Mueve el Excel a processed/

Uso:
  python main.py
"""
import os
import sys
import shutil
import argparse

# Forzar UTF-8 en la consola de Windows
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from config import INPUT_DIR, OUTPUT_DIR, DONE_DIR
from parser import parse_excel, agrupar_por_ip_proyecto
from groq_analyzer import analizar_grupo
from docx_generator import generar_docx_por_grupo

# ── Severidad ──────────────────────────────────────────────────────────────────
SEVERIDADES = ["critical", "high", "medium", "low"]

_CRITICIDAD_MAP = {
    # Critical
    "critica": "critical", "crítica": "critical", "critical": "critical",
    "critico": "critical", "crítico": "critical",
    # High
    "alta": "high", "alto": "high", "high": "high",
    # Medium
    "media": "medium", "medio": "medium", "medium": "medium", "moderate": "medium",
    # Low
    "baja": "low", "bajo": "low", "low": "low",
    "informational": "low", "info": "low",
}


def _normalizar_severidad(criticidad: str | None) -> str:
    if not criticidad:
        return "low"
    return _CRITICIDAD_MAP.get(criticidad.strip().lower(), "low")


def _expandir_por_severidad(grupos: dict) -> list[tuple]:
    """
    Recibe {(ip, proyecto): [vulns]} y retorna una lista de:
      (ip, proyecto, severidad, [vulns_de_esa_severidad])

    Cada IP/Proyecto genera UN documento por nivel de severidad presente,
    garantizando que todas las vulns en un doc tengan el mismo nivel.
    """
    resultado = []
    for (ip, proyecto), vulns in grupos.items():
        por_sev: dict[str, list] = {}
        for vuln in vulns:
            sev = _normalizar_severidad(vuln.get("criticidad"))
            por_sev.setdefault(sev, []).append(vuln)
        # Ordenar de mayor a menor criticidad
        for sev in SEVERIDADES:
            if sev in por_sev:
                resultado.append((ip, proyecto, sev, por_sev[sev]))
    return resultado


def _dedup_vulns(vulns: list[dict]) -> list[dict]:
    """
    Elimina registros duplicados: mismo ip + nombre_activo + plugin_id (o nombre_vulnerabilidad).
    Activos con el mismo nombre pero diferente IP se tratan como activos distintos.
    """
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


def _preparar_carpetas():
    for d in (INPUT_DIR, DONE_DIR):
        os.makedirs(d, exist_ok=True)
    for sev in SEVERIDADES:
        os.makedirs(os.path.join(OUTPUT_DIR, sev), exist_ok=True)


def _nombre_carpeta(ip: str, proyecto: str) -> str:
    raw = f"{ip}_{proyecto}"
    for ch in (" ", "/", ":", "*", "?", '"', "<", ">", "|", "\n", "\r", "\t"):
        raw = raw.replace(ch, "-")
    return raw


def _nombre_docx(ip: str, proyecto: str, severidad: str) -> str:
    safe = _nombre_carpeta(ip, proyecto)
    return f"Plan_Remediacion_{safe}_{severidad.upper()}.docx"


def procesar_archivo(excel_path: str):
    print(f"\n{'='*60}")
    print(f"  Procesando: {os.path.basename(excel_path)}")
    print(f"{'='*60}")

    # ── 1. Parseo ──────────────────────────────────────────────────────────────
    print("  [1/4] Parseando Excel...")
    vulnerabilidades, errores = parse_excel(excel_path)

    if errores:
        for e in errores:
            print(f"  [WARN] {e}")

    if not vulnerabilidades:
        print("  [ERROR] No se encontraron vulnerabilidades. Abortando.")
        return

    total_raw = len(vulnerabilidades)
    vulnerabilidades = _dedup_vulns(vulnerabilidades)
    eliminados = total_raw - len(vulnerabilidades)
    print(f"  [OK] {total_raw} registros → {len(vulnerabilidades)} únicos "
          f"({eliminados} duplicados eliminados por IP+activo+plugin).")

    # ── 2. Agrupación por IP + Proyecto + Severidad ────────────────────────────
    grupos_base = agrupar_por_ip_proyecto(vulnerabilidades)
    grupos_expandidos = _expandir_por_severidad(grupos_base)

    # Distribución por severidad
    conteo_sev: dict[str, int] = {s: 0 for s in SEVERIDADES}
    for _, _, sev, _ in grupos_expandidos:
        conteo_sev[sev] += 1

    print(f"  [OK] {len(grupos_base)} activos → {len(grupos_expandidos)} documentos a generar.")
    print(f"  [OK] Distribución: " + " | ".join(
        f"{s.upper()}:{conteo_sev[s]}" for s in SEVERIDADES
    ))

    # ── 3. Analizar → Generar docx ────────────────────────────────────────────
    total = len(grupos_expandidos)
    for idx, (ip, proyecto, severidad, vulns) in enumerate(grupos_expandidos, 1):
        carpeta_nombre = _nombre_carpeta(ip, proyecto)
        docx_nombre    = _nombre_docx(ip, proyecto, severidad)
        output_path    = os.path.join(OUTPUT_DIR, severidad, carpeta_nombre, docx_nombre)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        print(f"\n  [{idx}/{total}] [{severidad.upper()}] {ip} | {proyecto} ({len(vulns)} vulns)")

        # Análisis LLM — usa la API key dedicada al nivel de severidad
        print(f"    [Groq] Analizando con key de nivel {severidad.upper()}...")
        vulns_enriquecidas = analizar_grupo(ip, proyecto, vulns, severidad)

        # Generar .docx
        generar_docx_por_grupo(ip, proyecto, vulns_enriquecidas, output_path)
        print(f"    [OK] Guardado en: {output_path}")

    # ── 4. Mover Excel a processed/ ───────────────────────────────────────────
    done_path = os.path.join(DONE_DIR, os.path.basename(excel_path))
    shutil.move(excel_path, done_path)
    print(f"\n  [OK] Excel movido a: processed/")
    print(f"  [OK] Documentos en: output/{{critical|high|medium|low}}/")


def main():
    _preparar_carpetas()

    excels = [
        os.path.join(INPUT_DIR, f)
        for f in os.listdir(INPUT_DIR)
        if f.lower().endswith((".xlsx", ".xls"))
    ]

    if not excels:
        print(f"\n[INFO] No hay archivos Excel en: {INPUT_DIR}")
        print(f"       Pon tu .xlsx ahí y vuelve a ejecutar.\n")
        return

    print(f"\n[INFO] {len(excels)} archivo(s) encontrado(s) en input/")

    for excel_path in excels:
        try:
            procesar_archivo(excel_path)
        except Exception as e:
            print(f"  [ERROR] Fallo al procesar {excel_path}: {e}")

    print("\n[DONE] Proceso completado.\n")


if __name__ == "__main__":
    main()
