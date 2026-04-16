"""
Script de prueba con 5 vulnerabilidades REALES extraídas del Excel de Fiduprevisora.
  - 2 Críticas  (SSL v2/v3 en HP-UX | Oracle WebLogic RCE en Solaris)
  - 2 Altas     (SWEET32 SSL en Windows | SMBv1 Multiple Vulns en Windows 2003)
  - 1 Media     (SMB Signing not required en Windows)

Cada grupo usa su propia Groq API key según el nivel de criticidad.
Uso: python test_5vulns.py
"""
import os
import sys

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from groq_analyzer import analizar_grupo
from docx_generator import generar_docx_por_grupo
from config import OUTPUT_DIR

# ── 5 Vulnerabilidades reales del Excel ───────────────────────────────────────
VULNS_TEST = [
    # ── CRÍTICA 1 — SSL v2/v3 en HP-UX ───────────────────────────────────────
    {
        "id": "66",
        "periodo": "Enero--2026",
        "grupos": "RED-SRV-DB-CORE-PRD",
        "plugin_id": "20007",
        "fuente": "Tenable",
        "sinopsis": "SSL Version 2 and 3 Protocol Detection",
        "nombre_vulnerabilidad": "SSL Version 2 and 3 Protocol Detection — Protocolo con debilidades conocidas",
        "descripcion": "El servicio remoto acepta conexiones cifradas con SSL 2.0 o SSL 3.0, protocolos con debilidades criptográficas conocidas.",
        "posible_solucion": "Deshabilitar SSL 2.0 y 3.0 en la configuración de la aplicación. Usar TLS 1.2 (con suites de cifrado aprobadas) o superior.",
        "cve": None,
        "explotacion_activa": "No",
        "criticidad": "Critical",
        "ip": "10.10.1.50",
        "tipo_activo": None,
        "nombre_activo": None,
        "sistema_operativo": "HP-UX",
        "aplicacion": "Service detection",
        "puerto": "5989",
        "protocolo": "TCP",
        "cvss_score": "10.0",
        "explotado_malware": "No",
        "estado": "New",
    },
    # ── CRÍTICA 2 — Oracle WebLogic RCE en Solaris ────────────────────────────
    {
        "id": "930",
        "periodo": "Enero--2026",
        "grupos": "RED-SRV-FIDU-PRD",
        "plugin_id": "109429",
        "fuente": "Tenable",
        "sinopsis": "Oracle WebLogic Server Deserialization RCE (CVE-2018-2628)",
        "nombre_vulnerabilidad": "Oracle WebLogic Server — Ejecución Remota de Código por Deserialización",
        "descripcion": "El servidor Oracle WebLogic remoto está afectado por una vulnerabilidad de ejecución remota de código mediante deserialización insegura de objetos Java en el puerto de administración T3.",
        "posible_solucion": "Aplicar el parche del Oracle Critical Patch Update de abril 2018 según el advisory oficial. Nota: el parche inicial para CVE-2018-2628 es incompleto; consultar Oracle para mitigaciones adicionales.",
        "cve": "CVE-2018-2628",
        "explotacion_activa": "Sí",
        "criticidad": "Critical",
        "ip": "172.16.0.154",
        "tipo_activo": "general-purpose",
        "funcionalidad": "APLICACION - WEB-APP PEOPLESOFT",
        "nombre_activo": "HOLANDA",
        "sistema_operativo": "Solaris 11 (sun4v)",
        "aplicacion": "Web Servers",
        "puerto": "8300",
        "protocolo": "TCP",
        "cvss_score": "9.8",
        "explotado_malware": "Sí",
        "estado": "Active",
    },
    # ── ALTA 1 — SWEET32 SSL en Windows ──────────────────────────────────────
    {
        "id": "7",
        "periodo": "Enero--2026",
        "grupos": "RED-SRV-DB-CORE-PRD",
        "plugin_id": "42873",
        "fuente": "Tenable",
        "sinopsis": "SSL Medium Strength Cipher Suites Supported (SWEET32)",
        "nombre_vulnerabilidad": "SSL/TLS — Cipher Suites de Fuerza Media Soportados (SWEET32)",
        "descripcion": "El host remoto soporta suites de cifrado SSL de fortaleza media, incluyendo cifrados de 64 bits como 3DES vulnerables al ataque SWEET32.",
        "posible_solucion": "Reconfigurar la aplicación afectada para evitar el uso de cifrados de fuerza media. Deshabilitar 3DES y RC4 en la configuración TLS.",
        "cve": "CVE-2016-2183",
        "explotacion_activa": "No",
        "criticidad": "High",
        "ip": "10.10.1.100",
        "tipo_activo": "general-purpose",
        "funcionalidad": "fpfomagap",
        "nombre_activo": "DORIEN",
        "sistema_operativo": "Microsoft Windows",
        "aplicacion": "General",
        "puerto": "3389",
        "protocolo": "TCP",
        "cvss_score": "7.5",
        "explotado_malware": "No",
        "estado": "New",
    },
    # ── ALTA 2 — SMBv1 múltiples vulns en Windows Server 2003 ────────────────
    {
        "id": "2085",
        "periodo": "Enero--2026",
        "grupos": "RED-SRV-FIDU-PRD",
        "plugin_id": "100464",
        "fuente": "Tenable",
        "sinopsis": "Microsoft Windows SMBv1 Multiple Vulnerabilities",
        "nombre_vulnerabilidad": "Microsoft Windows SMBv1 — Múltiples Vulnerabilidades (EternalBlue family)",
        "descripcion": "El host Windows remoto tiene Microsoft Server Message Block 1.0 (SMBv1) habilitado y es vulnerable a múltiples vulnerabilidades críticas incluyendo la familia EternalBlue.",
        "posible_solucion": (
            "Aplicar la actualización de seguridad según la versión de Windows:\n"
            "- Windows Server 2008: KB4018466\n"
            "- Windows 7 / Server 2008 R2: KB4019264\n"
            "- Windows 8.1 / Server 2012 R2: KB4019215\n"
            "- Windows 10: KB4019474\n"
            "- Windows Server 2016: KB4019472"
        ),
        "cve": "CVE-2017-0267",
        "explotacion_activa": "No",
        "criticidad": "High",
        "ip": "172.16.0.52",
        "tipo_activo": "general-purpose",
        "nombre_activo": "PLUTON",
        "sistema_operativo": "Microsoft Windows Server 2003 Service Pack 2",
        "aplicacion": "Windows",
        "puerto": "445",
        "protocolo": "TCP",
        "cvss_score": "9.3",
        "explotado_malware": "No",
        "estado": "Active",
    },
    # ── MEDIA 1 — SMB Signing not required en Windows ─────────────────────────
    {
        "id": "2",
        "periodo": "Enero--2026",
        "grupos": "RED-SRV-DB-CORE-PRD",
        "plugin_id": "57608",
        "fuente": "Tenable",
        "sinopsis": "SMB Signing not required",
        "nombre_vulnerabilidad": "SMB Signing — Firma de Mensajes No Requerida (Man-in-the-Middle)",
        "descripcion": "La firma de mensajes no es requerida en el servidor SMB remoto. Un atacante no autenticado puede explotar esto para realizar ataques de hombre en el medio (MITM) contra el servidor SMB.",
        "posible_solucion": (
            "Habilitar la firma de mensajes SMB en la configuración del host. "
            "En Windows: política 'Microsoft network server: Digitally sign communications (always)'. "
            "En Samba: parámetro 'server signing = mandatory' en smb.conf."
        ),
        "cve": None,
        "explotacion_activa": "Sí",
        "criticidad": "Medium",
        "ip": "10.10.1.100",
        "tipo_activo": "general-purpose",
        "funcionalidad": "fpfomagap",
        "nombre_activo": "DORIEN",
        "sistema_operativo": "Microsoft Windows",
        "aplicacion": "Misc.",
        "puerto": "445",
        "protocolo": "TCP",
        "cvss_score": "5.0",
        "explotado_malware": "No",
        "estado": "New",
    },
]

# ── Mapa criticidad → severidad interna ──────────────────────────────────────
_SEV_MAP = {
    "critical": "critical", "critica": "critical", "crítica": "critical",
    "high": "high", "alta": "high",
    "medium": "medium", "media": "medium",
    "low": "low", "baja": "low",
}

# ── Agrupar por (IP, Proyecto, Severidad) ────────────────────────────────────
grupos: dict[tuple, list] = {}
for v in VULNS_TEST:
    sev = _SEV_MAP.get((v.get("criticidad") or "").lower().strip(), "medium")
    key = (v["ip"], v["grupos"], sev)
    grupos.setdefault(key, []).append(v)


def main():
    print("\n" + "=" * 65)
    print("  PRUEBA REAL — 5 vulns de Fiduprevisora Q1-2026")
    print("  2 Críticas | 2 Altas | 1 Media")
    print("  Cada nivel usa su propia Groq API key")
    print("=" * 65)

    for (ip, proyecto, severidad), vulns in grupos.items():
        print(f"\n[{severidad.upper()}] IP:{ip} | {proyecto} | {len(vulns)} vuln(s)")

        # Análisis con Groq usando la key del nivel correspondiente
        try:
            vulns_enriquecidas = analizar_grupo(ip, proyecto, vulns, severidad)
        except Exception as e:
            print(f"  [ERROR] Groq falló: {e}")
            continue

        # Validar 10 pasos por vulnerabilidad
        for v in vulns_enriquecidas:
            pasos = v.get("tareas") or []
            nombre = v.get("nombre_vulnerabilidad", "?")[:60]
            estado_pasos = "OK" if len(pasos) == 10 else f"WARN ({len(pasos)} pasos)"
            print(f"  [{estado_pasos}] {nombre}")

        # Generar .docx
        carpeta = f"{ip}_{proyecto}".replace(" ", "_").replace("/", "-")
        docx_dir = os.path.join(OUTPUT_DIR, severidad, carpeta)
        os.makedirs(docx_dir, exist_ok=True)
        docx_path = os.path.join(docx_dir, f"TEST4_{carpeta}_{severidad.upper()}.docx")

        generar_docx_por_grupo(ip, proyecto, vulns_enriquecidas, docx_path)
        print(f"  [DOC] output/{severidad}/{carpeta}/TEST_...{severidad.upper()}.docx")

    print("\n[DONE] Prueba completada. Revisa la carpeta output/\n")


if __name__ == "__main__":
    main()
