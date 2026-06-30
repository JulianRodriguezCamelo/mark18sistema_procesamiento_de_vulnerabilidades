"use client"

import { useState, useEffect, useRef, useCallback, memo } from "react"
import { Progress } from "@/components/ui/progress"
import {
  Shield, LogOut, Upload, FileSpreadsheet, FolderOpen, Clock,
  FileText, CheckCircle2, Loader2, ChevronRight, ChevronDown,
  AlertTriangle, AlertCircle, Info, Download, RefreshCw, Zap,
  Settings, History, X, WifiOff, Activity, Trash2, Save,
  Server, Key, RotateCcw, ExternalLink, Lock, Users, Plus,
} from "lucide-react"

// ── Constantes globales ───────────────────────────────────────────────────────
const DEFAULT_API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
const LS_HISTORY  = "caronte_history"
const LS_CONFIG   = "caronte_config"

const ORANGE        = "#f97316"
const ORANGE_DIM    = "rgba(249,115,22,0.12)"
const ORANGE_BORDER = "rgba(249,115,22,0.25)"

const SEV_STYLE: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: "#f87171", bg: "rgba(248,113,113,0.08)", border: "rgba(248,113,113,0.2)" },
  HIGH:     { color: "#f97316", bg: "rgba(249,115,22,0.08)",  border: "rgba(249,115,22,0.2)"  },
  MEDIUM:   { color: "#facc15", bg: "rgba(250,204,21,0.08)",  border: "rgba(250,204,21,0.2)"  },
  LOW:      { color: "#60a5fa", bg: "rgba(96,165,250,0.08)",  border: "rgba(96,165,250,0.2)"  },
}

const NAV_ITEMS = [
  { id: "procesar",      icon: Upload,   label: "Procesar"      },
  { id: "historial",     icon: History,  label: "Historial"     },
  { id: "configuracion", icon: Settings, label: "Configuración" },
] as const

// ── Tipos ─────────────────────────────────────────────────────────────────────
interface DashboardProps {
  userName:  string
  userEmail: string
  userRole:  string
  token:     string
  onLogout:  () => void
}

interface VulnEntry {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  status: "pending" | "processing" | "completed"
  documents: number
}
interface Project {
  ip: string; name: string; vulnerabilities: VulnEntry[]; expanded: boolean
}
interface TaskSnapshot {
  task_id: string; status: "processing" | "completed" | "error"
  progress: number; file: string; projects: Project[]
  total_docs: number; total_folders: number; completed_docs: number
  elapsed_seconds: number; message: string; error: string | null
}
type ViewState = "upload" | "processing" | "completed" | "error"
type NavId = "procesar" | "historial" | "configuracion"

interface HistoryEntry {
  id: string
  filename: string
  date: string
  totalDocs: number
  totalFolders: number
  elapsedSeconds: number
  status: "completed" | "error"
  error?: string
  severityBreakdown: Record<string, number>
}

interface AppConfig {
  apiUrl: string
  groqModel: string
  autoDownload: boolean
}

const DEFAULT_CONFIG: AppConfig = {
  apiUrl:      DEFAULT_API,
  groqModel:   "llama-3.1-8b-instant",
  autoDownload: false,
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function loadHistory(): HistoryEntry[] {
  if (typeof window === "undefined") return []
  try { return JSON.parse(localStorage.getItem(LS_HISTORY) ?? "[]") } catch { return [] }
}
function saveHistory(h: HistoryEntry[]) {
  localStorage.setItem(LS_HISTORY, JSON.stringify(h))
}
function loadConfig(): AppConfig {
  if (typeof window === "undefined") return DEFAULT_CONFIG
  try { return { ...DEFAULT_CONFIG, ...JSON.parse(localStorage.getItem(LS_CONFIG) ?? "{}") } } catch { return DEFAULT_CONFIG }
}
function saveConfig(c: AppConfig) {
  localStorage.setItem(LS_CONFIG, JSON.stringify(c))
}
function formatTime(s: number) {
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`
}
function formatDate(iso: string) {
  return new Date(iso).toLocaleString("es-ES", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })
}

// ── Sub-componentes ───────────────────────────────────────────────────────────

const SevIcon = memo(function SevIcon({ sev }: { sev: string }) {
  if (sev === "CRITICAL") return <AlertCircle  className="w-3 h-3" />
  if (sev === "HIGH")     return <AlertTriangle className="w-3 h-3" />
  return <Info className="w-3 h-3" />
})

const SevBadge = memo(function SevBadge({ sev }: { sev: string }) {
  const s = SEV_STYLE[sev] ?? { color: "#888", bg: "#111", border: "#333" }
  return (
    <span className="sev-badge" style={{ color: s.color, background: s.bg, border: `1px solid ${s.border}` }}>
      <SevIcon sev={sev} />{sev}
    </span>
  )
})

const ProjectRow = memo(function ProjectRow({ project, completed = false, onToggle }: {
  project: Project; completed?: boolean; onToggle: () => void
}) {
  return (
    <div className="rounded-xl overflow-hidden" style={{ background: "#0a0a0a", border: "1px solid #1a1a1a" }}>
      <button onClick={onToggle} className="project-row-btn w-full px-4 py-3 flex items-center gap-3 text-left"
        style={{ background: "transparent" }}>
        {project.expanded
          ? <ChevronDown  className="w-3.5 h-3.5 shrink-0" style={{ color: "#444" }} />
          : <ChevronRight className="w-3.5 h-3.5 shrink-0" style={{ color: "#444" }} />}
        <span className="text-xs font-mono px-2 py-0.5 rounded shrink-0"
          style={{ background: ORANGE_DIM, color: ORANGE }}>{project.ip}</span>
        <span className="text-sm font-medium text-white truncate">{project.name}</span>
        <span className="ml-auto text-xs shrink-0" style={{ color: "#444" }}>
          {project.vulnerabilities.length} niveles
        </span>
        {completed && <CheckCircle2 className="w-3.5 h-3.5 text-green-400 ml-1 shrink-0" />}
      </button>

      {project.expanded && (
        <div className="px-4 pb-3 space-y-1.5">
          {project.vulnerabilities.map((v, i) => {
            const st   = SEV_STYLE[v.severity] ?? { color: "#888", bg: "#111", border: "#333" }
            const done = completed || v.status === "completed"
            return (
              <div key={i} className="ml-6 flex items-center gap-3 px-3 py-2 rounded-lg"
                style={{ background: "#0f0f0f", border: "1px solid #1a1a1a" }}>
                <div className="p-1 rounded" style={{ background: st.bg, color: st.color }}>
                  <SevIcon sev={v.severity} />
                </div>
                <span className="text-xs font-semibold" style={{ color: st.color }}>{v.severity}</span>
                <span className="text-xs" style={{ color: "#444" }}>({v.documents} doc)</span>
                <div className="ml-auto flex items-center gap-1.5">
                  {done
                    ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                    : v.status === "processing"
                      ? <Loader2 className="w-3.5 h-3.5 animate-spin" style={{ color: ORANGE }} />
                      : <Clock   className="w-3.5 h-3.5" style={{ color: "#444" }} />}
                  <span className="text-xs" style={{ color: done ? "#4ade80" : v.status === "processing" ? ORANGE : "#444" }}>
                    {done ? "Listo" : v.status === "processing" ? "Generando…" : "Pendiente"}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
})

// ── Vista: Historial ──────────────────────────────────────────────────────────
function HistorialView({ history, onClear }: { history: HistoryEntry[]; onClear: () => void }) {
  if (history.length === 0) {
    return (
      <div className="card fade-up">
        <div className="card-header">
          <History className="w-4 h-4" style={{ color: ORANGE }} />
          <span className="font-semibold text-sm text-white">Historial de Procesamiento</span>
        </div>
        <div className="card-body flex flex-col items-center justify-center py-16 gap-4">
          <div className="w-14 h-14 rounded-2xl flex items-center justify-center" style={{ background: "#141414" }}>
            <History className="w-7 h-7" style={{ color: "#333" }} />
          </div>
          <div className="text-center">
            <p className="text-sm font-medium text-white">Sin registros aún</p>
            <p className="text-xs mt-1" style={{ color: "#555" }}>Los reportes procesados aparecerán aquí</p>
          </div>
        </div>
      </div>
    )
  }

  const totalDocs    = history.reduce((s, e) => s + e.totalDocs, 0)
  const totalOk      = history.filter(e => e.status === "completed").length
  const avgTime      = Math.round(history.reduce((s, e) => s + e.elapsedSeconds, 0) / history.length)

  return (
    <div className="space-y-4 fade-up">
      {/* Stats rápidas */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { icon: FileText,   label: "Docs generados",    value: totalDocs      },
          { icon: CheckCircle2, label: "Reportes exitosos", value: totalOk        },
          { icon: Clock,      label: "Tiempo promedio",   value: formatTime(avgTime) },
        ].map(({ icon: Icon, label, value }) => (
          <div key={label} className="rounded-xl p-4 flex items-center gap-3"
            style={{ background: "#0d0d0d", border: "1px solid #1c1c1c" }}>
            <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
              style={{ background: ORANGE_DIM }}>
              <Icon className="w-4 h-4" style={{ color: ORANGE }} />
            </div>
            <div>
              <p className="text-lg font-bold text-white leading-none">{value}</p>
              <p className="text-xs mt-0.5" style={{ color: "#555" }}>{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabla */}
      <div className="card">
        <div className="card-header justify-between">
          <div className="flex items-center gap-2.5">
            <History className="w-4 h-4" style={{ color: ORANGE }} />
            <span className="font-semibold text-sm text-white">Historial</span>
            <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: ORANGE_DIM, color: ORANGE }}>
              {history.length}
            </span>
          </div>
          <button onClick={onClear} className="btn-danger flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs">
            <Trash2 className="w-3.5 h-3.5" /> Limpiar
          </button>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="hist-table">
            <thead>
              <tr>
                <th>Archivo</th>
                <th>Fecha</th>
                <th>Docs</th>
                <th>Carpetas</th>
                <th>Tiempo</th>
                <th>Estado</th>
              </tr>
            </thead>
            <tbody>
              {history.map(entry => (
                <tr key={entry.id}>
                  <td>
                    <div className="flex items-center gap-2">
                      <FileSpreadsheet className="w-3.5 h-3.5 shrink-0" style={{ color: ORANGE }} />
                      <span className="font-medium text-white truncate max-w-[180px]">{entry.filename}</span>
                    </div>
                    {/* Badges de severidad */}
                    {Object.keys(entry.severityBreakdown).length > 0 && (
                      <div className="flex gap-1 mt-1.5 flex-wrap">
                        {Object.entries(entry.severityBreakdown).map(([sev, count]) => (
                          <SevBadge key={sev} sev={sev} />
                        ))}
                      </div>
                    )}
                  </td>
                  <td style={{ color: "#777", whiteSpace: "nowrap" }}>{formatDate(entry.date)}</td>
                  <td>
                    <span className="font-semibold text-white">{entry.totalDocs}</span>
                  </td>
                  <td style={{ color: "#999" }}>{entry.totalFolders}</td>
                  <td style={{ color: "#777", whiteSpace: "nowrap" }}>{formatTime(entry.elapsedSeconds)}</td>
                  <td>
                    {entry.status === "completed"
                      ? <span className="flex items-center gap-1.5 text-green-400 text-xs font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Completado
                        </span>
                      : <span className="flex items-center gap-1.5 text-red-400 text-xs font-medium">
                          <AlertCircle className="w-3.5 h-3.5" /> Error
                        </span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Vista: Configuración ──────────────────────────────────────────────────────
function ConfiguracionView({ config, onSave, groqStatus, token, userRole, userEmail, onLogout }: {
  config: AppConfig
  onSave: (c: AppConfig) => void
  groqStatus: "connected" | "disconnected" | "checking"
  token: string
  userRole: string
  userEmail: string
  onLogout: () => void
}) {
  const [draft, setDraft]           = useState<AppConfig>(config)
  const [testing, setTesting]       = useState(false)
  const [testResult, setTestResult] = useState<"ok" | "fail" | null>(null)
  const [saved, setSaved]           = useState(false)

  // Cambiar contraseña
  const [pwCurrent, setPwCurrent]   = useState("")
  const [pwNew,     setPwNew]       = useState("")
  const [pwConfirm, setPwConfirm]   = useState("")
  const [pwLoading, setPwLoading]   = useState(false)
  const [pwMsg,     setPwMsg]       = useState<{ type: "ok" | "err"; text: string } | null>(null)

  // Gestión de usuarios (solo admin)
  type UserRecord = { email: string; name: string; role: string }
  const [users,        setUsers]        = useState<UserRecord[]>([])
  const [usersLoading, setUsersLoading] = useState(() => userRole === "admin")
  const [reloadTick,   setReloadTick]   = useState(0)
  const [showCreate,   setShowCreate]   = useState(false)
  const [newUser,      setNewUser]      = useState({ email: "", name: "", password: "", role: "user" })
  const [creatingUser, setCreatingUser] = useState(false)
  const [createMsg,    setCreateMsg]    = useState<{ type: "ok" | "err"; text: string } | null>(null)

  const authCall = useCallback(async (url: string, opts: RequestInit = {}) =>
    fetch(url, { ...opts, headers: { ...(opts.headers as Record<string, string>), Authorization: `Bearer ${token}` } })
  , [token])

  const reloadUsers = useCallback(() => {
    setUsersLoading(true)
    setReloadTick(t => t + 1)
  }, [])

  useEffect(() => {
    if (userRole !== "admin") return
    authCall(`${draft.apiUrl}/api/auth/users`)
      .then(r => r.json())
      .then(data => { setUsers(data); setUsersLoading(false) })
      .catch(() => setUsersLoading(false))
  }, [reloadTick, userRole, draft.apiUrl, authCall])

  const testConnection = async () => {
    setTesting(true); setTestResult(null)
    try {
      const r = await fetch(`${draft.apiUrl}/api/health`, { signal: AbortSignal.timeout(4000) })
      setTestResult(r.ok ? "ok" : "fail")
    } catch {
      setTestResult("fail")
    } finally {
      setTesting(false)
    }
  }

  const handleSave  = () => { onSave(draft); setSaved(true); setTimeout(() => setSaved(false), 2500) }
  const handleReset = () => { setDraft(DEFAULT_CONFIG); setTestResult(null) }

  const handleChangePassword = async () => {
    if (!pwCurrent || !pwNew)  { setPwMsg({ type: "err", text: "Completa todos los campos." }); return }
    if (pwNew !== pwConfirm)   { setPwMsg({ type: "err", text: "Las contraseñas nuevas no coinciden." }); return }
    if (pwNew.length < 6)      { setPwMsg({ type: "err", text: "La nueva contraseña debe tener al menos 6 caracteres." }); return }
    setPwLoading(true); setPwMsg(null)
    try {
      const r = await authCall(`${draft.apiUrl}/api/auth/change-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current_password: pwCurrent, new_password: pwNew }),
      })
      if (r.ok) {
        setPwMsg({ type: "ok", text: "Contraseña actualizada. Cerrando sesión…" })
        setPwCurrent(""); setPwNew(""); setPwConfirm("")
        setTimeout(onLogout, 2000)
      } else {
        const d = await r.json().catch(() => ({}))
        setPwMsg({ type: "err", text: d.detail ?? "Error al cambiar contraseña." })
      }
    } catch { setPwMsg({ type: "err", text: "Error de conexión." }) }
    finally  { setPwLoading(false) }
  }

  const handleCreateUser = async () => {
    if (!newUser.email || !newUser.name || !newUser.password) { setCreateMsg({ type: "err", text: "Completa todos los campos." }); return }
    setCreatingUser(true); setCreateMsg(null)
    try {
      const r = await authCall(`${draft.apiUrl}/api/auth/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newUser),
      })
      if (r.ok) {
        setCreateMsg({ type: "ok", text: `Usuario ${newUser.email} creado.` })
        setNewUser({ email: "", name: "", password: "", role: "user" })
        setShowCreate(false)
        reloadUsers()
      } else {
        const d = await r.json().catch(() => ({}))
        setCreateMsg({ type: "err", text: d.detail ?? "Error al crear usuario." })
      }
    } catch { setCreateMsg({ type: "err", text: "Error de conexión." }) }
    finally  { setCreatingUser(false) }
  }

  const handleDeleteUser = async (email: string) => {
    try {
      const r = await authCall(`${draft.apiUrl}/api/auth/users/${encodeURIComponent(email)}`, { method: "DELETE" })
      if (r.ok) setUsers(prev => prev.filter(u => u.email !== email))
    } catch {}
  }

  return (
    <div className="space-y-4 fade-up">

      {/* ── Conexión Backend ── */}
      <div className="card">
        <div className="card-header">
          <Server className="w-4 h-4" style={{ color: ORANGE }} />
          <span className="font-semibold text-sm text-white">Conexión Backend</span>
        </div>
        <div className="card-body space-y-4">
          <div>
            <label className="text-xs font-medium mb-2 block" style={{ color: "#aaa" }}>URL del servidor API</label>
            <div className="flex gap-2">
              <input
                className="cfg-input flex-1"
                value={draft.apiUrl}
                onChange={e => { setDraft(d => ({ ...d, apiUrl: e.target.value })); setTestResult(null) }}
                placeholder="http://localhost:8000"
              />
              <button onClick={testConnection} disabled={testing}
                className="btn-ghost px-4 rounded-xl text-xs font-medium flex items-center gap-1.5 shrink-0">
                {testing
                  ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Probando…</>
                  : <><ExternalLink className="w-3.5 h-3.5" /> Probar</>}
              </button>
            </div>
            {testResult && (
              <p className="text-xs mt-2 flex items-center gap-1.5"
                style={{ color: testResult === "ok" ? "#4ade80" : "#f87171" }}>
                {testResult === "ok"
                  ? <><CheckCircle2 className="w-3.5 h-3.5" /> Conexión exitosa</>
                  : <><AlertCircle  className="w-3.5 h-3.5" /> No se pudo conectar — verifica que el backend esté corriendo</>}
              </p>
            )}
          </div>

          <div className="flex items-center gap-3 p-3 rounded-xl" style={{ background: "#0a0a0a", border: "1px solid #1a1a1a" }}>
            <div className="flex items-center gap-2">
              {groqStatus === "checking"
                ? <Loader2 className="w-3.5 h-3.5 animate-spin" style={{ color: "#555" }} />
                : groqStatus === "connected"
                  ? <span className="w-2 h-2 rounded-full bg-green-500" style={{ boxShadow: "0 0 6px #22c55e" }} />
                  : <WifiOff className="w-3.5 h-3.5 text-red-500" />}
              <span className="text-xs" style={{ color: "#888" }}>
                Backend: <strong style={{ color: groqStatus === "connected" ? "#4ade80" : "#f87171" }}>
                  {groqStatus === "checking" ? "Verificando…" : groqStatus === "connected" ? "Conectado" : "Sin conexión"}
                </strong>
              </span>
            </div>
            <span className="text-xs ml-auto font-mono" style={{ color: "#444" }}>{draft.apiUrl}</span>
          </div>
        </div>
      </div>

      {/* ── Modelo Groq ── */}
      <div className="card">
        <div className="card-header">
          <Activity className="w-4 h-4" style={{ color: ORANGE }} />
          <span className="font-semibold text-sm text-white">Modelo de IA (Groq)</span>
        </div>
        <div className="card-body space-y-4">
          <div>
            <label className="text-xs font-medium mb-2 block" style={{ color: "#aaa" }}>Modelo activo</label>
            <select
              className="cfg-input"
              value={draft.groqModel}
              onChange={e => setDraft(d => ({ ...d, groqModel: e.target.value }))}
              style={{ cursor: "pointer" }}
            >
              <option value="llama-3.1-8b-instant">llama-3.1-8b-instant (por defecto)</option>
              <option value="llama-3.3-70b-versatile">llama-3.3-70b-versatile</option>
              <option value="llama-3.1-70b-versatile">llama-3.1-70b-versatile</option>
              <option value="mixtral-8x7b-32768">mixtral-8x7b-32768</option>
            </select>
            <p className="text-xs mt-1.5" style={{ color: "#555" }}>
              El modelo se usa en <code style={{ color: "#888" }}>config.py → GROQ_MODEL</code>. Cambiar aquí es informativo; edita el .env para persistirlo.
            </p>
          </div>

          <div>
            <label className="text-xs font-medium mb-2 block" style={{ color: "#aaa" }}>API Keys por severidad</label>
            <div className="space-y-1.5">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => {
                const s = SEV_STYLE[sev]
                return (
                  <div key={sev} className="flex items-center gap-3 px-3 py-2 rounded-lg"
                    style={{ background: "#0a0a0a", border: "1px solid #1a1a1a" }}>
                    <span className="sev-badge" style={{ color: s.color, background: s.bg, border: `1px solid ${s.border}` }}>
                      {sev}
                    </span>
                    <Key className="w-3 h-3 ml-1" style={{ color: "#444" }} />
                    <span className="text-xs font-mono" style={{ color: "#555" }}>
                      GROQ_API_KEY_{sev} = <span style={{ color: "#777" }}>gsk_••••••••</span>
                    </span>
                    <CheckCircle2 className="w-3.5 h-3.5 text-green-500 ml-auto" />
                  </div>
                )
              })}
            </div>
            <p className="text-xs mt-2" style={{ color: "#555" }}>
              Para cambiar las keys, edita el archivo <code style={{ color: "#888" }}>.env</code> en la raíz del proyecto.
            </p>
          </div>
        </div>
      </div>

      {/* ── Preferencias ── */}
      <div className="card">
        <div className="card-header">
          <Settings className="w-4 h-4" style={{ color: ORANGE }} />
          <span className="font-semibold text-sm text-white">Preferencias</span>
        </div>
        <div className="card-body space-y-3">
          <label className="flex items-center justify-between cursor-pointer">
            <div>
              <p className="text-sm text-white">Descarga automática al finalizar</p>
              <p className="text-xs mt-0.5" style={{ color: "#555" }}>Descarga el ZIP inmediatamente cuando el procesamiento termine</p>
            </div>
            <div
              onClick={() => setDraft(d => ({ ...d, autoDownload: !d.autoDownload }))}
              className="relative w-10 h-5.5 rounded-full transition-colors duration-200 shrink-0 ml-4 cursor-pointer"
              style={{
                background: draft.autoDownload ? ORANGE : "#222",
                width: 40, height: 22,
                border: `1px solid ${draft.autoDownload ? ORANGE : "#333"}`,
              }}
            >
              <span className="absolute top-0.5 transition-all duration-200 w-4 h-4 rounded-full bg-white"
                style={{ left: draft.autoDownload ? "calc(100% - 18px)" : 2 }} />
            </div>
          </label>
        </div>
      </div>

      {/* ── Cambiar Contraseña ── */}
      <div className="card">
        <div className="card-header">
          <Lock className="w-4 h-4" style={{ color: ORANGE }} />
          <span className="font-semibold text-sm text-white">Cambiar Contraseña</span>
        </div>
        <div className="card-body space-y-3">
          <p className="text-xs" style={{ color: "#555" }}>
            Cuenta: <span style={{ color: "#888" }}>{userEmail}</span>
          </p>
          {pwMsg && (
            <div className="flex items-start gap-2 p-3 rounded-xl text-xs"
              style={{
                background: pwMsg.type === "ok" ? "rgba(34,197,94,0.07)" : "rgba(239,68,68,0.07)",
                border: `1px solid ${pwMsg.type === "ok" ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.2)"}`,
                color:  pwMsg.type === "ok" ? "#4ade80" : "#f87171",
              }}>
              {pwMsg.type === "ok"
                ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                : <AlertCircle  className="w-3.5 h-3.5 shrink-0 mt-0.5" />}
              {pwMsg.text}
            </div>
          )}
          <div className="space-y-2">
            <input className="cfg-input" type="password" placeholder="Contraseña actual"
              value={pwCurrent} onChange={e => { setPwCurrent(e.target.value); setPwMsg(null) }} />
            <input className="cfg-input" type="password" placeholder="Nueva contraseña (mín. 6 caracteres)"
              value={pwNew} onChange={e => { setPwNew(e.target.value); setPwMsg(null) }} />
            <input className="cfg-input" type="password" placeholder="Confirmar nueva contraseña"
              value={pwConfirm} onChange={e => { setPwConfirm(e.target.value); setPwMsg(null) }} />
          </div>
          <button onClick={handleChangePassword} disabled={pwLoading}
            className="btn-primary w-full h-9 rounded-xl text-xs font-semibold text-white flex items-center justify-center gap-2 disabled:opacity-60">
            {pwLoading
              ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Guardando…</>
              : <><Key className="w-3.5 h-3.5" /> Actualizar contraseña</>}
          </button>
        </div>
      </div>

      {/* ── Gestión de Usuarios (solo admin) ── */}
      {userRole === "admin" && (
        <div className="card">
          <div className="card-header justify-between">
            <div className="flex items-center gap-2.5">
              <Users className="w-4 h-4" style={{ color: ORANGE }} />
              <span className="font-semibold text-sm text-white">Usuarios del Sistema</span>
              {!usersLoading && (
                <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: ORANGE_DIM, color: ORANGE }}>
                  {users.length}
                </span>
              )}
            </div>
            <button onClick={() => { setShowCreate(v => !v); setCreateMsg(null) }}
              className="btn-ghost flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs">
              <Plus className="w-3.5 h-3.5" /> Nuevo
            </button>
          </div>
          <div className="card-body space-y-3">
            {/* Formulario crear usuario */}
            {showCreate && (
              <div className="p-3 rounded-xl space-y-2" style={{ background: "#0a0a0a", border: "1px solid #1e1e1e" }}>
                {createMsg && (
                  <div className="flex items-center gap-2 text-xs p-2 rounded-lg"
                    style={{
                      background: createMsg.type === "ok" ? "rgba(34,197,94,0.07)" : "rgba(239,68,68,0.07)",
                      color: createMsg.type === "ok" ? "#4ade80" : "#f87171",
                    }}>
                    {createMsg.type === "ok" ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertCircle className="w-3.5 h-3.5" />}
                    {createMsg.text}
                  </div>
                )}
                <div className="grid grid-cols-2 gap-2">
                  <input className="cfg-input" placeholder="Nombre completo"
                    value={newUser.name} onChange={e => setNewUser(u => ({ ...u, name: e.target.value }))} />
                  <input className="cfg-input" placeholder="Correo electrónico" type="email"
                    value={newUser.email} onChange={e => setNewUser(u => ({ ...u, email: e.target.value }))} />
                  <input className="cfg-input" placeholder="Contraseña" type="password"
                    value={newUser.password} onChange={e => setNewUser(u => ({ ...u, password: e.target.value }))} />
                  <select className="cfg-input" value={newUser.role}
                    onChange={e => setNewUser(u => ({ ...u, role: e.target.value }))}
                    style={{ cursor: "pointer" }}>
                    <option value="user">user</option>
                    <option value="admin">admin</option>
                  </select>
                </div>
                <div className="flex gap-2">
                  <button onClick={handleCreateUser} disabled={creatingUser}
                    className="btn-primary flex-1 h-8 rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 disabled:opacity-60">
                    {creatingUser ? <><Loader2 className="w-3 h-3 animate-spin" /> Creando…</> : "Crear usuario"}
                  </button>
                  <button onClick={() => { setShowCreate(false); setCreateMsg(null) }}
                    className="btn-ghost h-8 px-3 rounded-lg text-xs">
                    Cancelar
                  </button>
                </div>
              </div>
            )}

            {/* Lista de usuarios */}
            {usersLoading
              ? <div className="flex items-center gap-2 text-xs py-4 justify-center" style={{ color: "#555" }}>
                  <Loader2 className="w-4 h-4 animate-spin" /> Cargando usuarios…
                </div>
              : users.map(u => (
                  <div key={u.email} className="flex items-center gap-3 px-3 py-2.5 rounded-lg"
                    style={{ background: "#0a0a0a", border: "1px solid #1a1a1a" }}>
                    <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                      style={{ background: ORANGE_DIM, color: ORANGE }}>
                      {u.name[0]?.toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-white truncate">{u.name}</p>
                      <p className="text-xs font-mono truncate" style={{ color: "#555" }}>{u.email}</p>
                    </div>
                    <span className="text-xs px-2 py-0.5 rounded shrink-0"
                      style={{
                        background: u.role === "admin" ? ORANGE_DIM : "#111",
                        color:      u.role === "admin" ? ORANGE : "#555",
                        border:     `1px solid ${u.role === "admin" ? ORANGE_BORDER : "#222"}`,
                      }}>
                      {u.role}
                    </span>
                    {u.email !== userEmail && (
                      <button onClick={() => handleDeleteUser(u.email)}
                        className="btn-danger p-1.5 rounded-lg ml-1 shrink-0" title="Eliminar usuario">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                ))
            }
          </div>
        </div>
      )}

      {/* ── Acciones ── */}
      <div className="flex gap-3">
        <button onClick={handleSave} className="btn-primary flex-1 h-10 rounded-xl text-sm font-semibold text-white flex items-center justify-center gap-2">
          {saved ? <><CheckCircle2 className="w-4 h-4" /> Guardado</> : <><Save className="w-4 h-4" /> Guardar cambios</>}
        </button>
        <button onClick={handleReset} className="btn-ghost h-10 px-4 rounded-xl text-sm flex items-center gap-2">
          <RotateCcw className="w-4 h-4" /> Restablecer
        </button>
      </div>
    </div>
  )
}

// ── Dashboard principal ───────────────────────────────────────────────────────
export function Dashboard({ userName, userEmail, userRole, token, onLogout }: DashboardProps) {
  const [timeStr,      setTimeStr]      = useState("")
  const [viewState,    setViewState]    = useState<ViewState>("upload")
  const [dragActive,   setDragActive]   = useState(false)
  const [uploadedFile, setUploadedFile] = useState<{ name: string; size: string; file: File } | null>(null)
  const [taskId,       setTaskId]       = useState<string | null>(null)
  const [taskData,     setTaskData]     = useState<TaskSnapshot | null>(null)
  const [projects,     setProjects]     = useState<Project[]>([])
  const [activeNav,    setActiveNav]    = useState<NavId>("procesar")
  const [groqStatus,   setGroqStatus]   = useState<"connected" | "disconnected" | "checking">("checking")
  const [uploadError,  setUploadError]  = useState<string | null>(null)
  // Lazy init desde localStorage — evita useEffect sincrónico
  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory())
  const [config,  setConfig]  = useState<AppConfig>(() => loadConfig())
  const esRef = useRef<EventSource | null>(null)

  const apiUrl = config.apiUrl

  // ── Auth fetch helper ────────────────────────────────────────────────────────
  const authFetch = useCallback(async (url: string, opts: RequestInit = {}) => {
    const res = await fetch(url, {
      ...opts,
      headers: { ...(opts.headers as Record<string, string>), Authorization: `Bearer ${token}` },
    })
    if (res.status === 401) { onLogout(); throw new Error("Sesión expirada") }
    return res
  }, [token, onLogout])

  // ── Download helper (declarado antes del SSE que lo usa) ─────────────────────
  const triggerDownload = useCallback(async (id: string, filename: string) => {
    const res = await authFetch(`${apiUrl}/api/tasks/${id}/download`)
    if (!res.ok) {
      const d = await res.json().catch(() => ({}))
      throw new Error(d.detail ?? `Error ${res.status} al descargar`)
    }
    const blob = await res.blob()
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement("a")
    a.href = url; a.download = `remediacion_${filename.replace(/\.[^.]+$/, "")}.zip`
    a.click(); URL.revokeObjectURL(url)
  }, [authFetch, apiUrl])

  // ── Reloj ────────────────────────────────────────────────────────────────────
  useEffect(() => {
    const tick = () => setTimeStr(
      new Date().toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" })
    )
    tick()
    const t = setInterval(tick, 1000)
    return () => clearInterval(t)
  }, [])

  // ── Health check ─────────────────────────────────────────────────────────────
  useEffect(() => {
    fetch(`${apiUrl}/api/health`)
      .then(r => r.json())
      .then(d => setGroqStatus(d.groq_connected ? "connected" : "disconnected"))
      .catch(() => setGroqStatus("disconnected"))
  }, [apiUrl])

  // ── SSE ───────────────────────────────────────────────────────────────────────
  const startSSE = useCallback((id: string) => {
    esRef.current?.close()
    // EventSource no soporta headers; pasamos el token como query param
    const es = new EventSource(`${apiUrl}/api/tasks/${id}/stream?token=${encodeURIComponent(token)}`)
    esRef.current = es
    es.onmessage = (e) => {
      const data: TaskSnapshot = JSON.parse(e.data)
      setTaskData(data)
      setProjects(prev => data.projects.map(p => ({
        ...p,
        expanded: prev.find(lp => lp.ip === p.ip && lp.name === p.name)?.expanded ?? true,
      })))
      if (data.status === "completed") {
        setViewState("completed")
        es.close()
        // Guardar en historial
        const sevBreak: Record<string, number> = {}
        data.projects.forEach(p => p.vulnerabilities.forEach(v => {
          sevBreak[v.severity] = (sevBreak[v.severity] ?? 0) + 1
        }))
        const entry: HistoryEntry = {
          id: data.task_id, filename: data.file, date: new Date().toISOString(),
          totalDocs: data.total_docs, totalFolders: data.total_folders,
          elapsedSeconds: data.elapsed_seconds, status: "completed",
          severityBreakdown: sevBreak,
        }
        setHistory(prev => {
          const next = [entry, ...prev.filter(e => e.id !== entry.id)]
          saveHistory(next)
          return next
        })
      } else if (data.status === "error") {
        setViewState("error"); es.close()
      }
    }
  }, [apiUrl, token])

  useEffect(() => () => { esRef.current?.close() }, [])

  // ── Handlers ─────────────────────────────────────────────────────────────────
  const handleFile = useCallback((file: File) => {
    const size = file.size < 1048576
      ? `${(file.size / 1024).toFixed(1)} KB`
      : `${(file.size / 1048576).toFixed(1)} MB`
    setUploadedFile({ name: file.name, size, file })
    setUploadError(null)
  }, [])

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation()
    setDragActive(e.type === "dragenter" || e.type === "dragover")
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation(); setDragActive(false)
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0])
  }, [handleFile])

  const startProcessing = useCallback(async () => {
    if (!uploadedFile) return
    setUploadError(null)
    const fd = new FormData()
    fd.append("file", uploadedFile.file)
    try {
      const res = await authFetch(`${apiUrl}/api/upload`, { method: "POST", body: fd })
      if (!res.ok) throw new Error((await res.json()).detail ?? "Error al subir")
      const { task_id } = await res.json()
      setTaskId(task_id); setViewState("processing"); startSSE(task_id)
    } catch (err: unknown) {
      setUploadError(err instanceof Error ? err.message : "Error desconocido")
    }
  }, [uploadedFile, apiUrl, authFetch, startSSE])

  const handleDownload = useCallback(async () => {
    if (!taskId) return
    try {
      await triggerDownload(taskId, uploadedFile?.name ?? "docs")
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Error al descargar el ZIP")
    }
  }, [taskId, uploadedFile, triggerDownload])

  const reset = useCallback(() => {
    esRef.current?.close()
    setUploadedFile(null); setTaskId(null); setTaskData(null)
    setProjects([]); setViewState("upload"); setUploadError(null)
  }, [])

  const toggleExpand = useCallback((i: number) =>
    setProjects(prev => prev.map((p, idx) => idx === i ? { ...p, expanded: !p.expanded } : p)),
  [])

  const handleSaveConfig = useCallback((c: AppConfig) => {
    setConfig(c); saveConfig(c)
  }, [])

  const handleClearHistory = useCallback(() => {
    setHistory([]); saveHistory([])
  }, [])

  const progress = taskData?.progress ?? 0
  const elapsed  = taskData?.elapsed_seconds ?? 0

  return (
    <div className="min-h-screen flex" style={{ background: "#080808", color: "#f0f0f0" }}>

      {/* ── Sidebar ─────────────────────────────────────────────────────────── */}
      <aside style={{
        width: 220,
        flexShrink: 0,
        display: "flex",
        flexDirection: "column",
        background: "linear-gradient(180deg, #080808 0%, #060606 100%)",
        borderRight: "1px solid #1a1a1a",
        position: "relative",
      }}>

        {/* Glow superior */}
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, height: 120,
          background: "radial-gradient(ellipse at 50% -20%, rgba(249,115,22,0.07) 0%, transparent 70%)",
          pointerEvents: "none",
        }} />

        {/* Logo */}
        <div style={{ padding: "22px 20px 18px", borderBottom: "1px solid #181818" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 34, height: 34, borderRadius: 10,
              background: "linear-gradient(135deg, rgba(249,115,22,0.2) 0%, rgba(249,115,22,0.08) 100%)",
              border: "1px solid rgba(249,115,22,0.3)",
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: "0 0 12px rgba(249,115,22,0.1)",
            }}>
              <Shield style={{ width: 16, height: 16, color: ORANGE }} />
            </div>
            <div>
              <div style={{ fontWeight: 700, letterSpacing: "0.12em", color: "#fff", fontSize: 13, lineHeight: 1 }}>
                CARONTE
              </div>
              <div style={{ fontSize: 10, color: "#3a3a3a", marginTop: 3, letterSpacing: "0.05em" }}>
                Sistema de Vulnerabilidades
              </div>
            </div>
          </div>
        </div>

        {/* Sección Nav */}
        <div style={{ padding: "8px 12px", flex: 1 }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: "#333", letterSpacing: "0.1em", textTransform: "uppercase", padding: "10px 8px 6px" }}>
            Menú
          </div>
          <nav style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {NAV_ITEMS.map(item => {
              const active = activeNav === item.id
              return (
                <button key={item.id} onClick={() => setActiveNav(item.id)}
                  style={{
                    display: "flex", alignItems: "center", gap: 10,
                    padding: "9px 10px",
                    borderRadius: 10,
                    border: active ? "1px solid rgba(249,115,22,0.2)" : "1px solid transparent",
                    background: active
                      ? "linear-gradient(90deg, rgba(249,115,22,0.14) 0%, rgba(249,115,22,0.06) 100%)"
                      : "transparent",
                    color: active ? ORANGE : "#5a5a5a",
                    cursor: "pointer",
                    textAlign: "left",
                    width: "100%",
                    transition: "all 150ms",
                    position: "relative",
                  }}
                  onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.03)" }}
                  onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = "transparent" }}
                >
                  {/* Indicador activo izquierdo */}
                  {active && (
                    <div style={{
                      position: "absolute", left: -1, top: "50%", transform: "translateY(-50%)",
                      width: 3, height: 18, borderRadius: "0 3px 3px 0",
                      background: ORANGE,
                      boxShadow: `0 0 8px ${ORANGE}`,
                    }} />
                  )}
                  <div style={{
                    width: 30, height: 30, borderRadius: 8, display: "flex",
                    alignItems: "center", justifyContent: "center", flexShrink: 0,
                    background: active ? "rgba(249,115,22,0.12)" : "rgba(255,255,255,0.03)",
                    border: `1px solid ${active ? "rgba(249,115,22,0.2)" : "rgba(255,255,255,0.04)"}`,
                  }}>
                    <item.icon style={{ width: 14, height: 14, color: active ? ORANGE : "#4a4a4a" }} />
                  </div>
                  <span style={{ fontSize: 13, fontWeight: active ? 600 : 500, flex: 1 }}>
                    {item.label}
                  </span>
                  {item.id === "historial" && history.length > 0 && (
                    <span style={{
                      fontSize: 10, fontWeight: 700,
                      background: active ? ORANGE : "rgba(249,115,22,0.15)",
                      color: active ? "#fff" : ORANGE,
                      borderRadius: 99, padding: "1px 6px", lineHeight: 1.6,
                    }}>
                      {history.length}
                    </span>
                  )}
                </button>
              )
            })}
          </nav>
        </div>

        {/* Groq status */}
        <div style={{ padding: "12px 12px 16px", borderTop: "1px solid #181818" }}>
          <div style={{
            padding: "10px 12px", borderRadius: 12,
            background: "#0a0a0a",
            border: "1px solid #1e1e1e",
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Activity style={{ width: 12, height: 12, color: ORANGE }} />
                <span style={{ fontSize: 11, fontWeight: 600, color: "#888", letterSpacing: "0.05em" }}>GROQ IA</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                {groqStatus === "checking"
                  ? <Loader2 style={{ width: 10, height: 10, color: "#444" }} className="animate-spin" />
                  : groqStatus === "connected"
                    ? <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#22c55e", display: "inline-block", boxShadow: "0 0 6px #22c55e" }} />
                    : <WifiOff style={{ width: 10, height: 10, color: "#ef4444" }} />}
                <span style={{ fontSize: 10, color: groqStatus === "connected" ? "#4ade80" : groqStatus === "disconnected" ? "#f87171" : "#555" }}>
                  {groqStatus === "checking" ? "…" : groqStatus === "connected" ? "Online" : "Offline"}
                </span>
              </div>
            </div>
            <div style={{ fontSize: 10, color: "#333", fontFamily: "monospace" }}>
              llama-3.1-8b-instant
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main ────────────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* Header */}
        <header style={{
          height: 54, padding: "0 24px",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          background: "#060606",
          borderBottom: "1px solid #161616",
          flexShrink: 0,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {(() => {
              const n = NAV_ITEMS.find(n => n.id === activeNav)
              if (!n) return null
              return <>
                <n.icon style={{ width: 15, height: 15, color: ORANGE }} />
                <span style={{ fontSize: 14, fontWeight: 600, color: "#e0e0e0" }}>{n.label}</span>
              </>
            })()}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <span style={{ fontSize: 12, fontFamily: "monospace", color: "#2e2e2e" }}>{timeStr}</span>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{
                width: 28, height: 28, borderRadius: "50%",
                background: "linear-gradient(135deg, rgba(249,115,22,0.25), rgba(249,115,22,0.1))",
                border: "1px solid rgba(249,115,22,0.35)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 12, fontWeight: 700, color: ORANGE,
              }}>
                {userName[0]?.toUpperCase()}
              </div>
              <span style={{ fontSize: 13, fontWeight: 500, color: ORANGE }}>{userName}</span>
            </div>
            <button onClick={onLogout} className="btn-logout flex items-center gap-1.5 text-xs">
              <LogOut className="w-3.5 h-3.5" /> Salir
            </button>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-auto" style={{ background: "#080808" }}>
          <div style={{ maxWidth: 720, margin: "0 auto", padding: "32px 40px" }}>

            {/* ══ HISTORIAL ══ */}
            {activeNav === "historial" && (
              <HistorialView history={history} onClear={handleClearHistory} />
            )}

            {/* ══ CONFIGURACIÓN ══ */}
            {activeNav === "configuracion" && (
              <ConfiguracionView config={config} onSave={handleSaveConfig} groqStatus={groqStatus}
                token={token} userRole={userRole} userEmail={userEmail} onLogout={onLogout} />
            )}

            {/* ══ PROCESAR ══ */}
            {activeNav === "procesar" && (
              <div className="space-y-4">

                {/* UPLOAD */}
                {viewState === "upload" && (
                  <div className="card fade-up">
                    <div className="card-header">
                      <FileSpreadsheet className="w-4 h-4" style={{ color: ORANGE }} />
                      <span className="font-semibold text-sm text-white">Cargar Reporte de Vulnerabilidades</span>
                    </div>
                    <div className="card-body space-y-4">
                      {/* Drop zone */}
                      <div
                        className="relative rounded-2xl transition-all duration-200 cursor-pointer"
                        style={{
                          border:     `2px dashed ${dragActive ? ORANGE : uploadedFile ? ORANGE_BORDER : "#222"}`,
                          background: dragActive ? ORANGE_DIM : uploadedFile ? "rgba(249,115,22,0.03)" : "#0a0a0a",
                          minHeight: 200,
                          display: "flex", alignItems: "center", justifyContent: "center",
                        }}
                        onDragEnter={handleDrag} onDragLeave={handleDrag}
                        onDragOver={handleDrag}  onDrop={handleDrop}
                      >
                        {uploadedFile ? (
                          <div className="text-center space-y-3 p-8">
                            <div className="w-12 h-12 rounded-xl mx-auto flex items-center justify-center"
                              style={{ background: ORANGE_DIM }}>
                              <FileSpreadsheet className="w-6 h-6" style={{ color: ORANGE }} />
                            </div>
                            <div>
                              <p className="font-semibold text-white text-sm">{uploadedFile.name}</p>
                              <p className="text-xs mt-0.5" style={{ color: "#555" }}>{uploadedFile.size}</p>
                            </div>
                            <button onClick={() => setUploadedFile(null)}
                              className="btn-delete flex items-center gap-1 text-xs mx-auto">
                              <X className="w-3 h-3" /> Eliminar
                            </button>
                          </div>
                        ) : (
                          <div className="text-center space-y-3 p-8">
                            <div className="w-12 h-12 rounded-xl mx-auto flex items-center justify-center"
                              style={{ background: "#111", border: "1px solid #1e1e1e" }}>
                              <Upload className="w-6 h-6" style={{ color: "#3a3a3a" }} />
                            </div>
                            <div>
                              <p className="font-semibold text-white text-sm">Arrastra tu archivo Excel aquí</p>
                              <p className="text-xs mt-1" style={{ color: "#555" }}>o haz clic para seleccionar • .xlsx, .xls</p>
                            </div>
                            <input type="file" accept=".xlsx,.xls"
                              onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])}
                              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
                          </div>
                        )}
                      </div>

                      {uploadError && (
                        <div className="flex items-center gap-2 p-3 rounded-xl text-xs"
                          style={{ background: "rgba(239,68,68,0.07)", border: "1px solid rgba(239,68,68,0.18)", color: "#f87171" }}>
                          <AlertCircle className="w-4 h-4 shrink-0" />{uploadError}
                        </div>
                      )}

                      {uploadedFile && (
                        <button onClick={startProcessing}
                          className="btn-primary w-full h-11 rounded-xl font-semibold text-sm text-white flex items-center justify-center gap-2">
                          <Zap className="w-4 h-4" /> Iniciar Procesamiento
                        </button>
                      )}

                      {/* Pista rápida si hay historial */}
                      {history.length > 0 && !uploadedFile && (
                        <div className="flex items-center gap-2 p-3 rounded-xl text-xs"
                          style={{ background: "#0a0a0a", border: "1px solid #1a1a1a" }}>
                          <History className="w-3.5 h-3.5 shrink-0" style={{ color: "#555" }} />
                          <span style={{ color: "#555" }}>
                            {history.length} reporte{history.length > 1 ? "s" : ""} procesado{history.length > 1 ? "s" : ""} en total
                            {" • "}
                            <button className="underline" style={{ color: "#888" }}
                              onClick={() => setActiveNav("historial")}>
                              ver historial
                            </button>
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* PROCESSING */}
                {viewState === "processing" && (
                  <>
                    <div className="card fade-up glow-orange">
                      <div className="card-body space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div className="w-9 h-9 rounded-xl flex items-center justify-center"
                              style={{ background: ORANGE_DIM }}>
                              <Loader2 className="w-5 h-5 animate-spin" style={{ color: ORANGE }} />
                            </div>
                            <div>
                              <p className="text-sm font-semibold text-white">Procesando con Groq LLM…</p>
                              <p className="text-xs mt-0.5 max-w-xs truncate" style={{ color: "#555" }}>
                                {taskData?.message ?? uploadedFile?.name}
                              </p>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="text-2xl font-bold tabular-nums" style={{ color: ORANGE }}>{progress}%</p>
                            <p className="text-xs" style={{ color: "#555" }}>{formatTime(elapsed)}</p>
                          </div>
                        </div>
                        <Progress value={progress} />
                        {(taskData?.total_docs ?? 0) > 0 && (
                          <p className="text-xs text-right" style={{ color: "#444" }}>
                            {taskData?.completed_docs ?? 0} / {taskData?.total_docs} documentos
                          </p>
                        )}
                      </div>
                    </div>

                    {projects.length > 0 && (
                      <div className="card fade-up">
                        <div className="card-header">
                          <FolderOpen className="w-4 h-4" style={{ color: ORANGE }} />
                          <span className="font-semibold text-sm text-white">Estructura de Proyectos</span>
                        </div>
                        <div className="card-body space-y-2">
                          {projects.map((p, i) => (
                            <ProjectRow key={`${p.ip}-${p.name}`} project={p} onToggle={() => toggleExpand(i)} />
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}

                {/* ERROR */}
                {viewState === "error" && (
                  <div className="card fade-up"
                    style={{ background: "rgba(239,68,68,0.04)", border: "1px solid rgba(239,68,68,0.15)" }}>
                    <div className="card-body space-y-4">
                      <div className="flex items-center gap-4">
                        <div className="w-11 h-11 rounded-2xl flex items-center justify-center shrink-0"
                          style={{ background: "rgba(239,68,68,0.1)" }}>
                          <AlertCircle className="w-6 h-6 text-red-400" />
                        </div>
                        <div>
                          <h3 className="font-semibold text-white">Error en el procesamiento</h3>
                          <p className="text-xs mt-0.5" style={{ color: "#888" }}>{taskData?.error ?? "Error inesperado."}</p>
                        </div>
                      </div>
                      <button onClick={reset}
                        className="btn-ghost w-full h-10 rounded-xl text-sm font-medium flex items-center justify-center gap-2">
                        <RefreshCw className="w-4 h-4" /> Intentar de nuevo
                      </button>
                    </div>
                  </div>
                )}

                {/* COMPLETED */}
                {viewState === "completed" && (
                  <>
                    <div className="card fade-up"
                      style={{ background: "rgba(34,197,94,0.04)", border: "1px solid rgba(34,197,94,0.18)" }}>
                      <div className="card-body">
                        <div className="flex items-center gap-4">
                          <div className="w-11 h-11 rounded-2xl flex items-center justify-center shrink-0"
                            style={{ background: "rgba(34,197,94,0.1)" }}>
                            <CheckCircle2 className="w-6 h-6 text-green-400" />
                          </div>
                          <div>
                            <h3 className="font-semibold text-white">¡Proceso completado!</h3>
                            <p className="text-xs mt-0.5" style={{ color: "#888" }}>
                              Documentos en <code style={{ color: ORANGE }}>output/</code> •{" "}
                              {taskData?.total_docs} docs en {formatTime(elapsed)}
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-3">
                      {([
                        { icon: FileText,   label: "Documentos", value: taskData?.total_docs   ?? 0 },
                        { icon: FolderOpen, label: "Carpetas",   value: taskData?.total_folders ?? 0 },
                        { icon: Clock,      label: "Tiempo",     value: formatTime(elapsed)        },
                      ] as const).map(({ icon: Icon, label, value }) => (
                        <div key={label} className="rounded-xl p-4 flex items-center gap-3"
                          style={{ background: "#0d0d0d", border: "1px solid #1c1c1c" }}>
                          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                            style={{ background: ORANGE_DIM }}>
                            <Icon className="w-4 h-4" style={{ color: ORANGE }} />
                          </div>
                          <div>
                            <p className="text-xl font-bold text-white tabular-nums">{value}</p>
                            <p className="text-xs" style={{ color: "#555" }}>{label}</p>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="flex gap-3">
                      <button onClick={handleDownload}
                        className="btn-primary flex-1 h-11 rounded-xl text-sm font-semibold text-white flex items-center justify-center gap-2">
                        <Download className="w-4 h-4" /> Descargar ZIP
                      </button>
                      <button onClick={reset}
                        className="btn-ghost flex-1 h-11 rounded-xl text-sm font-semibold flex items-center justify-center gap-2">
                        <RefreshCw className="w-4 h-4" /> Nuevo reporte
                      </button>
                    </div>

                    <div className="card">
                      <div className="card-header">
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                        <span className="font-semibold text-sm text-white">Resumen</span>
                      </div>
                      <div className="card-body space-y-2">
                        {projects.map((p, i) => (
                          <ProjectRow key={`${p.ip}-${p.name}`} project={p} completed onToggle={() => toggleExpand(i)} />
                        ))}
                      </div>
                    </div>
                  </>
                )}

              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}
