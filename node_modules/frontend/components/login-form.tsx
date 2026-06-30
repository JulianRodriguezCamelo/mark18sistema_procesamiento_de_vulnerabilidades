"use client"

import { useState } from "react"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Eye, EyeOff, Shield, AlertCircle, KeyRound } from "lucide-react"

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

interface UserInfo { email: string; name: string; role: string }

interface LoginFormProps {
  onLogin: (token: string, user: UserInfo) => void
}

export function LoginForm({ onLogin }: LoginFormProps) {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")

  // Estado del paso 2FA
  const [step, setStep] = useState<"credentials" | "totp">("credentials")
  const [tempToken, setTempToken] = useState("")
  const [totpCode, setTotpCode] = useState("")

  // Paso 1: email + contraseña
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setError("")

    if (!email.trim()) { setError("Ingresa tu correo electrónico."); return }
    if (!password.trim() || password.length < 4) { setError("La contraseña debe tener al menos 4 caracteres."); return }

    setIsLoading(true)
    try {
      const r = await fetch(`${API}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
        signal: AbortSignal.timeout(8000),
      })
      if (!r.ok) {
        const d = await r.json().catch(() => ({}))
        setError(d.detail ?? "Correo o contraseña incorrectos.")
        return
      }
      const data = await r.json()

      if (data.require_totp) {
        setTempToken(data.temp_token)
        setStep("totp")
      } else {
        onLogin(data.access_token, data.user)
      }
    } catch (err) {
      if (err instanceof Error && err.name === "TimeoutError") {
        setError("No se puede conectar al servidor. Verifica que el backend esté corriendo en :8000.")
      } else {
        setError("Error de conexión. Intenta nuevamente.")
      }
    } finally {
      setIsLoading(false)
    }
  }

  // Paso 2: código TOTP de Microsoft Authenticator
  const handleTotpSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setError("")

    if (totpCode.length !== 6 || !/^\d+$/.test(totpCode)) {
      setError("El código debe tener exactamente 6 dígitos.")
      return
    }

    setIsLoading(true)
    try {
      const r = await fetch(`${API}/api/auth/verify-totp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ temp_token: tempToken, code: totpCode }),
        signal: AbortSignal.timeout(8000),
      })
      if (!r.ok) {
        const d = await r.json().catch(() => ({}))
        setError(d.detail ?? "Código incorrecto. Intenta de nuevo.")
        setTotpCode("")
        return
      }
      const { access_token, user } = await r.json()
      onLogin(access_token, user)
    } catch (err) {
      if (err instanceof Error && err.name === "TimeoutError") {
        setError("No se puede conectar al servidor.")
      } else {
        setError("Error de conexión. Intenta nuevamente.")
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-background relative overflow-hidden">
      {/* Glow de fondo sutil */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(249,115,22,0.08) 0%, transparent 70%)" }} />
        <div className="absolute bottom-0 left-0 w-80 h-80 rounded-full"
          style={{ background: "radial-gradient(circle, rgba(249,115,22,0.05) 0%, transparent 70%)" }} />
      </div>

      {/* Grid sutil */}
      <div className="pointer-events-none absolute inset-0"
        style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.012) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.012) 1px, transparent 1px)", backgroundSize: "60px 60px" }} />

      {/* Header */}
      <header className="relative z-10 px-8 py-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: "rgba(249,115,22,0.15)", border: "1px solid rgba(249,115,22,0.3)" }}>
            <Shield className="w-5 h-5" style={{ color: "#f97316" }} />
          </div>
          <span className="text-lg font-bold tracking-widest text-white">CARONTE</span>
        </div>
      </header>

      {/* Contenido centrado */}
      <main className="relative z-10 flex-1 flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-[420px]">

          {/* Título */}
          <div className="mb-10 text-center">
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium mb-6"
              style={{ background: "rgba(249,115,22,0.1)", border: "1px solid rgba(249,115,22,0.25)", color: "#f97316" }}>
              <span className="w-1.5 h-1.5 rounded-full bg-orange-400 animate-pulse inline-block" />
              Sistema activo
            </div>
            <h1 className="text-3xl font-bold text-white leading-tight mb-3">
              Bienvenido a<br />
              <span style={{ color: "#f97316" }}>CARONTE</span>
            </h1>
            <p className="text-sm" style={{ color: "#888" }}>
              {step === "credentials"
                ? "Procesamiento inteligente de vulnerabilidades"
                : "Verificación en dos pasos"}
            </p>
          </div>

          {/* Card */}
          <div className="rounded-2xl p-8 space-y-5"
            style={{ background: "hsl(0 0% 7%)", border: "1px solid hsl(0 0% 14%)" }}>

            {/* Error */}
            {error && (
              <div className="flex items-start gap-3 p-3.5 rounded-xl text-sm"
                style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.25)", color: "#f87171" }}>
                <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* ── Paso 1: credenciales ── */}
            {step === "credentials" && (
              <form onSubmit={handleSubmit} className="space-y-5">
                <div className="space-y-1.5">
                  <Label htmlFor="email" className="text-sm font-medium" style={{ color: "#ccc" }}>
                    Correo electrónico
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="usuario@fiduprevisora.com.co"
                    value={email}
                    onChange={e => { setEmail(e.target.value); setError("") }}
                    required
                    disabled={isLoading}
                    className="h-11 text-sm"
                    style={{ background: "#0a0a0a", borderColor: error ? "rgba(239,68,68,0.5)" : "hsl(0 0% 14%)", color: "#fff" }}
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="password" className="text-sm font-medium" style={{ color: "#ccc" }}>
                    Contraseña
                  </Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••"
                      value={password}
                      onChange={e => { setPassword(e.target.value); setError("") }}
                      required
                      disabled={isLoading}
                      className="h-11 text-sm pr-11"
                      style={{ background: "#0a0a0a", borderColor: error ? "rgba(239,68,68,0.5)" : "hsl(0 0% 14%)", color: "#fff" }}
                    />
                    <button type="button" tabIndex={-1}
                      onClick={() => setShowPassword(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                      style={{ color: "#666" }}>
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full h-11 rounded-xl font-semibold text-sm text-white transition-all duration-200 disabled:opacity-60 disabled:cursor-not-allowed"
                  style={{ background: isLoading ? "rgba(249,115,22,0.6)" : "#f97316" }}
                  onMouseEnter={e => { if (!isLoading) (e.currentTarget as HTMLButtonElement).style.background = "#ea6c10" }}
                  onMouseLeave={e => { if (!isLoading) (e.currentTarget as HTMLButtonElement).style.background = "#f97316" }}
                >
                  {isLoading ? (
                    <span className="flex items-center justify-center gap-2">
                      <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin inline-block" />
                      Verificando...
                    </span>
                  ) : "Acceder al sistema"}
                </button>
              </form>
            )}

            {/* ── Paso 2: código TOTP ── */}
            {step === "totp" && (
              <form onSubmit={handleTotpSubmit} className="space-y-5">
                <div className="flex flex-col items-center gap-3 py-2">
                  <div className="w-12 h-12 rounded-xl flex items-center justify-center"
                    style={{ background: "rgba(249,115,22,0.15)", border: "1px solid rgba(249,115,22,0.3)" }}>
                    <KeyRound className="w-6 h-6" style={{ color: "#f97316" }} />
                  </div>
                  <p className="text-sm text-center" style={{ color: "#aaa" }}>
                    Abre <strong style={{ color: "#fff" }}>Microsoft Authenticator</strong> e ingresa
                    el código de 6 dígitos de la cuenta <strong style={{ color: "#f97316" }}>CARONTE</strong>.
                  </p>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="totp" className="text-sm font-medium" style={{ color: "#ccc" }}>
                    Código de verificación
                  </Label>
                  <Input
                    id="totp"
                    type="text"
                    inputMode="numeric"
                    placeholder="000000"
                    maxLength={6}
                    value={totpCode}
                    onChange={e => { setTotpCode(e.target.value.replace(/\D/g, "")); setError("") }}
                    required
                    disabled={isLoading}
                    autoFocus
                    className="h-11 text-sm text-center tracking-[0.5em] font-mono"
                    style={{ background: "#0a0a0a", borderColor: error ? "rgba(239,68,68,0.5)" : "hsl(0 0% 14%)", color: "#fff" }}
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLoading || totpCode.length !== 6}
                  className="w-full h-11 rounded-xl font-semibold text-sm text-white transition-all duration-200 disabled:opacity-60 disabled:cursor-not-allowed"
                  style={{ background: isLoading ? "rgba(249,115,22,0.6)" : "#f97316" }}
                  onMouseEnter={e => { if (!isLoading) (e.currentTarget as HTMLButtonElement).style.background = "#ea6c10" }}
                  onMouseLeave={e => { if (!isLoading) (e.currentTarget as HTMLButtonElement).style.background = "#f97316" }}
                >
                  {isLoading ? (
                    <span className="flex items-center justify-center gap-2">
                      <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin inline-block" />
                      Verificando...
                    </span>
                  ) : "Confirmar código"}
                </button>

                <button
                  type="button"
                  onClick={() => { setStep("credentials"); setError(""); setTotpCode(""); setTempToken("") }}
                  className="w-full text-xs text-center transition-colors"
                  style={{ color: "#555" }}
                  onMouseEnter={e => (e.currentTarget.style.color = "#f97316")}
                  onMouseLeave={e => (e.currentTarget.style.color = "#555")}
                >
                  ← Volver al inicio de sesión
                </button>
              </form>
            )}

            {step === "credentials" && (
              <p className="text-center text-xs pt-1" style={{ color: "#555" }}>
                ¿Olvidaste tus credenciales? Contacta al administrador
              </p>
            )}
          </div>

          <p className="text-center text-xs mt-6" style={{ color: "#444" }}>
            ¿Problemas de acceso?{" "}
            <a href="#" style={{ color: "#f97316" }} className="hover:underline">Contacta soporte</a>
          </p>
        </div>
      </main>

      <footer className="relative z-10 px-8 py-5 text-center">
        <p className="text-xs" style={{ color: "#333" }}>
          © 2025 Fiduprevisora S.A. — Dirección de Ciberseguridad
        </p>
      </footer>
    </div>
  )
}
