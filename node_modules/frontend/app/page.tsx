"use client"

import { useState, useEffect } from "react"
import { LoginForm } from "@/components/login-form"
import { Dashboard } from "@/components/dashboard"
import { Shield } from "lucide-react"

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
export const TOKEN_KEY = "caronte_token"

export interface UserInfo { email: string; name: string; role: string }

export default function Home() {
  const [user,     setUser]     = useState<UserInfo | null>(null)
  const [token,    setToken]    = useState<string>("")
  const [checking, setChecking] = useState(true)

  // Verificar token guardado al montar
  useEffect(() => {
    const verify = async () => {
      const stored = localStorage.getItem(TOKEN_KEY)
      if (!stored) { setChecking(false); return }
      try {
        const r = await fetch(`${API}/api/auth/me`, {
          headers: { Authorization: `Bearer ${stored}` },
          signal:  AbortSignal.timeout(5000),
        })
        if (r.ok) {
          const data: UserInfo = await r.json()
          setToken(stored)
          setUser(data)
        } else {
          localStorage.removeItem(TOKEN_KEY)
        }
      } catch {
        localStorage.removeItem(TOKEN_KEY)
      } finally {
        setChecking(false)
      }
    }
    verify()
  }, [])

  const handleLogin = (newToken: string, userData: UserInfo) => {
    localStorage.setItem(TOKEN_KEY, newToken)
    setToken(newToken)
    setUser(userData)
  }

  const handleLogout = () => {
    localStorage.removeItem(TOKEN_KEY)
    setToken("")
    setUser(null)
  }

  if (checking) {
    return (
      <div style={{
        minHeight: "100vh", background: "#080808",
        display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center", gap: 16,
      }}>
        <div style={{
          width: 40, height: 40, borderRadius: 12,
          background: "rgba(249,115,22,0.1)",
          border: "1px solid rgba(249,115,22,0.25)",
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <Shield style={{ width: 20, height: 20, color: "#f97316" }} />
        </div>
        <div style={{
          width: 24, height: 24,
          border: "2px solid #1e1e1e",
          borderTop: "2px solid #f97316",
          borderRadius: "50%",
          animation: "spin 0.7s linear infinite",
        }} />
        <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      </div>
    )
  }

  if (user && token) {
    return (
      <Dashboard
        userName={user.name}
        userEmail={user.email}
        userRole={user.role}
        token={token}
        onLogout={handleLogout}
      />
    )
  }

  return <LoginForm onLogin={handleLogin} />
}
