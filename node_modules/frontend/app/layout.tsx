import type { Metadata } from "next"
import "./globals.css"

export const metadata: Metadata = {
  title: "CARONTE — Sistema de Procesamiento de Vulnerabilidades",
  description: "Automatiza la documentación de reportes de seguridad con IA",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es" className="dark">
      <body>{children}</body>
    </html>
  )
}
