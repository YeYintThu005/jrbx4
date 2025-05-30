"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skull, Eye, EyeOff, Lock, Mail, Terminal, Wifi, Shield } from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"

export default function LoginPage() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setIsLoading(true)

    // Simulate loading delay
    await new Promise((resolve) => setTimeout(resolve, 1000))

    // Check credentials
    if (email === "jrbx4@osi.com" && password === "OSI_SecureAdmin_2024_jrBX4!") {
      // Set authentication token
      localStorage.setItem("adminAuth", "authenticated")
      localStorage.setItem("adminEmail", email)

      // Redirect to blog upload page
      router.push("/blog-upload")
    } else {
      setError("Access denied. Invalid credentials detected.")
    }

    setIsLoading(false)
  }

  return (
    <div className="min-h-screen bg-black text-white relative overflow-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        {/* Moving red particles */}
        <div className="absolute inset-0">
          {[...Array(15)].map((_, i) => (
            <div
              key={i}
              className="absolute w-1 h-1 bg-red-500 rounded-full opacity-40 animate-pulse"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 3}s`,
                animationDuration: `${3 + Math.random() * 2}s`,
              }}
            />
          ))}
        </div>

        {/* Moving red lines */}
        <div className="absolute inset-0 opacity-10">
          <svg className="w-full h-full">
            <defs>
              <linearGradient id="redGlow" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#dc2626" />
                <stop offset="100%" stopColor="#991b1b" />
              </linearGradient>
            </defs>
            <path
              d="M0,50 Q200,25 400,50 T800,50"
              stroke="url(#redGlow)"
              strokeWidth="2"
              fill="none"
              className="animate-pulse"
            />
            <path
              d="M0,150 Q300,125 600,150 T1200,150"
              stroke="url(#redGlow)"
              strokeWidth="1"
              fill="none"
              className="animate-pulse"
              style={{ animationDelay: "1s" }}
            />
          </svg>
        </div>

        {/* Grid pattern */}
        <div
          className="absolute inset-0 opacity-5"
          style={{
            backgroundImage: `
              linear-gradient(rgba(220, 38, 38, 0.3) 1px, transparent 1px),
              linear-gradient(90deg, rgba(220, 38, 38, 0.3) 1px, transparent 1px)
            `,
            backgroundSize: "30px 30px",
          }}
        />
      </div>

      {/* Header */}
      <header className="border-b border-red-900/30 bg-black/90 backdrop-blur-xl relative z-10">
        <div className="container mx-auto px-4 py-4">
          <nav className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              {/* jrBX4 Logo */}
              <div className="relative group">
                <div className="flex items-center space-x-3 p-3 bg-gradient-to-r from-red-900/40 to-black/60 rounded-lg border border-red-600/40 shadow-lg backdrop-blur-sm">
                  <div className="relative">
                    <div className="p-2 bg-red-600/20 rounded-lg border border-red-500/30">
                      <Skull className="h-7 w-7 text-red-400" />
                    </div>
                    <div className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                  </div>
                  <div>
                    <div className="text-xl font-bold bg-gradient-to-r from-red-400 to-red-600 bg-clip-text text-transparent">
                      jrBX4
                    </div>
                    <div className="text-xs text-red-400 font-medium">Admin Access</div>
                  </div>
                </div>
                <div className="absolute inset-0 bg-red-500/10 rounded-lg blur-md opacity-0 group-hover:opacity-100 transition-opacity"></div>
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-white to-red-200 bg-clip-text text-transparent">
                Ye Yint Thu
              </span>
            </div>
            <div className="flex items-center space-x-6">
              <Link href="/" className="text-gray-300 hover:text-red-400 transition-colors">
                Home
              </Link>
              <Link href="/blog" className="text-gray-300 hover:text-red-400 transition-colors">
                Blog
              </Link>
            </div>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex items-center justify-center min-h-[calc(100vh-80px)] px-4 relative z-10">
        <div className="w-full max-w-md">
          {/* Login Card */}
          <Card className="bg-black/50 border border-red-900/30 backdrop-blur-sm shadow-lg shadow-red-500/10">
            <CardHeader className="text-center">
              <div className="mx-auto mb-4 p-4 bg-red-900/30 rounded-full border border-red-700/40">
                <Terminal className="h-10 w-10 text-red-400" />
              </div>
              <CardTitle className="text-3xl font-bold bg-gradient-to-r from-white to-red-200 bg-clip-text text-transparent">
                Elite Access
              </CardTitle>
              <CardDescription className="text-gray-400">Restricted admin portal for elite operations</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleLogin} className="space-y-6">
                {error && (
                  <div className="p-4 bg-black/50 border border-red-900/30 rounded-lg backdrop-blur-sm">
                    <p className="text-red-400 text-sm text-center font-medium">{error}</p>
                  </div>
                )}

                <div className="space-y-4">
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                      Email Credentials
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-red-400" />
                      <input
                        id="email"
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="Enter elite credentials"
                        className="w-full pl-10 pr-4 py-3 bg-gray-900/50 border border-red-700/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-colors backdrop-blur-sm"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2">
                      Access Code
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-red-400" />
                      <input
                        id="password"
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter secure access code"
                        className="w-full pl-10 pr-12 py-3 bg-gray-900/50 border border-red-700/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-colors backdrop-blur-sm"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 transform -translate-y-1/2 text-red-400 hover:text-red-300 transition-colors"
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                </div>

                <Button
                  type="submit"
                  disabled={isLoading}
                  className="w-full bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white py-3 font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-red-500/25"
                >
                  {isLoading ? (
                    <div className="flex items-center justify-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Authenticating...
                    </div>
                  ) : (
                    <div className="flex items-center justify-center">
                      <Shield className="mr-2 h-4 w-4" />
                      Initiate Access
                    </div>
                  )}
                </Button>
              </form>

              {/* Demo Credentials */}
              <div className="mt-6 p-4 bg-red-900/20 rounded-lg border border-red-700/30 backdrop-blur-sm">
                <h4 className="text-sm font-medium text-red-300 mb-2 flex items-center">
                  <Wifi className="mr-2 h-3 w-3" />
                  Elite Credentials:
                </h4>
                <div className="space-y-1 text-xs text-gray-400">
                  <p>
                    <span className="font-medium text-red-400">Email:</span> jrbx4@osi.com
                  </p>
                  <p>
                    <span className="font-medium text-red-400">Code:</span> OSI_SecureAdmin_2024_jrBX4!
                  </p>
                </div>
              </div>

              {/* Security Notice */}
              <div className="mt-4 text-center">
                <p className="text-xs text-gray-500">
                  Restricted access. Unauthorized intrusion attempts will be logged and traced.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Back to Portfolio */}
          <div className="text-center mt-6">
            <Link
              href="/"
              className="text-gray-400 hover:text-red-400 transition-colors text-sm inline-flex items-center"
            >
              ← Return to Main Site
            </Link>
          </div>
        </div>
      </div>

      {/* Floating Security Elements */}
      <div className="absolute top-20 left-10 opacity-20">
        <Skull className="h-16 w-16 text-red-500 animate-pulse" />
      </div>
      <div className="absolute bottom-20 right-10 opacity-20">
        <Terminal className="h-12 w-12 text-red-500 animate-pulse" style={{ animationDelay: "1s" }} />
      </div>
      <div className="absolute top-1/2 right-20 opacity-15">
        <Lock className="h-8 w-8 text-red-500 animate-pulse" style={{ animationDelay: "2s" }} />
      </div>

      {/* Footer */}
      <footer className="border-t border-red-900/30 bg-black/90 py-6 px-4 relative z-10">
        <div className="container mx-auto text-center">
          <p className="text-gray-500 text-sm">
            © {new Date().getFullYear()} jrBX4 Elite Access Portal. Unauthorized access prohibited.
          </p>
        </div>
      </footer>
    </div>
  )
}
