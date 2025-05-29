"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, Eye, EyeOff, Lock, Mail } from "lucide-react"
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
      setError("Invalid email or password. Please try again.")
    }

    setIsLoading(false)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 relative overflow-hidden">
      {/* Animated Background Pattern */}
      <div className="absolute inset-0 opacity-10">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fillRule='evenodd'%3E%3Cg fill='%23ef4444' fillOpacity='0.1'%3E%3Ccircle cx='30' cy='30' r='2'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
          }}
        />
      </div>

      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-900/50 backdrop-blur-sm relative z-10">
        <div className="container mx-auto px-4 py-4">
          <nav className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-red-500" />
              <span className="text-xl font-bold text-white">Ye Yint Thu</span>
            </div>
            <div className="flex items-center space-x-6">
              <Link href="/" className="text-slate-300 hover:text-white transition-colors">
                Home
              </Link>
              <Link href="/blog" className="text-slate-300 hover:text-white transition-colors">
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
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="text-center">
              <div className="mx-auto mb-4 p-3 bg-red-900/20 rounded-full border border-red-700">
                <Lock className="h-8 w-8 text-red-400" />
              </div>
              <CardTitle className="text-2xl font-bold text-white">Admin Login</CardTitle>
              <CardDescription className="text-slate-400">Access the blog administration panel</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleLogin} className="space-y-6">
                {error && (
                  <div className="p-3 bg-red-900/20 border border-red-700 rounded-md">
                    <p className="text-red-400 text-sm text-center">{error}</p>
                  </div>
                )}

                <div className="space-y-4">
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-slate-300 mb-2">
                      Email Address
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
                      <input
                        id="email"
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="Enter your email"
                        className="w-full pl-10 pr-4 py-3 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-colors"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="password" className="block text-sm font-medium text-slate-300 mb-2">
                      Password
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
                      <input
                        id="password"
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter your password"
                        className="w-full pl-10 pr-12 py-3 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-colors"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-slate-300 transition-colors"
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                </div>

                <Button
                  type="submit"
                  disabled={isLoading}
                  className="w-full bg-red-600 hover:bg-red-700 text-white py-3 font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? (
                    <div className="flex items-center justify-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Signing In...
                    </div>
                  ) : (
                    "Sign In"
                  )}
                </Button>
              </form>

              {/* Demo Credentials */}
              <div className="mt-6 p-4 bg-slate-700/30 rounded-md border border-slate-600">
                <h4 className="text-sm font-medium text-slate-300 mb-2">Demo Credentials:</h4>
                <div className="space-y-1 text-xs text-slate-400">
                  <p>
                    <span className="font-medium">Email:</span> jrbx4@osi.com
                  </p>
                  <p>
                    <span className="font-medium">Password:</span> OSI_SecureAdmin_2024_jrBX4!
                  </p>
                </div>
              </div>

              {/* Security Notice */}
              <div className="mt-4 text-center">
                <p className="text-xs text-slate-500">
                  This is a secure admin area. Unauthorized access is prohibited.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Back to Portfolio */}
          <div className="text-center mt-6">
            <Link
              href="/"
              className="text-slate-400 hover:text-white transition-colors text-sm inline-flex items-center"
            >
              ← Back to Portfolio
            </Link>
          </div>
        </div>
      </div>

      {/* Floating Security Elements */}
      <div className="absolute top-20 left-10 opacity-20">
        <Shield className="h-16 w-16 text-red-500 animate-pulse" />
      </div>
      <div className="absolute bottom-20 right-10 opacity-20">
        <Lock className="h-12 w-12 text-red-500 animate-pulse" style={{ animationDelay: "1s" }} />
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-700 bg-slate-900/50 py-6 px-4 relative z-10">
        <div className="container mx-auto text-center">
          <p className="text-slate-400 text-sm">
            © {new Date().getFullYear()} Ye Yint Thu. All rights reserved. | Secure Admin Access
          </p>
        </div>
      </footer>
    </div>
  )
}
