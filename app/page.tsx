"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Shield,
  Target,
  Search,
  Lock,
  Server,
  Code,
  Award,
  ExternalLink,
  Mail,
  MapPin,
  Github,
  Linkedin,
  Download,
  ChevronDown,
  Eye,
  Calendar,
  Users,
  BookOpen,
  Send,
  Zap,
  Terminal,
  ArrowRight,
  Star,
  TrendingUp,
} from "lucide-react"
import Link from "next/link"

interface BlogPost {
  id: number
  title: string
  category: string
  status: string
  date: string
  views: string
  content: string
  featuredImage?: string
  slug: string
}

export default function HomePage() {
  const [posts, setPosts] = useState<BlogPost[]>([])
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    subject: "",
    message: "",
  })
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitStatus, setSubmitStatus] = useState<"idle" | "success" | "error">("idle")

  useEffect(() => {
    // Load latest blog posts
    const loadPosts = () => {
      const savedPosts = localStorage.getItem("blogPosts")
      if (savedPosts) {
        const parsedPosts = JSON.parse(savedPosts)
        const publishedPosts = parsedPosts
          .filter((post: BlogPost) => post.status === "published")
          .sort((a: BlogPost, b: BlogPost) => new Date(b.date).getTime() - new Date(a.date).getTime())
          .slice(0, 3) // Show only latest 3 posts
        setPosts(publishedPosts)
      } else {
        // Default posts if none saved
        setPosts([
          {
            id: 1,
            title: "Advanced SQL Injection Techniques",
            category: "Web Security",
            status: "published",
            date: "Dec 15, 2024",
            views: "1.2k",
            content: "SQL injection remains one of the most critical vulnerabilities in web applications...",
            featuredImage: "/placeholder.svg?height=300&width=400",
            slug: "advanced-sql-injection-techniques",
          },
          {
            id: 2,
            title: "Active Directory Privilege Escalation",
            category: "Network Security",
            status: "published",
            date: "Dec 10, 2024",
            views: "890",
            content: "This guide covers common AD privilege escalation techniques...",
            featuredImage: "/placeholder.svg?height=300&width=400",
            slug: "active-directory-privilege-escalation",
          },
          {
            id: 3,
            title: "HTB Machine Writeup: Buffer Overflow",
            category: "CTF Writeup",
            status: "published",
            date: "Nov 28, 2024",
            views: "654",
            content: "Step-by-step walkthrough of exploiting a custom binary...",
            featuredImage: "/placeholder.svg?height=300&width=400",
            slug: "htb-machine-writeup-buffer-overflow",
          },
        ])
      }
    }

    loadPosts()

    // Listen for storage changes
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === "blogPosts") {
        loadPosts()
      }
    }

    window.addEventListener("storage", handleStorageChange)
    return () => window.removeEventListener("storage", handleStorageChange)
  }, [])

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    setSubmitStatus("idle")

    try {
      // Create mailto link with form data
      const subject = encodeURIComponent(formData.subject || "Contact Form Submission")
      const body = encodeURIComponent(`
Name: ${formData.firstName} ${formData.lastName}
Email: ${formData.email}
Subject: ${formData.subject}

Message:
${formData.message}

---
Sent from Ye Yint Thu's Portfolio Contact Form
      `)

      const mailtoLink = `mailto:yeyintthu.mst@gmail.com?subject=${subject}&body=${body}`

      // Open email client
      window.location.href = mailtoLink

      // Reset form after a short delay
      setTimeout(() => {
        setFormData({
          firstName: "",
          lastName: "",
          email: "",
          subject: "",
          message: "",
        })
        setSubmitStatus("success")
        setIsSubmitting(false)
      }, 1000)
    } catch (error) {
      setSubmitStatus("error")
      setIsSubmitting(false)
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case "Web Security":
        return "bg-red-500/10 text-red-400 border-red-500/20"
      case "Network Security":
        return "bg-blue-500/10 text-blue-400 border-blue-500/20"
      case "CTF Writeup":
        return "bg-green-500/10 text-green-400 border-green-500/20"
      case "Cloud Security":
        return "bg-orange-500/10 text-orange-400 border-orange-500/20"
      case "Tools & Techniques":
        return "bg-purple-500/10 text-purple-400 border-purple-500/20"
      case "Research":
        return "bg-indigo-500/10 text-indigo-400 border-indigo-500/20"
      default:
        return "bg-gray-500/10 text-gray-400 border-gray-500/20"
    }
  }

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute inset-0 bg-gradient-to-br from-red-900/5 via-black to-blue-900/5"></div>
        <div className="absolute top-0 left-0 w-full h-full">
          <div className="absolute top-20 left-20 w-72 h-72 bg-red-500/5 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute bottom-20 right-20 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl animate-pulse delay-1000"></div>
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-purple-500/5 rounded-full blur-3xl animate-pulse delay-500"></div>
        </div>
      </div>

      {/* Header */}
      <header className="relative z-50 border-b border-gray-800/50 bg-black/80 backdrop-blur-xl sticky top-0">
        <div className="container mx-auto px-6 py-4">
          <nav className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <Shield className="h-10 w-10 text-red-500" />
                <div className="absolute inset-0 bg-red-500/20 rounded-full blur-lg"></div>
              </div>
              <div>
                <span className="text-2xl font-bold bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
                  Ye Yint Thu
                </span>
                <div className="text-xs text-red-400 font-medium">PENETRATION TESTER</div>
              </div>
            </div>
            <div className="hidden md:flex space-x-8">
              <a href="#home" className="text-red-400 font-medium hover:text-red-300 transition-colors">
                Home
              </a>
              <a href="#about" className="text-gray-300 hover:text-white transition-colors">
                About
              </a>
              <a href="#services" className="text-gray-300 hover:text-white transition-colors">
                Services
              </a>
              <Link href="/blog" className="text-gray-300 hover:text-white transition-colors">
                Blog
              </Link>
              <a href="#contact" className="text-gray-300 hover:text-white transition-colors">
                Contact
              </a>
            </div>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section id="home" className="relative py-32 px-6 overflow-hidden">
        <div className="container mx-auto relative z-10">
          <div className="max-w-6xl mx-auto">
            <div className="grid lg:grid-cols-2 gap-16 items-center">
              <div className="space-y-8">
                <div className="space-y-4">
                  <Badge className="bg-red-500/10 text-red-400 border-red-500/20 hover:bg-red-500/20">
                    <a
                      href="https://www.offsecinitiative.net"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center space-x-2"
                    >
                      <Zap className="h-3 w-3" />
                      <span>OSI Team Member</span>
                    </a>
                  </Badge>
                  <h1 className="text-6xl md:text-8xl font-black">
                    <span className="bg-gradient-to-r from-white via-gray-200 to-gray-400 bg-clip-text text-transparent">
                      YE YINT
                    </span>
                    <br />
                    <span className="bg-gradient-to-r from-red-500 via-red-400 to-orange-500 bg-clip-text text-transparent">
                      THU
                    </span>
                  </h1>
                  <div className="flex items-center space-x-4">
                    <div className="h-px bg-gradient-to-r from-red-500 to-transparent w-16"></div>
                    <p className="text-xl text-gray-400 font-light">Cybersecurity Specialist</p>
                  </div>
                </div>
                <p className="text-lg text-gray-300 leading-relaxed max-w-lg">
                  Ethical hacker and penetration tester specializing in web application security, network
                  infrastructure, and vulnerability research. Passionate about strengthening digital defenses.
                </p>
                <div className="flex flex-col sm:flex-row gap-4">
                  <Button
                    onClick={() => document.getElementById("contact")?.scrollIntoView({ behavior: "smooth" })}
                    className="bg-gradient-to-r from-red-600 to-red-500 hover:from-red-700 hover:to-red-600 text-white px-8 py-4 text-lg font-medium group"
                  >
                    <Mail className="mr-2 h-5 w-5" />
                    Let's Connect
                    <ArrowRight className="ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform" />
                  </Button>
                  <Button
                    variant="outline"
                    className="border-gray-700 text-gray-300 hover:bg-gray-800 hover:text-white px-8 py-4 text-lg"
                  >
                    <Download className="mr-2 h-5 w-5" />
                    Download CV
                  </Button>
                </div>
                <div className="flex items-center space-x-6 pt-4">
                  <a
                    href="https://github.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-3 bg-gray-900/50 border border-gray-800 rounded-xl hover:bg-gray-800 hover:border-gray-700 transition-all group"
                  >
                    <Github className="h-6 w-6 text-gray-400 group-hover:text-white" />
                  </a>
                  <a
                    href="https://www.linkedin.com/in/ye-yint-thu-5a808a278/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-3 bg-gray-900/50 border border-gray-800 rounded-xl hover:bg-gray-800 hover:border-gray-700 transition-all group"
                  >
                    <Linkedin className="h-6 w-6 text-gray-400 group-hover:text-white" />
                  </a>
                  <a
                    href="https://app.hackthebox.com/users/1644532"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-3 bg-gray-900/50 border border-gray-800 rounded-xl hover:bg-gray-800 hover:border-gray-700 transition-all group"
                  >
                    <Target className="h-6 w-6 text-gray-400 group-hover:text-white" />
                  </a>
                </div>
              </div>
              <div className="relative">
                <div className="relative z-10">
                  <div className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border border-gray-800/50 rounded-3xl p-8">
                    <div className="space-y-6">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                          <span className="text-gray-400 text-sm font-mono">SYSTEM STATUS</span>
                        </div>
                        <Badge className="bg-green-500/10 text-green-400 border-green-500/20">ONLINE</Badge>
                      </div>
                      <div className="space-y-4">
                        <div className="flex justify-between items-center">
                          <span className="text-gray-300">Penetration Tests</span>
                          <span className="text-white font-bold">150+</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-gray-300">Vulnerabilities Found</span>
                          <span className="text-white font-bold">500+</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-gray-300">Security Reports</span>
                          <span className="text-white font-bold">75+</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-gray-300">HTB Rank</span>
                          <span className="text-red-400 font-bold">jrBX4</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="absolute inset-0 bg-gradient-to-br from-red-500/10 to-blue-500/10 rounded-3xl blur-3xl"></div>
              </div>
            </div>
          </div>
        </div>
        <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 animate-bounce">
          <ChevronDown className="h-6 w-6 text-gray-500" />
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="relative py-32 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-5xl font-bold mb-6">
                <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">About Me</span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Dedicated cybersecurity professional with expertise in penetration testing, vulnerability assessment,
                and security research.
              </p>
            </div>
            <div className="grid lg:grid-cols-3 gap-8">
              <div className="lg:col-span-2 space-y-8">
                <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                  <CardHeader>
                    <CardTitle className="text-2xl text-white flex items-center">
                      <Terminal className="mr-3 h-6 w-6 text-red-500" />
                      Professional Background
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-gray-300 leading-relaxed">
                      As a penetration tester and cybersecurity specialist, I focus on identifying security
                      vulnerabilities in web applications, networks, and systems. My approach combines technical
                      expertise with creative problem-solving to uncover potential attack vectors.
                    </p>
                    <div className="grid grid-cols-2 gap-6 pt-4">
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-red-500/10 rounded-lg">
                          <Target className="h-5 w-5 text-red-400" />
                        </div>
                        <span className="text-gray-300">Web App Testing</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-blue-500/10 rounded-lg">
                          <Server className="h-5 w-5 text-blue-400" />
                        </div>
                        <span className="text-gray-300">Network Security</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-green-500/10 rounded-lg">
                          <Search className="h-5 w-5 text-green-400" />
                        </div>
                        <span className="text-gray-300">Vulnerability Assessment</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-purple-500/10 rounded-lg">
                          <Code className="h-5 w-5 text-purple-400" />
                        </div>
                        <span className="text-gray-300">Security Research</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                  <CardHeader>
                    <CardTitle className="text-2xl text-white flex items-center">
                      <Users className="mr-3 h-6 w-6 text-red-500" />
                      OSI Team Member
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-gray-300 leading-relaxed">
                      Proud member of the{" "}
                      <a
                        href="https://www.offsecinitiative.net"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-red-400 hover:text-red-300 underline"
                      >
                        OSI (Offensive Security Initiative)
                      </a>{" "}
                      team, collaborating on cutting-edge security research and contributing to the cybersecurity
                      community through innovative methodologies and knowledge sharing.
                    </p>
                  </CardContent>
                </Card>
              </div>
              <div className="space-y-8">
                <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                  <CardHeader>
                    <CardTitle className="text-xl text-white flex items-center">
                      <Award className="mr-3 h-5 w-5 text-red-500" />
                      Certifications
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-medium">eCPPT v2</span>
                      <Badge className="bg-green-500/10 text-green-400 border-green-500/20">
                        <Star className="mr-1 h-3 w-3" />
                        Certified
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-medium">CRTA</span>
                      <Badge className="bg-green-500/10 text-green-400 border-green-500/20">
                        <Star className="mr-1 h-3 w-3" />
                        Certified
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-medium">CPTS</span>
                      <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
                        <TrendingUp className="mr-1 h-3 w-3" />
                        In Progress
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                  <CardHeader>
                    <CardTitle className="text-xl text-white flex items-center">
                      <Target className="mr-3 h-5 w-5 text-red-500" />
                      Hack The Box
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div>
                        <p className="text-gray-300 font-medium">Username: jrBX4</p>
                        <p className="text-gray-500 text-sm">Active CTF participant</p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full border-gray-700 text-gray-300 hover:bg-gray-800"
                        onClick={() =>
                          window.open("https://app.hackthebox.com/users/1644532", "_blank", "noopener,noreferrer")
                        }
                      >
                        <ExternalLink className="mr-2 h-4 w-4" />
                        View Profile
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section id="services" className="relative py-32 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-5xl font-bold mb-6">
                <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">Services</span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Comprehensive cybersecurity services to protect your digital assets and infrastructure.
              </p>
            </div>
            <div className="grid md:grid-cols-3 gap-8">
              <Card className="group bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50 hover:border-red-500/30 transition-all duration-300">
                <CardHeader>
                  <div className="p-4 bg-red-500/10 rounded-2xl w-fit group-hover:bg-red-500/20 transition-colors">
                    <Target className="h-8 w-8 text-red-400" />
                  </div>
                  <CardTitle className="text-xl text-white">Penetration Testing</CardTitle>
                  <CardDescription className="text-gray-400">
                    Comprehensive security assessments to identify vulnerabilities in your systems and applications.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Web Application Testing
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Network Infrastructure
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Mobile Applications
                    </li>
                  </ul>
                </CardContent>
              </Card>

              <Card className="group bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50 hover:border-blue-500/30 transition-all duration-300">
                <CardHeader>
                  <div className="p-4 bg-blue-500/10 rounded-2xl w-fit group-hover:bg-blue-500/20 transition-colors">
                    <Search className="h-8 w-8 text-blue-400" />
                  </div>
                  <CardTitle className="text-xl text-white">Vulnerability Assessment</CardTitle>
                  <CardDescription className="text-gray-400">
                    Systematic evaluation of security weaknesses in your IT infrastructure and applications.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
                      Automated Scanning
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
                      Manual Testing
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
                      Risk Assessment
                    </li>
                  </ul>
                </CardContent>
              </Card>

              <Card className="group bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50 hover:border-green-500/30 transition-all duration-300">
                <CardHeader>
                  <div className="p-4 bg-green-500/10 rounded-2xl w-fit group-hover:bg-green-500/20 transition-colors">
                    <Lock className="h-8 w-8 text-green-400" />
                  </div>
                  <CardTitle className="text-xl text-white">Security Consulting</CardTitle>
                  <CardDescription className="text-gray-400">
                    Expert guidance on security best practices and compliance requirements.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                      Security Architecture
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                      Compliance Audits
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                      Training & Awareness
                    </li>
                  </ul>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Latest Blog Posts */}
      <section className="relative py-32 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-5xl font-bold mb-6">
                <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                  Latest Insights
                </span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Recent articles on cybersecurity, penetration testing, and security research.
              </p>
            </div>
            {posts.length > 0 ? (
              <div className="grid md:grid-cols-3 gap-8">
                {posts.map((post) => (
                  <Card
                    key={post.id}
                    className="group bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50 hover:border-gray-700/50 transition-all duration-300 overflow-hidden"
                  >
                    <div className="aspect-video overflow-hidden">
                      <img
                        src={post.featuredImage || "/placeholder.svg?height=200&width=350"}
                        alt="Blog post"
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                      />
                    </div>
                    <CardHeader>
                      <div className="flex items-center justify-between mb-3">
                        <Badge className={getCategoryColor(post.category)}>{post.category}</Badge>
                        <div className="flex items-center text-gray-500 text-sm">
                          <Calendar className="mr-1 h-3 w-3" />
                          {post.date}
                        </div>
                      </div>
                      <CardTitle className="text-white group-hover:text-red-400 transition-colors">
                        <Link href={`/blog/${post.slug}`} className="block">
                          {post.title}
                        </Link>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <CardDescription className="text-gray-400 mb-4">
                        {post.content.substring(0, 120)}...
                      </CardDescription>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center text-gray-500 text-sm">
                          <Eye className="mr-1 h-3 w-3" />
                          {post.views} views
                        </div>
                        <Link
                          href={`/blog/${post.slug}`}
                          className="text-red-400 hover:text-red-300 text-sm font-medium group"
                        >
                          Read More
                          <ArrowRight className="ml-1 h-3 w-3 inline group-hover:translate-x-1 transition-transform" />
                        </Link>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            ) : (
              <div className="text-center py-20">
                <BookOpen className="h-20 w-20 text-gray-700 mx-auto mb-6" />
                <p className="text-gray-400 text-xl">No blog posts available yet.</p>
                <p className="text-gray-600 text-sm mt-2">Check back soon for cybersecurity insights and tutorials.</p>
              </div>
            )}
            <div className="text-center mt-16">
              <Link href="/blog">
                <Button className="bg-gradient-to-r from-red-600 to-red-500 hover:from-red-700 hover:to-red-600 text-white px-8 py-4 text-lg">
                  <BookOpen className="mr-2 h-5 w-5" />
                  View All Posts
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Contact Section */}
      <section id="contact" className="relative py-32 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-5xl font-bold mb-6">
                <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                  Get In Touch
                </span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Ready to secure your digital assets? Let's discuss your cybersecurity needs.
              </p>
            </div>
            <div className="grid lg:grid-cols-2 gap-16">
              <div className="space-y-8">
                <div>
                  <h3 className="text-3xl font-bold text-white mb-8">Contact Information</h3>
                  <div className="space-y-6">
                    <div className="flex items-center space-x-4">
                      <div className="p-4 bg-red-500/10 rounded-2xl border border-red-500/20">
                        <Mail className="h-6 w-6 text-red-400" />
                      </div>
                      <div>
                        <p className="text-gray-300 font-medium text-lg">Email</p>
                        <a
                          href="mailto:yeyintthu.mst@gmail.com"
                          className="text-gray-400 hover:text-red-400 transition-colors"
                        >
                          yeyintthu.mst@gmail.com
                        </a>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="p-4 bg-blue-500/10 rounded-2xl border border-blue-500/20">
                        <MapPin className="h-6 w-6 text-blue-400" />
                      </div>
                      <div>
                        <p className="text-gray-300 font-medium text-lg">Location</p>
                        <p className="text-gray-400">Available for Remote Work</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="p-4 bg-green-500/10 rounded-2xl border border-green-500/20">
                        <Users className="h-6 w-6 text-green-400" />
                      </div>
                      <div>
                        <p className="text-gray-300 font-medium text-lg">Organization</p>
                        <a
                          href="https://www.offsecinitiative.net"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-gray-400 hover:text-green-400 transition-colors"
                        >
                          OSI Team Member
                        </a>
                      </div>
                    </div>
                  </div>
                </div>
                <div>
                  <h4 className="text-xl font-semibold text-white mb-6">Follow Me</h4>
                  <div className="flex space-x-4">
                    <a
                      href="https://github.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-4 bg-gray-900/50 border border-gray-800 rounded-2xl hover:bg-gray-800 hover:border-gray-700 transition-all group"
                    >
                      <Github className="h-6 w-6 text-gray-400 group-hover:text-white" />
                    </a>
                    <a
                      href="https://www.linkedin.com/in/ye-yint-thu-5a808a278/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-4 bg-gray-900/50 border border-gray-800 rounded-2xl hover:bg-gray-800 hover:border-gray-700 transition-all group"
                    >
                      <Linkedin className="h-6 w-6 text-gray-400 group-hover:text-white" />
                    </a>
                    <a
                      href="https://app.hackthebox.com/users/1644532"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-4 bg-gray-900/50 border border-gray-800 rounded-2xl hover:bg-gray-800 hover:border-gray-700 transition-all group"
                    >
                      <Target className="h-6 w-6 text-gray-400 group-hover:text-white" />
                    </a>
                  </div>
                </div>
              </div>
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardHeader>
                  <CardTitle className="text-2xl text-white">Send a Message</CardTitle>
                  <CardDescription className="text-gray-400">
                    Interested in cybersecurity services? Let's start a conversation.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {submitStatus === "success" && (
                    <div className="mb-6 p-4 bg-green-500/10 border border-green-500/20 rounded-xl">
                      <p className="text-green-400 text-sm">
                        Your email client should have opened. If not, please send an email directly to{" "}
                        <a href="mailto:yeyintthu.mst@gmail.com" className="underline">
                          yeyintthu.mst@gmail.com
                        </a>
                      </p>
                    </div>
                  )}
                  {submitStatus === "error" && (
                    <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl">
                      <p className="text-red-400 text-sm">
                        There was an error. Please send an email directly to{" "}
                        <a href="mailto:yeyintthu.mst@gmail.com" className="underline">
                          yeyintthu.mst@gmail.com
                        </a>
                      </p>
                    </div>
                  )}
                  <form onSubmit={handleSubmit} className="space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">First Name</label>
                        <input
                          type="text"
                          name="firstName"
                          value={formData.firstName}
                          onChange={handleInputChange}
                          className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                          placeholder="John"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">Last Name</label>
                        <input
                          type="text"
                          name="lastName"
                          value={formData.lastName}
                          onChange={handleInputChange}
                          className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                          placeholder="Doe"
                          required
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">Email</label>
                      <input
                        type="email"
                        name="email"
                        value={formData.email}
                        onChange={handleInputChange}
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                        placeholder="john@example.com"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">Subject</label>
                      <input
                        type="text"
                        name="subject"
                        value={formData.subject}
                        onChange={handleInputChange}
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                        placeholder="Security Assessment Inquiry"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">Message</label>
                      <textarea
                        rows={4}
                        name="message"
                        value={formData.message}
                        onChange={handleInputChange}
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent resize-none"
                        placeholder="Tell me about your cybersecurity needs..."
                        required
                      />
                    </div>
                    <Button
                      type="submit"
                      disabled={isSubmitting}
                      className="w-full bg-gradient-to-r from-red-600 to-red-500 hover:from-red-700 hover:to-red-600 text-white py-4 text-lg disabled:opacity-50"
                    >
                      {isSubmitting ? (
                        <div className="flex items-center justify-center">
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                          Sending...
                        </div>
                      ) : (
                        <>
                          <Send className="mr-2 h-5 w-5" />
                          Send Message
                          <ArrowRight className="ml-2 h-4 w-4" />
                        </>
                      )}
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative border-t border-gray-800/50 bg-black/80 backdrop-blur-xl py-12 px-6">
        <div className="container mx-auto text-center">
          <p className="text-gray-500">
            © {new Date().getFullYear()} Ye Yint Thu. All rights reserved. | Cybersecurity Professional
          </p>
        </div>
      </footer>
    </div>
  )
}
