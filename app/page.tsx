"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
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
  Briefcase,
  Shield,
  Skull,
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

interface Certification {
  id: number
  name: string
  status: "certified" | "in-progress" | "planned"
  date?: string
}

interface Experience {
  id: number
  title: string
  company: string
  period: string
  description: string
  current: boolean
}

export default function HomePage() {
  const [posts, setPosts] = useState<BlogPost[]>([])
  const [certifications, setCertifications] = useState<Certification[]>([])
  const [experiences, setExperiences] = useState<Experience[]>([])
  const [resumeFile, setResumeFile] = useState<string>("")
  const [resumeFileName, setResumeFileName] = useState<string>("")
  const [profileImage, setProfileImage] = useState<string>("")
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
    // Load data from localStorage
    const loadData = () => {
      // Load blog posts
      const savedPosts = localStorage.getItem("blogPosts")
      if (savedPosts) {
        const parsedPosts = JSON.parse(savedPosts)
        const publishedPosts = parsedPosts
          .filter((post: BlogPost) => post.status === "published")
          .sort((a: BlogPost, b: BlogPost) => new Date(b.date).getTime() - new Date(a.date).getTime())
          .slice(0, 3)
        setPosts(publishedPosts)
      } else {
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

      // Load certifications
      const savedCertifications = localStorage.getItem("certifications")
      if (savedCertifications) {
        setCertifications(JSON.parse(savedCertifications))
      } else {
        setCertifications([
          { id: 1, name: "eCPPT v2", status: "certified", date: "2024" },
          { id: 2, name: "CRTA", status: "certified", date: "2024" },
          { id: 3, name: "CPTS", status: "in-progress" },
        ])
      }

      // Load experiences
      const savedExperiences = localStorage.getItem("experiences")
      if (savedExperiences) {
        setExperiences(JSON.parse(savedExperiences))
      } else {
        setExperiences([
          {
            id: 1,
            title: "Penetration Tester",
            company: "OSI Team",
            period: "2023 - Present",
            description: "Conducting security assessments and vulnerability research",
            current: true,
          },
          {
            id: 2,
            title: "Security Researcher",
            company: "Independent",
            period: "2022 - 2023",
            description: "Bug bounty hunting and security research",
            current: false,
          },
        ])
      }

      // Load profile image
      const savedProfileImage = localStorage.getItem("profileImage")
      if (savedProfileImage) {
        setProfileImage(savedProfileImage)
      }

      // Load resume
      const savedResume = localStorage.getItem("resumeFile")
      const savedResumeFileName = localStorage.getItem("resumeFileName")
      if (savedResume && savedResumeFileName) {
        setResumeFile(savedResume)
        setResumeFileName(savedResumeFileName)
      }
    }

    loadData()

    // Listen for storage changes
    const handleStorageChange = (e: StorageEvent) => {
      if (["blogPosts", "certifications", "experiences", "resumeFile", "profileImage"].includes(e.key || "")) {
        loadData()
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
      window.location.href = mailtoLink

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

  const downloadResume = () => {
    if (resumeFile && resumeFileName) {
      const link = document.createElement("a")
      link.href = resumeFile
      link.download = resumeFileName
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    } else {
      alert("No resume available for download. Please contact the administrator.")
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case "Web Security":
        return "bg-red-500/20 text-red-300 border-red-500/30"
      case "Network Security":
        return "bg-red-600/20 text-red-400 border-red-600/30"
      case "CTF Writeup":
        return "bg-red-700/20 text-red-200 border-red-700/30"
      case "Cloud Security":
        return "bg-red-800/20 text-red-300 border-red-800/30"
      case "Tools & Techniques":
        return "bg-gray-700/20 text-gray-300 border-gray-700/30"
      case "Research":
        return "bg-gray-600/20 text-gray-300 border-gray-600/30"
      default:
        return "bg-gray-500/20 text-gray-300 border-gray-500/30"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "certified":
        return "bg-red-500/20 text-red-300 border-red-500/30"
      case "in-progress":
        return "bg-yellow-500/20 text-yellow-300 border-yellow-500/30"
      case "planned":
        return "bg-gray-500/20 text-gray-300 border-gray-500/30"
      default:
        return "bg-gray-500/20 text-gray-300 border-gray-500/30"
    }
  }

  return (
    <div className="min-h-screen bg-black text-white relative overflow-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        {/* Moving red particles */}
        <div className="absolute inset-0">
          {[...Array(20)].map((_, i) => (
            <div
              key={i}
              className="absolute w-2 h-2 bg-red-500 rounded-full opacity-30 animate-pulse"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 3}s`,
                animationDuration: `${3 + Math.random() * 2}s`,
              }}
            />
          ))}
        </div>

        {/* Moving gradient orbs */}
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-gradient-to-r from-red-600/20 to-red-800/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-gradient-to-r from-red-500/15 to-red-700/15 rounded-full blur-3xl animate-pulse delay-1000"></div>

        {/* Flowing lines animation */}
        <div className="absolute inset-0 opacity-10">
          <svg className="w-full h-full">
            <defs>
              <linearGradient id="redGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#dc2626" />
                <stop offset="100%" stopColor="#991b1b" />
              </linearGradient>
            </defs>
            <path
              d="M0,100 Q400,50 800,100 T1600,100"
              stroke="url(#redGradient)"
              strokeWidth="2"
              fill="none"
              className="animate-pulse"
            />
            <path
              d="M0,200 Q600,150 1200,200 T2400,200"
              stroke="url(#redGradient)"
              strokeWidth="1"
              fill="none"
              className="animate-pulse"
              style={{ animationDelay: "1s" }}
            />
          </svg>
        </div>
      </div>

      {/* Header */}
      <header className="relative z-50 border-b border-red-900/30 bg-black/90 backdrop-blur-xl sticky top-0">
        <div className="container mx-auto px-6 py-4">
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
                    <div className="text-xs text-red-400 font-medium">Security Elite</div>
                  </div>
                </div>
                <div className="absolute inset-0 bg-red-500/10 rounded-lg blur-md opacity-0 group-hover:opacity-100 transition-opacity"></div>
              </div>
              <div>
                <span className="text-2xl font-bold bg-gradient-to-r from-white to-red-200 bg-clip-text text-transparent">
                  Ye Yint Thu
                </span>
                <div className="text-xs text-red-400">Elite Penetration Tester</div>
              </div>
            </div>
            <div className="hidden md:flex space-x-8">
              <a href="#home" className="text-red-400 font-medium hover:text-red-300 transition-colors">
                Home
              </a>
              <a href="#about" className="text-gray-300 hover:text-red-400 transition-colors">
                About
              </a>
              <a href="#experience" className="text-gray-300 hover:text-red-400 transition-colors">
                Experience
              </a>
              <a href="#services" className="text-gray-300 hover:text-red-400 transition-colors">
                Services
              </a>
              <Link href="/blog" className="text-gray-300 hover:text-red-400 transition-colors">
                Blog
              </Link>
              <a href="#contact" className="text-gray-300 hover:text-red-400 transition-colors">
                Contact
              </a>
            </div>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section id="home" className="relative py-32 px-6">
        <div className="container mx-auto relative z-10">
          <div className="max-w-7xl mx-auto">
            <div className="grid lg:grid-cols-2 gap-16 items-center">
              <div className="space-y-8">
                <div className="space-y-6">
                  <Badge className="bg-red-600/20 text-red-300 border-red-500/30 hover:bg-red-500/30 transition-all px-3 py-1 animate-pulse">
                    <a
                      href="https://www.offsecinitiative.net"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center space-x-2"
                    >
                      <Zap className="h-3 w-3" />
                      <span>OSI Elite Member</span>
                    </a>
                  </Badge>
                  <h1 className="text-5xl md:text-6xl font-bold leading-tight">
                    <span className="text-white">Breaching Digital</span>
                    <br />
                    <span className="bg-gradient-to-r from-red-500 to-red-700 bg-clip-text text-transparent">
                      Fortresses
                    </span>
                  </h1>
                  <div className="flex items-center space-x-4">
                    <div className="h-px bg-gradient-to-r from-red-500 to-transparent w-20 animate-pulse"></div>
                    <p className="text-lg text-gray-300">Elite Penetration Tester & Security Specialist</p>
                  </div>
                </div>
                <p className="text-lg text-gray-400 leading-relaxed max-w-lg">
                  Master of digital infiltration and cybersecurity warfare. Specializing in advanced penetration
                  testing, vulnerability research, and ethical hacking to expose critical security flaws before
                  malicious actors do.
                </p>
                <div className="flex flex-col sm:flex-row gap-4">
                  <Button
                    onClick={() => document.getElementById("contact")?.scrollIntoView({ behavior: "smooth" })}
                    className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white px-6 py-2 text-base font-medium group shadow-lg shadow-red-500/25"
                  >
                    <Mail className="mr-2 h-4 w-4" />
                    Initiate Contact
                    <ArrowRight className="ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform" />
                  </Button>
                  <Button
                    onClick={downloadResume}
                    variant="outline"
                    className="border-red-500/40 text-red-400 hover:bg-red-500/10 hover:text-red-300 hover:border-red-400 px-6 py-2 text-base"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    Download Intel
                  </Button>
                </div>
                <div className="flex items-center space-x-6 pt-4">
                  <a
                    href="https://github.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-3 bg-gray-900/50 border border-gray-700 rounded-lg hover:bg-red-500/10 hover:border-red-500/30 transition-all group"
                  >
                    <Github className="h-5 w-5 text-gray-400 group-hover:text-red-400" />
                  </a>
                  <a
                    href="https://www.linkedin.com/in/ye-yint-thu-5a808a278/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-3 bg-gray-900/50 border border-gray-700 rounded-lg hover:bg-red-500/10 hover:border-red-500/30 transition-all group"
                  >
                    <Linkedin className="h-5 w-5 text-gray-400 group-hover:text-red-400" />
                  </a>
                  <a
                    href="https://app.hackthebox.com/users/1644532"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-3 bg-gray-900/50 border border-gray-700 rounded-lg hover:bg-red-500/10 hover:border-red-500/30 transition-all group"
                  >
                    <Target className="h-5 w-5 text-gray-400 group-hover:text-red-400" />
                  </a>
                </div>
              </div>

              {/* Profile Photo Section */}
              <div className="relative">
                <div className="relative z-10">
                  {/* Profile Photo */}
                  <div className="mb-8 text-center">
                    <div className="relative inline-block">
                      <div className="w-64 h-64 mx-auto rounded-full border-4 border-red-500/40 overflow-hidden bg-gray-900/50 shadow-lg shadow-red-500/20">
                        {profileImage ? (
                          <img
                            src={profileImage || "/placeholder.svg"}
                            alt="Ye Yint Thu"
                            className="w-full h-full object-cover"
                          />
                        ) : (
                          <div className="w-full h-full flex items-center justify-center">
                            <div className="text-center">
                              <Shield className="h-16 w-16 text-red-500/50 mx-auto mb-4" />
                              <p className="text-red-400 text-sm">Elite Profile</p>
                              <p className="text-gray-500 text-xs">Classified</p>
                            </div>
                          </div>
                        )}
                      </div>
                      {/* Pulsing ring animation */}
                      <div className="absolute inset-0 rounded-full border border-red-500/30 animate-pulse"></div>
                    </div>
                  </div>

                  {/* Professional Stats Card */}
                  <div className="bg-gradient-to-br from-gray-900/80 to-red-900/20 border border-red-700/30 rounded-lg p-6 shadow-lg backdrop-blur-sm">
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300 font-medium">Systems Breached</span>
                        <span className="text-red-400 font-bold">250+</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300 font-medium">Critical Vulnerabilities</span>
                        <span className="text-red-400 font-bold">750+</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300 font-medium">Security Reports</span>
                        <span className="text-red-400 font-bold">100+</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300 font-medium">HTB Rank</span>
                        <span className="text-red-400 font-bold">Elite Hacker</span>
                      </div>
                    </div>
                  </div>
                </div>
                {/* Red glow effect */}
                <div className="absolute inset-0 bg-red-500/10 rounded-lg blur-2xl"></div>
              </div>
            </div>
          </div>
        </div>
        <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 animate-bounce">
          <ChevronDown className="h-6 w-6 text-red-400" />
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="relative py-32 px-6">
        <div className="container mx-auto">
          <div className="max-w-7xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-4xl font-bold mb-6">
                <span className="text-white">About The</span>
                <span className="bg-gradient-to-r from-red-500 to-red-700 bg-clip-text text-transparent"> Elite</span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Elite cybersecurity operative with advanced skills in digital infiltration, vulnerability research, and
                security warfare.
              </p>
            </div>
            <div className="grid lg:grid-cols-3 gap-8">
              <div className="lg:col-span-2 space-y-8">
                <Card className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="text-2xl text-white flex items-center">
                      <Terminal className="mr-3 h-5 w-5 text-red-400" />
                      Elite Operations
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-gray-300 leading-relaxed">
                      As an elite penetration tester and cybersecurity specialist, I excel in identifying and exploiting
                      critical security vulnerabilities across complex digital infrastructures. My expertise spans
                      advanced web application testing, network infiltration, and cutting-edge attack methodologies.
                    </p>
                    <div className="grid grid-cols-2 gap-6 pt-4">
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-red-600/20 rounded-lg border border-red-500/30">
                          <Target className="h-5 w-5 text-red-400" />
                        </div>
                        <span className="text-gray-300">Advanced Web Exploitation</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-red-600/20 rounded-lg border border-red-500/30">
                          <Server className="h-5 w-5 text-red-400" />
                        </div>
                        <span className="text-gray-300">Network Infiltration</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-red-600/20 rounded-lg border border-red-500/30">
                          <Search className="h-5 w-5 text-red-400" />
                        </div>
                        <span className="text-gray-300">Zero-Day Research</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-red-600/20 rounded-lg border border-red-500/30">
                          <Code className="h-5 w-5 text-red-400" />
                        </div>
                        <span className="text-gray-300">Exploit Development</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="text-2xl text-white flex items-center">
                      <Users className="mr-3 h-5 w-5 text-red-400" />
                      OSI Elite Division
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-gray-300 leading-relaxed">
                      Elite member of the{" "}
                      <a
                        href="https://www.offsecinitiative.net"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-red-400 hover:text-red-300 underline font-medium"
                      >
                        OSI (Offensive Security Initiative)
                      </a>{" "}
                      elite division, spearheading advanced security research and developing next-generation penetration
                      testing methodologies. Contributing to the global cybersecurity community through innovative
                      attack vectors and defensive strategies.
                    </p>
                  </CardContent>
                </Card>
              </div>
              <div className="space-y-8">
                <Card className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="text-xl text-white flex items-center">
                      <Award className="mr-3 h-5 w-5 text-red-400" />
                      Elite Certifications
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {certifications.map((cert) => (
                      <div key={cert.id} className="flex justify-between items-center">
                        <span className="text-gray-300 font-medium">{cert.name}</span>
                        <Badge className={getStatusColor(cert.status)}>
                          {cert.status === "certified" && <Star className="mr-1 h-3 w-3" />}
                          {cert.status === "in-progress" && <TrendingUp className="mr-1 h-3 w-3" />}
                          {cert.status === "certified"
                            ? "Elite"
                            : cert.status === "in-progress"
                              ? "Training"
                              : "Planned"}
                        </Badge>
                      </div>
                    ))}
                  </CardContent>
                </Card>
                <Card className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="text-xl text-white flex items-center">
                      <Target className="mr-3 h-5 w-5 text-red-400" />
                      HTB Elite Profile
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div>
                        <p className="text-gray-300 font-medium">Username: jrBX4</p>
                        <p className="text-red-400 text-sm font-medium">Elite Hacker Status</p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full border-red-500/40 text-red-400 hover:bg-red-500/10 hover:border-red-400"
                        onClick={() =>
                          window.open("https://app.hackthebox.com/users/1644532", "_blank", "noopener,noreferrer")
                        }
                      >
                        <ExternalLink className="mr-2 h-4 w-4" />
                        View Elite Profile
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Experience Section */}
      <section id="experience" className="relative py-32 px-6">
        <div className="container mx-auto">
          <div className="max-w-7xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-4xl font-bold mb-6">
                <span className="text-white">Elite</span>
                <span className="bg-gradient-to-r from-red-500 to-red-700 bg-clip-text text-transparent">
                  {" "}
                  Operations
                </span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Professional journey through elite cybersecurity operations and advanced penetration testing
                engagements.
              </p>
            </div>
            <div className="space-y-8">
              {experiences.map((exp, index) => (
                <Card
                  key={exp.id}
                  className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all duration-300 overflow-hidden shadow-lg backdrop-blur-sm group"
                >
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-4">
                        <div className="p-3 bg-red-600/20 rounded-lg border border-red-500/30">
                          <Briefcase className="h-6 w-6 text-red-400" />
                        </div>
                        <div>
                          <h3 className="text-xl font-bold text-white">{exp.title}</h3>
                          <p className="text-red-400 font-medium">{exp.company}</p>
                          <p className="text-gray-400 mt-2">{exp.description}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-gray-300 font-medium">{exp.period}</p>
                        {exp.current && (
                          <Badge className="bg-red-500/20 text-red-300 border-red-500/30 mt-2">Active</Badge>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section id="services" className="relative py-32 px-6">
        <div className="container mx-auto">
          <div className="max-w-7xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-4xl font-bold mb-6">
                <span className="text-white">Elite</span>
                <span className="bg-gradient-to-r from-red-500 to-red-700 bg-clip-text text-transparent">
                  {" "}
                  Services
                </span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Advanced cybersecurity services designed to breach defenses and fortify your digital infrastructure
                against sophisticated threats.
              </p>
            </div>
            <div className="grid md:grid-cols-3 gap-8">
              <Card className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm">
                <CardHeader>
                  <div className="p-4 bg-red-600/20 rounded-lg w-fit group-hover:bg-red-500/30 transition-colors border border-red-500/30">
                    <Target className="h-6 w-6 text-red-400" />
                  </div>
                  <CardTitle className="text-xl text-white">Elite Penetration Testing</CardTitle>
                  <CardDescription className="text-gray-400">
                    Advanced security assessments using cutting-edge techniques to identify critical vulnerabilities.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Advanced Web App Exploitation
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Network Infrastructure Breach
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Mobile Application Testing
                    </li>
                  </ul>
                </CardContent>
              </Card>

              <Card className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm">
                <CardHeader>
                  <div className="p-4 bg-red-600/20 rounded-lg w-fit group-hover:bg-red-500/30 transition-colors border border-red-500/30">
                    <Search className="h-6 w-6 text-red-400" />
                  </div>
                  <CardTitle className="text-xl text-white">Zero-Day Research</CardTitle>
                  <CardDescription className="text-gray-400">
                    Advanced vulnerability research and zero-day discovery using innovative testing methodologies.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Advanced Fuzzing Techniques
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Exploit Development
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Critical Risk Assessment
                    </li>
                  </ul>
                </CardContent>
              </Card>

              <Card className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm">
                <CardHeader>
                  <div className="p-4 bg-red-600/20 rounded-lg w-fit group-hover:bg-red-500/30 transition-colors border border-red-500/30">
                    <Lock className="h-6 w-6 text-red-400" />
                  </div>
                  <CardTitle className="text-xl text-white">Security Architecture</CardTitle>
                  <CardDescription className="text-gray-400">
                    Elite guidance on advanced security implementations and threat modeling strategies.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Advanced Threat Modeling
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Elite Security Design
                    </li>
                    <li className="flex items-center">
                      <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                      Advanced Training Programs
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
          <div className="max-w-7xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-4xl font-bold mb-6">
                <span className="text-white">Elite</span>
                <span className="bg-gradient-to-r from-red-500 to-red-700 bg-clip-text text-transparent">
                  {" "}
                  Intelligence
                </span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Advanced cybersecurity intelligence, penetration testing methodologies, and elite security research.
              </p>
            </div>
            {posts.length > 0 ? (
              <div className="grid md:grid-cols-3 gap-8">
                {posts.map((post) => (
                  <Card
                    key={post.id}
                    className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm group"
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
                          Access Intel
                          <ArrowRight className="ml-1 h-3 w-3 inline group-hover:translate-x-1 transition-transform" />
                        </Link>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            ) : (
              <div className="text-center py-20">
                <BookOpen className="h-16 w-16 text-gray-700 mx-auto mb-6" />
                <p className="text-gray-400 text-xl">Elite intelligence classified.</p>
                <p className="text-gray-600 text-sm mt-2">Access pending authorization clearance.</p>
              </div>
            )}
            <div className="text-center mt-16">
              <Link href="/blog">
                <Button className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white px-8 py-2 text-lg shadow-lg shadow-red-500/25">
                  <BookOpen className="mr-2 h-5 w-5" />
                  Access Full Intel
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
          <div className="max-w-7xl mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-4xl font-bold mb-6">
                <span className="text-white">Initiate</span>
                <span className="bg-gradient-to-r from-red-500 to-red-700 bg-clip-text text-transparent"> Contact</span>
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Ready to deploy elite cybersecurity services? Initiate secure communication channel to discuss your
                digital defense requirements.
              </p>
            </div>
            <div className="grid lg:grid-cols-2 gap-16">
              <div className="space-y-8">
                <div>
                  <h3 className="text-2xl font-bold text-white mb-8">Elite Contact Channels</h3>
                  <div className="space-y-6">
                    <div className="flex items-center space-x-4">
                      <div className="p-4 bg-red-600/20 rounded-lg border border-red-500/30">
                        <Mail className="h-6 w-6 text-red-400" />
                      </div>
                      <div>
                        <p className="text-gray-300 font-medium text-lg">Secure Email</p>
                        <a
                          href="mailto:yeyintthu.mst@gmail.com"
                          className="text-gray-400 hover:text-red-400 transition-colors"
                        >
                          yeyintthu.mst@gmail.com
                        </a>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="p-4 bg-red-600/20 rounded-lg border border-red-500/30">
                        <MapPin className="h-6 w-6 text-red-400" />
                      </div>
                      <div>
                        <p className="text-gray-300 font-medium text-lg">Operational Zone</p>
                        <p className="text-gray-400">Global Remote Operations</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="p-4 bg-red-600/20 rounded-lg border border-red-500/30">
                        <Users className="h-6 w-6 text-red-400" />
                      </div>
                      <div>
                        <p className="text-gray-300 font-medium text-lg">Elite Division</p>
                        <a
                          href="https://www.offsecinitiative.net"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-gray-400 hover:text-red-400 transition-colors"
                        >
                          OSI Elite Member
                        </a>
                      </div>
                    </div>
                  </div>
                </div>
                <div>
                  <h4 className="text-xl font-bold text-white mb-6">Elite Network</h4>
                  <div className="flex space-x-4">
                    <a
                      href="https://github.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-4 bg-gray-900/50 border border-gray-700 rounded-lg hover:bg-red-500/10 hover:border-red-500/30 transition-all group"
                    >
                      <Github className="h-6 w-6 text-gray-400 group-hover:text-red-400" />
                    </a>
                    <a
                      href="https://www.linkedin.com/in/ye-yint-thu-5a808a278/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-4 bg-gray-900/50 border border-gray-700 rounded-lg hover:bg-red-500/10 hover:border-red-500/30 transition-all group"
                    >
                      <Linkedin className="h-6 w-6 text-gray-400 group-hover:text-red-400" />
                    </a>
                    <a
                      href="https://app.hackthebox.com/users/1644532"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-4 bg-gray-900/50 border border-gray-700 rounded-lg hover:bg-red-500/10 hover:border-red-500/30 transition-all group"
                    >
                      <Target className="h-6 w-6 text-gray-400 group-hover:text-red-400" />
                    </a>
                  </div>
                </div>
              </div>
              <Card className="bg-black/50 border border-red-900/30 hover:border-red-500/40 transition-all shadow-lg backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="text-2xl text-white">Secure Communication</CardTitle>
                  <CardDescription className="text-gray-400">
                    Initiate encrypted communication channel for elite cybersecurity services.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {submitStatus === "success" && (
                    <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <p className="text-red-400 text-sm">
                        Secure channel established. If email client failed to open, contact directly at{" "}
                        <a href="mailto:yeyintthu.mst@gmail.com" className="underline">
                          yeyintthu.mst@gmail.com
                        </a>
                      </p>
                    </div>
                  )}
                  {submitStatus === "error" && (
                    <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <p className="text-red-400 text-sm">
                        Communication error. Use direct secure channel:{" "}
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
                          className="w-full px-4 py-3 bg-gray-900/50 border border-red-700/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
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
                          className="w-full px-4 py-3 bg-gray-900/50 border border-red-700/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
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
                        className="w-full px-4 py-3 bg-gray-900/50 border border-red-700/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
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
                        className="w-full px-4 py-3 bg-gray-900/50 border border-red-700/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                        placeholder="Elite Security Assessment Request"
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
                        className="w-full px-4 py-3 bg-gray-900/50 border border-red-700/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent resize-none"
                        placeholder="Describe your elite cybersecurity requirements..."
                        required
                      />
                    </div>
                    <Button
                      type="submit"
                      disabled={isSubmitting}
                      className="w-full bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white py-3 disabled:opacity-50 shadow-lg shadow-red-500/25"
                    >
                      {isSubmitting ? (
                        <div className="flex items-center justify-center">
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                          Establishing Connection...
                        </div>
                      ) : (
                        <>
                          <Send className="mr-2 h-5 w-5" />
                          Initiate Secure Contact
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
      <footer className="relative border-t border-red-900/30 bg-black/90 backdrop-blur-xl py-8 px-6">
        <div className="container mx-auto text-center">
          <p className="text-gray-500">
            © {new Date().getFullYear()} Ye Yint Thu - jrBX4. All rights reserved. | Elite Cybersecurity Operations
          </p>
        </div>
      </footer>
    </div>
  )
}
