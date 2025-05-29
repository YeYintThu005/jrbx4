"use client"

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
  Twitter,
  Download,
  ChevronDown,
  Eye,
  Calendar,
  Users,
  BookOpen,
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

  const getCategoryColor = (category: string) => {
    switch (category) {
      case "Web Security":
        return "bg-red-900/30 text-red-300 border-red-700"
      case "Network Security":
        return "bg-blue-900/30 text-blue-300 border-blue-700"
      case "CTF Writeup":
        return "bg-green-900/30 text-green-300 border-green-700"
      case "Cloud Security":
        return "bg-orange-900/30 text-orange-300 border-orange-700"
      case "Tools & Techniques":
        return "bg-purple-900/30 text-purple-300 border-purple-700"
      case "Research":
        return "bg-indigo-900/30 text-indigo-300 border-indigo-700"
      default:
        return "bg-gray-900/30 text-gray-300 border-gray-700"
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <nav className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-red-500" />
              <span className="text-xl font-bold text-white">Ye Yint Thu</span>
            </div>
            <div className="hidden md:flex space-x-6">
              <a href="#home" className="text-red-400 font-medium">
                Home
              </a>
              <a href="#about" className="text-slate-300 hover:text-white transition-colors">
                About
              </a>
              <a href="#services" className="text-slate-300 hover:text-white transition-colors">
                Services
              </a>
              <Link href="/blog" className="text-slate-300 hover:text-white transition-colors">
                Blog
              </Link>
              <a href="#contact" className="text-slate-300 hover:text-white transition-colors">
                Contact
              </a>
            </div>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section id="home" className="py-20 px-4 relative overflow-hidden">
        <div className="absolute inset-0 opacity-10">
          <div
            className="absolute inset-0"
            style={{
              backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fillRule='evenodd'%3E%3Cg fill='%23ef4444' fillOpacity='0.1'%3E%3Ccircle cx='30' cy='30' r='2'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
            }}
          />
        </div>
        <div className="container mx-auto relative z-10">
          <div className="max-w-4xl mx-auto text-center">
            <div className="mb-8">
              <Badge variant="secondary" className="bg-red-900/30 text-red-300 border-red-700 mb-4">
                OSI Team Member
              </Badge>
              <h1 className="text-5xl md:text-7xl font-bold text-white mb-6">
                Ye Yint Thu
                <span className="text-red-500 block">Penetration Tester</span>
              </h1>
              <p className="text-xl text-slate-300 mb-8 max-w-2xl mx-auto">
                Cybersecurity specialist focused on identifying vulnerabilities and strengthening digital defenses.
                Passionate about ethical hacking and security research.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
              <Button className="bg-red-600 hover:bg-red-700 text-white px-8 py-3">
                <Mail className="mr-2 h-4 w-4" />
                Get In Touch
              </Button>
              <Button variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-700 px-8 py-3">
                <Download className="mr-2 h-4 w-4" />
                Download CV
              </Button>
            </div>
            <div className="flex justify-center space-x-6">
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 hover:text-white transition-colors"
              >
                <Github className="h-6 w-6" />
              </a>
              <a
                href="https://linkedin.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 hover:text-white transition-colors"
              >
                <Linkedin className="h-6 w-6" />
              </a>
              <a
                href="https://twitter.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 hover:text-white transition-colors"
              >
                <Twitter className="h-6 w-6" />
              </a>
            </div>
          </div>
        </div>
        <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 animate-bounce">
          <ChevronDown className="h-6 w-6 text-slate-400" />
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="py-20 px-4 bg-slate-800/30">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-white mb-4">About Me</h2>
              <p className="text-xl text-slate-300 max-w-2xl mx-auto">
                Dedicated cybersecurity professional with expertise in penetration testing and vulnerability assessment.
              </p>
            </div>
            <div className="grid lg:grid-cols-2 gap-12 items-center">
              <div>
                <div className="space-y-6">
                  <div>
                    <h3 className="text-2xl font-bold text-white mb-4">Professional Background</h3>
                    <p className="text-slate-300 leading-relaxed">
                      As a penetration tester and cybersecurity specialist, I focus on identifying security
                      vulnerabilities in web applications, networks, and systems. My approach combines technical
                      expertise with creative problem-solving to uncover potential attack vectors.
                    </p>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold text-white mb-3">Core Competencies</h4>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="flex items-center space-x-2">
                        <Target className="h-4 w-4 text-red-500" />
                        <span className="text-slate-300">Web App Testing</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Server className="h-4 w-4 text-red-500" />
                        <span className="text-slate-300">Network Security</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Search className="h-4 w-4 text-red-500" />
                        <span className="text-slate-300">Vulnerability Assessment</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Code className="h-4 w-4 text-red-500" />
                        <span className="text-slate-300">Security Research</span>
                      </div>
                    </div>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold text-white mb-3">OSI Team Member</h4>
                    <p className="text-slate-300">
                      Proud member of the OSI (Open Security Initiative) team, collaborating on cutting-edge security
                      research and contributing to the cybersecurity community.
                    </p>
                  </div>
                </div>
              </div>
              <div className="space-y-6">
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center">
                      <Award className="mr-2 h-5 w-5 text-red-500" />
                      Certifications
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-300">OSCP</span>
                      <Badge variant="secondary" className="bg-green-900/30 text-green-300 border-green-700">
                        Certified
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-300">CEH</span>
                      <Badge variant="secondary" className="bg-green-900/30 text-green-300 border-green-700">
                        Certified
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-300">CISSP</span>
                      <Badge variant="secondary" className="bg-yellow-900/30 text-yellow-300 border-yellow-700">
                        In Progress
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center">
                      <Users className="mr-2 h-5 w-5 text-red-500" />
                      Hack The Box Profile
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-slate-300 font-medium">Username: jrBX4</p>
                        <p className="text-slate-400 text-sm">Active CTF participant</p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="border-slate-600 text-slate-300 hover:bg-slate-700"
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
      <section id="services" className="py-20 px-4">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-white mb-4">Services</h2>
              <p className="text-xl text-slate-300 max-w-2xl mx-auto">
                Comprehensive cybersecurity services to protect your digital assets and infrastructure.
              </p>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
              <Card className="bg-slate-800/50 border-slate-700 hover:bg-slate-800/70 transition-colors card-hover">
                <CardHeader>
                  <div className="p-3 bg-red-900/20 rounded-full w-fit border border-red-700">
                    <Target className="h-8 w-8 text-red-400" />
                  </div>
                  <CardTitle className="text-white">Penetration Testing</CardTitle>
                  <CardDescription className="text-slate-400">
                    Comprehensive security assessments to identify vulnerabilities in your systems and applications.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2 text-slate-300">
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

              <Card className="bg-slate-800/50 border-slate-700 hover:bg-slate-800/70 transition-colors card-hover">
                <CardHeader>
                  <div className="p-3 bg-blue-900/20 rounded-full w-fit border border-blue-700">
                    <Search className="h-8 w-8 text-blue-400" />
                  </div>
                  <CardTitle className="text-white">Vulnerability Assessment</CardTitle>
                  <CardDescription className="text-slate-400">
                    Systematic evaluation of security weaknesses in your IT infrastructure and applications.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2 text-slate-300">
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

              <Card className="bg-slate-800/50 border-slate-700 hover:bg-slate-800/70 transition-colors card-hover">
                <CardHeader>
                  <div className="p-3 bg-green-900/20 rounded-full w-fit border border-green-700">
                    <Lock className="h-8 w-8 text-green-400" />
                  </div>
                  <CardTitle className="text-white">Security Consulting</CardTitle>
                  <CardDescription className="text-slate-400">
                    Expert guidance on security best practices and compliance requirements.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2 text-slate-300">
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
      <section className="py-20 px-4 bg-slate-800/30">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-white mb-4">Latest Insights</h2>
              <p className="text-xl text-slate-300 max-w-2xl mx-auto">
                Recent articles on cybersecurity, penetration testing, and security research.
              </p>
            </div>
            {posts.length > 0 ? (
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
                {posts.map((post) => (
                  <Card
                    key={post.id}
                    className="bg-slate-800/50 border-slate-700 hover:bg-slate-800/70 transition-colors card-hover"
                  >
                    <div className="aspect-video overflow-hidden rounded-t-lg">
                      <img
                        src={post.featuredImage || "/placeholder.svg?height=200&width=350"}
                        alt="Blog post"
                        className="w-full h-full object-cover hover:scale-105 transition-transform"
                      />
                    </div>
                    <CardHeader>
                      <div className="flex items-center justify-between mb-2">
                        <Badge variant="secondary" className={getCategoryColor(post.category)}>
                          {post.category}
                        </Badge>
                        <div className="flex items-center text-slate-400 text-sm">
                          <Calendar className="mr-1 h-3 w-3" />
                          {post.date}
                        </div>
                      </div>
                      <CardTitle className="text-white hover:text-red-400 transition-colors">
                        <Link href={`/blog/${post.slug}`} className="block">
                          {post.title}
                        </Link>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <CardDescription className="text-slate-300 mb-4">
                        {post.content.substring(0, 120)}...
                      </CardDescription>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center text-slate-400 text-sm">
                          <Eye className="mr-1 h-3 w-3" />
                          {post.views} views
                        </div>
                        <Link
                          href={`/blog/${post.slug}`}
                          className="text-red-400 hover:text-red-300 text-sm font-medium"
                        >
                          Read More →
                        </Link>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            ) : (
              <div className="text-center py-12">
                <BookOpen className="h-16 w-16 text-slate-600 mx-auto mb-4" />
                <p className="text-slate-400 text-lg">No blog posts available yet.</p>
                <p className="text-slate-500 text-sm mt-2">Check back soon for cybersecurity insights and tutorials.</p>
              </div>
            )}
            <div className="text-center mt-12">
              <Link href="/blog">
                <Button className="bg-red-600 hover:bg-red-700 text-white">
                  <BookOpen className="mr-2 h-4 w-4" />
                  View All Posts
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Contact Section */}
      <section id="contact" className="py-20 px-4">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-white mb-4">Get In Touch</h2>
              <p className="text-xl text-slate-300 max-w-2xl mx-auto">
                Ready to secure your digital assets? Let's discuss your cybersecurity needs.
              </p>
            </div>
            <div className="grid lg:grid-cols-2 gap-12">
              <div className="space-y-8">
                <div>
                  <h3 className="text-2xl font-bold text-white mb-6">Contact Information</h3>
                  <div className="space-y-4">
                    <div className="flex items-center space-x-4">
                      <div className="p-3 bg-red-900/20 rounded-full border border-red-700">
                        <Mail className="h-5 w-5 text-red-400" />
                      </div>
                      <div>
                        <p className="text-slate-300 font-medium">Email</p>
                        <p className="text-slate-400">jrbx4@osi.com</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="p-3 bg-blue-900/20 rounded-full border border-blue-700">
                        <MapPin className="h-5 w-5 text-blue-400" />
                      </div>
                      <div>
                        <p className="text-slate-300 font-medium">Location</p>
                        <p className="text-slate-400">Available for Remote Work</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="p-3 bg-green-900/20 rounded-full border border-green-700">
                        <Users className="h-5 w-5 text-green-400" />
                      </div>
                      <div>
                        <p className="text-slate-300 font-medium">Organization</p>
                        <p className="text-slate-400">OSI Team Member</p>
                      </div>
                    </div>
                  </div>
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-white mb-4">Follow Me</h4>
                  <div className="flex space-x-4">
                    <a
                      href="https://github.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-3 bg-slate-800 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors"
                    >
                      <Github className="h-5 w-5 text-slate-300" />
                    </a>
                    <a
                      href="https://linkedin.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-3 bg-slate-800 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors"
                    >
                      <Linkedin className="h-5 w-5 text-slate-300" />
                    </a>
                    <a
                      href="https://twitter.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-3 bg-slate-800 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors"
                    >
                      <Twitter className="h-5 w-5 text-slate-300" />
                    </a>
                  </div>
                </div>
              </div>
              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Send a Message</CardTitle>
                  <CardDescription className="text-slate-400">
                    Interested in cybersecurity services? Let's start a conversation.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form className="space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">First Name</label>
                        <input
                          type="text"
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                          placeholder="John"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">Last Name</label>
                        <input
                          type="text"
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                          placeholder="Doe"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Email</label>
                      <input
                        type="email"
                        className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                        placeholder="john@example.com"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Subject</label>
                      <input
                        type="text"
                        className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                        placeholder="Security Assessment Inquiry"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Message</label>
                      <textarea
                        rows={4}
                        className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500 resize-none"
                        placeholder="Tell me about your cybersecurity needs..."
                      />
                    </div>
                    <Button className="w-full bg-red-600 hover:bg-red-700 text-white">
                      <Mail className="mr-2 h-4 w-4" />
                      Send Message
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-700 bg-slate-900/50 py-8 px-4">
        <div className="container mx-auto text-center">
          <p className="text-slate-400">
            © {new Date().getFullYear()} Ye Yint Thu. All rights reserved. | Cybersecurity Professional
          </p>
        </div>
      </footer>
    </div>
  )
}
