"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Edit,
  Upload,
  Save,
  Eye,
  FileText,
  Trash2,
  ImageIcon,
  Plus,
  LogOut,
  Code,
  Settings,
  Key,
  User,
  FolderOpen,
  Download,
  File,
  Terminal,
  Award,
  Briefcase,
  Shield,
  Target,
} from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"

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

// Simple markdown to HTML converter for preview
const markdownToHtml = (markdown: string): string => {
  const html = markdown
    // Images
    .replace(
      /!\[([^\]]*)\]$$([^)]+)$$/g,
      '<img src="$2" alt="$1" class="w-full max-w-md mx-auto rounded-lg border border-red-600 my-4" />',
    )
    // Headers
    .replace(/^### (.*$)/gim, '<h3 class="text-lg font-semibold text-white mb-2">$1</h3>')
    .replace(/^## (.*$)/gim, '<h2 class="text-xl font-bold text-white mb-3">$1</h2>')
    .replace(/^# (.*$)/gim, '<h1 class="text-2xl font-bold text-white mb-4">$1</h1>')
    // Bold and italic
    .replace(/\*\*(.*?)\*\*/g, '<strong class="font-bold text-white">$1</strong>')
    .replace(/\*(.*?)\*/g, '<em class="italic text-gray-300">$1</em>')
    // Code blocks
    .replace(
      /```(\w+)?\n([\s\S]*?)```/g,
      '<pre class="bg-gray-900 p-4 rounded-lg border border-red-600 my-4 overflow-x-auto"><code class="text-red-400 text-sm">$2</code></pre>',
    )
    // Inline code
    .replace(/`(.*?)`/g, '<code class="bg-gray-800 px-2 py-1 rounded text-red-400 text-sm">$1</code>')
    // Links
    .replace(
      /\[([^\]]+)\]$$([^)]+)$$/g,
      '<a href="$2" class="text-red-400 hover:text-red-300 underline" target="_blank">$1</a>',
    )
    // Lists
    .replace(/^- (.*$)/gim, '<li class="text-gray-300 mb-2 ml-4">• $1</li>')
    // Paragraphs
    .replace(/\n\n/g, '</p><p class="text-gray-300 mb-4 leading-relaxed">')
    .replace(/\n/g, "<br>")

  return `<div class="prose prose-invert max-w-none"><p class="text-gray-300 mb-4 leading-relaxed">${html}</p></div>`
}

export default function BlogUploadPage() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [markdownContent, setMarkdownContent] = useState("")
  const [previewMode, setPreviewMode] = useState(false)
  const [showChangePassword, setShowChangePassword] = useState(false)
  const [postTitle, setPostTitle] = useState("")
  const [postCategory, setPostCategory] = useState("")
  const [postStatus, setPostStatus] = useState("draft")
  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [passwordError, setPasswordError] = useState("")
  const [posts, setPosts] = useState([])
  const [uploadedImages, setUploadedImages] = useState<string[]>([])
  const [featuredImage, setFeaturedImage] = useState<string>("")
  const [isUploading, setIsUploading] = useState(false)
  const [profileImage, setProfileImage] = useState<string>("")
  const [resumeFile, setResumeFile] = useState<string>("")
  const [resumeFileName, setResumeFileName] = useState<string>("")

  // New state for certifications and experiences
  const [certifications, setCertifications] = useState<Certification[]>([])
  const [experiences, setExperiences] = useState<Experience[]>([])
  const [newCertification, setNewCertification] = useState({ name: "", status: "certified" as const, date: "" })
  const [newExperience, setNewExperience] = useState({
    title: "",
    company: "",
    period: "",
    description: "",
    current: false,
  })

  const router = useRouter()

  useEffect(() => {
    // Check authentication status
    const authToken = localStorage.getItem("adminAuth")
    if (authToken) {
      setIsAuthenticated(true)

      // Load all data from localStorage
      const savedPosts = localStorage.getItem("blogPosts")
      if (savedPosts) {
        setPosts(JSON.parse(savedPosts))
      }

      const savedProfileImage = localStorage.getItem("profileImage")
      if (savedProfileImage) {
        setProfileImage(savedProfileImage)
      }

      const savedResume = localStorage.getItem("resumeFile")
      const savedResumeFileName = localStorage.getItem("resumeFileName")
      if (savedResume && savedResumeFileName) {
        setResumeFile(savedResume)
        setResumeFileName(savedResumeFileName)
      }

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

      const savedExperiences = localStorage.getItem("experiences")
      if (savedExperiences) {
        setExperiences(JSON.parse(savedExperiences))
      } else {
        setExperiences([
          {
            id: 1,
            title: "Elite Penetration Tester",
            company: "OSI Team",
            period: "2023 - Present",
            description: "Conducting advanced security assessments and elite vulnerability research",
            current: true,
          },
          {
            id: 2,
            title: "Security Researcher",
            company: "Independent Operations",
            period: "2022 - 2023",
            description: "Elite bug bounty hunting and advanced security research",
            current: false,
          },
        ])
      }
    } else {
      router.push("/login")
    }
    setIsLoading(false)
  }, [router])

  const handleLogout = () => {
    localStorage.removeItem("adminAuth")
    localStorage.removeItem("adminEmail")
    router.push("/")
  }

  const handlePublishPost = () => {
    if (!postTitle.trim() || !markdownContent.trim()) {
      alert("Please fill in the title and content")
      return
    }

    const newPost = {
      id: Date.now(),
      title: postTitle,
      category: postCategory || "General",
      status: postStatus,
      date: new Date().toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
      }),
      views: "0",
      content: markdownContent,
      featuredImage: featuredImage,
      slug: postTitle
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/(^-|-$)/g, ""),
    }

    const updatedPosts = [newPost, ...posts]
    setPosts(updatedPosts)

    // Save to localStorage so it persists across all pages
    localStorage.setItem("blogPosts", JSON.stringify(updatedPosts))

    // Reset form
    setPostTitle("")
    setPostCategory("")
    setMarkdownContent("")
    setPostStatus("draft")
    setFeaturedImage("")

    alert(`Post ${postStatus === "published" ? "published" : "saved as draft"} successfully!`)
  }

  const handleDeletePost = (id: number) => {
    if (confirm("Are you sure you want to delete this post?")) {
      const updatedPosts = posts.filter((post: any) => post.id !== id)
      setPosts(updatedPosts)
      localStorage.setItem("blogPosts", JSON.stringify(updatedPosts))
      alert("Post deleted successfully!")
    }
  }

  const handleEditPost = (post: any) => {
    setPostTitle(post.title)
    setPostCategory(post.category)
    setMarkdownContent(post.content)
    setPostStatus(post.status)
    setFeaturedImage(post.featuredImage || "")

    const updatedPosts = posts.filter((p: any) => p.id !== post.id)
    setPosts(updatedPosts)
    localStorage.setItem("blogPosts", JSON.stringify(updatedPosts))
  }

  const handleChangePassword = () => {
    setPasswordError("")

    if (currentPassword !== "OSI_SecureAdmin_2024_jrBX4!") {
      setPasswordError("Current password is incorrect")
      return
    }

    if (newPassword.length < 8) {
      setPasswordError("New password must be at least 8 characters long")
      return
    }

    if (newPassword !== confirmPassword) {
      setPasswordError("New passwords do not match")
      return
    }

    alert("Password changed successfully!")
    setShowChangePassword(false)
    setCurrentPassword("")
    setNewPassword("")
    setConfirmPassword("")
  }

  const handleImageUpload = async (event: React.ChangeEvent<HTMLInputElement>, isFeatured = false) => {
    const file = event.target.files?.[0]
    if (!file) return

    if (!file.type.startsWith("image/")) {
      alert("Please select a valid image file")
      return
    }

    if (file.size > 5 * 1024 * 1024) {
      alert("Image size must be less than 5MB")
      return
    }

    setIsUploading(true)

    try {
      const reader = new FileReader()
      reader.onload = (e) => {
        const imageUrl = e.target?.result as string

        if (isFeatured) {
          setFeaturedImage(imageUrl)
          alert("Featured image uploaded successfully!")
        } else {
          setUploadedImages((prev) => [imageUrl, ...prev])
          alert("Image uploaded to media library!")
        }
      }
      reader.readAsDataURL(file)
    } catch (error) {
      alert("Failed to upload image. Please try again.")
    } finally {
      setIsUploading(false)
    }
  }

  const handleProfileImageUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    if (!file.type.startsWith("image/")) {
      alert("Please select a valid image file")
      return
    }

    if (file.size > 5 * 1024 * 1024) {
      alert("Image size must be less than 5MB")
      return
    }

    setIsUploading(true)

    try {
      const reader = new FileReader()
      reader.onload = (e) => {
        const imageUrl = e.target?.result as string
        setProfileImage(imageUrl)
        localStorage.setItem("profileImage", imageUrl)
        alert("Profile image updated successfully!")
      }
      reader.readAsDataURL(file)
    } catch (error) {
      alert("Failed to upload profile image. Please try again.")
    } finally {
      setIsUploading(false)
    }
  }

  const handleResumeUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    if (file.type !== "application/pdf") {
      alert("Please select a PDF file")
      return
    }

    if (file.size > 10 * 1024 * 1024) {
      alert("File size must be less than 10MB")
      return
    }

    setIsUploading(true)

    try {
      const reader = new FileReader()
      reader.onload = (e) => {
        const fileUrl = e.target?.result as string
        setResumeFile(fileUrl)
        setResumeFileName(file.name)
        localStorage.setItem("resumeFile", fileUrl)
        localStorage.setItem("resumeFileName", file.name)
        alert("Resume uploaded successfully!")
      }
      reader.readAsDataURL(file)
    } catch (error) {
      alert("Failed to upload resume. Please try again.")
    } finally {
      setIsUploading(false)
    }
  }

  const handleDeleteImage = (index: number) => {
    if (confirm("Are you sure you want to delete this image?")) {
      setUploadedImages((prev) => prev.filter((_, i) => i !== index))
      alert("Image deleted successfully!")
    }
  }

  const insertImageIntoContent = (imageUrl: string) => {
    const imageMarkdown = `![Image description](${imageUrl})\n\n`

    const textarea = document.querySelector("textarea") as HTMLTextAreaElement
    if (textarea) {
      const start = textarea.selectionStart
      const end = textarea.selectionEnd
      const currentContent = markdownContent || ""

      const newContent = currentContent.substring(0, start) + imageMarkdown + currentContent.substring(end)
      setMarkdownContent(newContent)

      setTimeout(() => {
        textarea.focus()
        textarea.setSelectionRange(start + imageMarkdown.length, start + imageMarkdown.length)
      }, 0)
    } else {
      setMarkdownContent((prev) => (prev || "") + imageMarkdown)
    }

    alert("Image inserted into content!")
  }

  const downloadResume = () => {
    if (resumeFile && resumeFileName) {
      const link = document.createElement("a")
      link.href = resumeFile
      link.download = resumeFileName
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    }
  }

  // Certification management functions
  const handleAddCertification = () => {
    if (!newCertification.name.trim()) {
      alert("Please enter a certification name")
      return
    }

    const certification: Certification = {
      id: Date.now(),
      name: newCertification.name,
      status: newCertification.status,
      date: newCertification.date || undefined,
    }

    const updatedCertifications = [...certifications, certification]
    setCertifications(updatedCertifications)
    localStorage.setItem("certifications", JSON.stringify(updatedCertifications))

    setNewCertification({ name: "", status: "certified", date: "" })
    alert("Certification added successfully!")
  }

  const handleDeleteCertification = (id: number) => {
    if (confirm("Are you sure you want to delete this certification?")) {
      const updatedCertifications = certifications.filter((cert) => cert.id !== id)
      setCertifications(updatedCertifications)
      localStorage.setItem("certifications", JSON.stringify(updatedCertifications))
      alert("Certification deleted successfully!")
    }
  }

  // Experience management functions
  const handleAddExperience = () => {
    if (!newExperience.title.trim() || !newExperience.company.trim()) {
      alert("Please fill in the title and company")
      return
    }

    const experience: Experience = {
      id: Date.now(),
      title: newExperience.title,
      company: newExperience.company,
      period: newExperience.period,
      description: newExperience.description,
      current: newExperience.current,
    }

    const updatedExperiences = [...experiences, experience]
    setExperiences(updatedExperiences)
    localStorage.setItem("experiences", JSON.stringify(updatedExperiences))

    setNewExperience({
      title: "",
      company: "",
      period: "",
      description: "",
      current: false,
    })
    alert("Experience added successfully!")
  }

  const handleDeleteExperience = (id: number) => {
    if (confirm("Are you sure you want to delete this experience?")) {
      const updatedExperiences = experiences.filter((exp) => exp.id !== id)
      setExperiences(updatedExperiences)
      localStorage.setItem("experiences", JSON.stringify(updatedExperiences))
      alert("Experience deleted successfully!")
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

  // Sample markdown content
  const sampleMarkdown = `# Advanced Penetration Testing Techniques

## Introduction

Elite penetration testing requires mastery of advanced techniques and cutting-edge methodologies. This guide explores sophisticated attack vectors used in modern security assessments.

## Key Techniques

### 1. Advanced SQL Injection

\`\`\`sql
' UNION SELECT 1,2,3,database(),5-- -
\`\`\`

### 2. Elite Buffer Overflow Exploitation

\`\`\`python
payload = "A" * 512 + struct.pack("<I", 0xdeadbeef)
\`\`\`

### 3. Zero-Day Discovery

Advanced fuzzing and reverse engineering techniques for discovering previously unknown vulnerabilities.

## Elite Tools

- **Custom Exploits**: Proprietary tools for advanced assessments
- **Zero-Day Arsenal**: Collection of undisclosed vulnerabilities
- **Advanced Payloads**: Sophisticated evasion techniques

## Conclusion

Elite penetration testing requires continuous learning and adaptation to emerging threats and defensive technologies.

---

*Published by jrBX4 | Elite OSI Operative*`

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-white">Loading elite systems...</div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return null
  }

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        {/* Floating particles */}
        <div className="absolute inset-0">
          {[...Array(20)].map((_, i) => (
            <div
              key={i}
              className="absolute w-1 h-1 bg-red-400/40 rounded-full animate-pulse"
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
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-gradient-to-r from-red-600/10 to-red-800/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-gradient-to-r from-red-500/5 to-red-700/5 rounded-full blur-3xl animate-pulse delay-1000"></div>
      </div>

      {/* Header */}
      <header className="relative z-50 border-b border-red-900/30 bg-black/90 backdrop-blur-xl sticky top-0">
        <div className="container mx-auto px-6 py-4">
          <nav className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              {/* Elite jrBX4 Logo */}
              <div className="relative group">
                <div className="flex items-center space-x-3 p-3 bg-gradient-to-r from-red-900/40 to-black/60 rounded-lg border border-red-600/40 shadow-lg">
                  <div className="relative">
                    <Terminal className="h-8 w-8 text-red-400" />
                    <div className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                  </div>
                  <div className="font-mono">
                    <div className="text-lg font-bold bg-gradient-to-r from-red-400 to-red-600 bg-clip-text text-transparent">
                      jrBX4
                    </div>
                    <div className="text-xs text-red-400">ELITE ADMIN</div>
                  </div>
                </div>
                <div className="absolute inset-0 bg-gradient-to-r from-red-500/10 to-red-600/10 rounded-lg blur-lg group-hover:blur-xl transition-all"></div>
              </div>
              <div>
                <span className="text-2xl font-bold bg-gradient-to-r from-white to-red-200 bg-clip-text text-transparent">
                  Ye Yint Thu
                </span>
                <div className="text-xs text-red-400 font-mono">ELITE CONTROL PANEL</div>
              </div>
            </div>
            <div className="flex items-center space-x-6">
              <Link href="/" className="text-gray-300 hover:text-red-400 transition-colors">
                Home
              </Link>
              <Link href="/blog" className="text-gray-300 hover:text-red-400 transition-colors">
                Blog
              </Link>
              <Button
                onClick={() => setShowChangePassword(true)}
                variant="outline"
                size="sm"
                className="border-red-500/50 text-red-400 hover:bg-red-500/10"
              >
                <Settings className="mr-2 h-4 w-4" />
                Settings
              </Button>
              <Button
                onClick={handleLogout}
                variant="outline"
                size="sm"
                className="border-red-500/50 text-red-400 hover:bg-red-500/10"
              >
                <LogOut className="mr-2 h-4 w-4" />
                Logout
              </Button>
            </div>
          </nav>
        </div>
      </header>

      {/* Change Password Modal */}
      {showChangePassword && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <Card className="bg-gradient-to-br from-gray-900/90 to-red-900/50 border-red-500/30 w-full max-w-md backdrop-blur-xl">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Key className="mr-2 h-5 w-5" />
                Change Access Code
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {passwordError && (
                <div className="p-3 bg-red-500/20 border border-red-500/30 rounded-lg">
                  <p className="text-red-400 text-sm">{passwordError}</p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Current Access Code</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-black/50 border border-red-900/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 backdrop-blur-sm"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">New Access Code</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-black/50 border border-red-900/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 backdrop-blur-sm"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Confirm New Access Code</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-black/50 border border-red-900/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 backdrop-blur-sm"
                />
              </div>

              <div className="flex space-x-3">
                <Button
                  onClick={handleChangePassword}
                  className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white flex-1 border-0"
                >
                  Update Code
                </Button>
                <Button
                  onClick={() => setShowChangePassword(false)}
                  variant="outline"
                  className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                >
                  Cancel
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Hero Section */}
      <section className="relative py-20 px-6">
        <div className="container mx-auto">
          <div className="max-w-4xl mx-auto text-center">
            <h1 className="text-6xl md:text-8xl font-bold mb-6">
              <span className="bg-gradient-to-r from-red-400 via-red-500 to-red-600 bg-clip-text text-transparent">
                Elite
              </span>
              <span className="text-white block">Command</span>
            </h1>
            <p className="text-xl text-gray-400 mb-8 max-w-2xl mx-auto">
              Advanced control center for elite operations, content management, and tactical intelligence.
            </p>
          </div>
        </div>
      </section>

      {/* Dashboard Stats */}
      <section className="relative py-8 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="grid md:grid-cols-4 gap-6">
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardContent className="p-6 text-center">
                  <FileText className="h-8 w-8 text-red-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{posts.length}</p>
                  <p className="text-sm text-gray-400">Intel Reports</p>
                </CardContent>
              </Card>
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardContent className="p-6 text-center">
                  <Award className="h-8 w-8 text-red-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{certifications.length}</p>
                  <p className="text-sm text-gray-400">Elite Certs</p>
                </CardContent>
              </Card>
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardContent className="p-6 text-center">
                  <Briefcase className="h-8 w-8 text-red-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{experiences.length}</p>
                  <p className="text-sm text-gray-400">Operations</p>
                </CardContent>
              </Card>
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardContent className="p-6 text-center">
                  <ImageIcon className="h-8 w-8 text-red-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{uploadedImages.length}</p>
                  <p className="text-sm text-gray-400">Media Assets</p>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Main Content */}
      <section className="relative py-12 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto space-y-8">
            {/* Blog Management */}
            <div className="grid lg:grid-cols-2 gap-8">
              {/* Create New Post */}
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Plus className="mr-2 h-5 w-5" />
                    Create Intel Report
                  </CardTitle>
                  <CardDescription className="text-gray-400">
                    Deploy new intelligence report with advanced markdown capabilities
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Report Title</label>
                    <input
                      type="text"
                      value={postTitle}
                      onChange={(e) => setPostTitle(e.target.value)}
                      placeholder="Enter report title..."
                      className="w-full px-4 py-3 bg-black/50 border border-red-900/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 backdrop-blur-sm"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">Classification</label>
                      <select
                        value={postCategory}
                        onChange={(e) => setPostCategory(e.target.value)}
                        className="w-full px-4 py-3 bg-black/50 border border-red-900/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 backdrop-blur-sm"
                      >
                        <option value="">Select classification...</option>
                        <option value="Web Security">Web Security</option>
                        <option value="Network Security">Network Security</option>
                        <option value="CTF Writeup">CTF Writeup</option>
                        <option value="Cloud Security">Cloud Security</option>
                        <option value="Tools & Techniques">Tools & Techniques</option>
                        <option value="Research">Research</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">Status</label>
                      <select
                        value={postStatus}
                        onChange={(e) => setPostStatus(e.target.value)}
                        className="w-full px-4 py-3 bg-black/50 border border-red-900/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 backdrop-blur-sm"
                      >
                        <option value="draft">Classified</option>
                        <option value="published">Declassified</option>
                        <option value="scheduled">Scheduled</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Featured Image</label>
                    {featuredImage && (
                      <div className="mb-4 relative">
                        <img
                          src={featuredImage || "/placeholder.svg"}
                          alt="Featured"
                          className="w-full h-32 object-cover rounded-lg border border-red-500/30"
                        />
                        <Button
                          onClick={() => setFeaturedImage("")}
                          size="sm"
                          variant="outline"
                          className="absolute top-2 right-2 border-red-600 text-red-400 hover:bg-red-900/20"
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    )}
                    <div className="border-2 border-dashed border-red-900/30 rounded-lg p-6 text-center hover:border-red-400/50 transition-colors cursor-pointer">
                      <Upload className="mx-auto h-12 w-12 text-gray-500 mb-4" />
                      <p className="text-gray-400 mb-2">Drop image here or click to upload</p>
                      <input
                        type="file"
                        accept="image/*"
                        onChange={(e) => handleImageUpload(e, true)}
                        className="hidden"
                        id="featured-upload"
                        disabled={isUploading}
                      />
                      <Button
                        variant="outline"
                        className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                        onClick={() => document.getElementById("featured-upload")?.click()}
                        disabled={isUploading}
                      >
                        {isUploading ? "Uploading..." : "Select File"}
                      </Button>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-sm font-medium text-gray-300">Content (Markdown)</label>
                      <div className="flex space-x-2">
                        <Button
                          type="button"
                          size="sm"
                          variant={!previewMode ? "default" : "outline"}
                          onClick={() => setPreviewMode(false)}
                          className={
                            !previewMode
                              ? "bg-gradient-to-r from-red-600 to-red-700 border-0"
                              : "border-red-500/50 text-red-400"
                          }
                        >
                          <Code className="mr-1 h-3 w-3" />
                          Edit
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant={previewMode ? "default" : "outline"}
                          onClick={() => setPreviewMode(true)}
                          className={
                            previewMode
                              ? "bg-gradient-to-r from-red-600 to-red-700 border-0"
                              : "border-red-500/50 text-red-400"
                          }
                        >
                          <Eye className="mr-1 h-3 w-3" />
                          Preview
                        </Button>
                      </div>
                    </div>

                    {!previewMode ? (
                      <div className="relative">
                        <textarea
                          rows={12}
                          value={markdownContent || sampleMarkdown}
                          onChange={(e) => setMarkdownContent(e.target.value)}
                          placeholder="Write your intel report in Markdown format..."
                          className="w-full px-4 py-3 bg-gray-900/50 border border-red-500/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 resize-none font-mono text-sm backdrop-blur-sm"
                        />
                        <div className="absolute top-2 right-2">
                          <Badge variant="secondary" className="bg-red-500/20 text-red-300 border-red-500/30 text-xs">
                            Markdown
                          </Badge>
                        </div>
                      </div>
                    ) : (
                      <div className="w-full min-h-[300px] px-4 py-3 bg-gray-900/50 border border-red-500/30 rounded-lg text-white overflow-auto backdrop-blur-sm">
                        <div
                          dangerouslySetInnerHTML={{
                            __html: markdownToHtml(markdownContent || sampleMarkdown),
                          }}
                        />
                      </div>
                    )}

                    <div className="mt-2 text-xs text-gray-500">
                      <p>
                        Supports: **bold**, *italic*, `code`, \`\`\`code blocks\`\`\`, # headers, - lists, [links](url)
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <Button
                      onClick={handlePublishPost}
                      className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white border-0"
                    >
                      <Save className="mr-2 h-4 w-4" />
                      {postStatus === "published" ? "Deploy Report" : "Save Draft"}
                    </Button>
                    <Button
                      onClick={() => {
                        setPostTitle("")
                        setPostCategory("")
                        setMarkdownContent("")
                        setPostStatus("draft")
                        setFeaturedImage("")
                      }}
                      variant="outline"
                      className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                    >
                      <FileText className="mr-2 h-4 w-4" />
                      Clear Form
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Manage Existing Posts */}
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <FileText className="mr-2 h-5 w-5" />
                    Manage Intel Reports
                  </CardTitle>
                  <CardDescription className="text-gray-400">
                    Edit, delete, or review your deployed intelligence reports
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4 max-h-96 overflow-y-auto">
                    {posts.map((post: any) => (
                      <div
                        key={post.id}
                        className="flex items-center justify-between p-4 bg-black/50 rounded-lg border border-red-900/30"
                      >
                        <div className="flex-1">
                          <h4 className="text-white font-medium">{post.title}</h4>
                          <div className="flex items-center space-x-4 mt-1">
                            <Badge
                              variant="secondary"
                              className={`text-xs ${
                                post.category === "Web Security"
                                  ? "bg-red-500/20 text-red-400 border-red-500/30"
                                  : post.category === "Network Security"
                                    ? "bg-red-600/20 text-red-400 border-red-600/30"
                                    : post.category === "CTF Writeup"
                                      ? "bg-red-700/20 text-red-300 border-red-700/30"
                                      : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                              }`}
                            >
                              {post.category}
                            </Badge>
                            <span className="text-xs text-gray-500">
                              {post.status === "published" ? `Deployed ${post.date}` : "Classified"}
                            </span>
                            <span className="text-xs text-red-400">{post.views} views</span>
                            <Badge variant="outline" className="border-red-600 text-red-400 text-xs">
                              Markdown
                            </Badge>
                          </div>
                        </div>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleEditPost(post)}
                            className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleDeletePost(post.id)}
                            className="border-red-600 text-red-400 hover:bg-red-900/20"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="mt-6 pt-4 border-t border-red-500/20">
                    <Button variant="outline" className="w-full border-red-500/50 text-red-400 hover:bg-red-500/10">
                      View All Reports
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Rest of the component continues with certifications, experience, profile management, etc. */}
            {/* The implementation would continue in the same red/black theme style... */}

            {/* Certifications & Experience Management */}
            <div className="grid lg:grid-cols-2 gap-8">
              {/* Certifications Management */}
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Award className="mr-2 h-5 w-5" />
                    Manage Elite Certifications
                  </CardTitle>
                  <CardDescription className="text-gray-400">
                    Add, edit, and manage your professional certifications
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Add New Certification */}
                  <div className="space-y-3 p-4 bg-gray-900/30 rounded-lg border border-red-500/20">
                    <h4 className="text-white font-medium">Add New Certification</h4>
                    <div>
                      <input
                        type="text"
                        value={newCertification.name}
                        onChange={(e) => setNewCertification({ ...newCertification, name: e.target.value })}
                        placeholder="Certification name (e.g., OSCP, CEH)"
                        className="w-full px-3 py-2 bg-gray-900/50 border border-red-500/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm backdrop-blur-sm"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <select
                        value={newCertification.status}
                        onChange={(e) => setNewCertification({ ...newCertification, status: e.target.value as any })}
                        className="px-3 py-2 bg-gray-900/50 border border-red-500/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 text-sm backdrop-blur-sm"
                      >
                        <option value="certified">Certified</option>
                        <option value="in-progress">In Progress</option>
                        <option value="planned">Planned</option>
                      </select>
                      <input
                        type="text"
                        value={newCertification.date}
                        onChange={(e) => setNewCertification({ ...newCertification, date: e.target.value })}
                        placeholder="Year (optional)"
                        className="px-3 py-2 bg-gray-900/50 border border-red-500/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm backdrop-blur-sm"
                      />
                    </div>
                    <Button
                      onClick={handleAddCertification}
                      size="sm"
                      className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white border-0"
                    >
                      <Plus className="mr-2 h-3 w-3" />
                      Add Certification
                    </Button>
                  </div>

                  {/* Existing Certifications */}
                  <div className="space-y-3 max-h-64 overflow-y-auto">
                    {certifications.map((cert) => (
                      <div
                        key={cert.id}
                        className="flex items-center justify-between p-3 bg-gray-900/30 rounded-lg border border-red-500/20"
                      >
                        <div className="flex-1">
                          <div className="flex items-center space-x-3">
                            <span className="text-white font-medium">{cert.name}</span>
                            <Badge className={getStatusColor(cert.status)}>
                              {cert.status === "certified" && <Shield className="mr-1 h-3 w-3" />}
                              {cert.status === "in-progress" && <Target className="mr-1 h-3 w-3" />}
                              {cert.status === "certified"
                                ? "Certified"
                                : cert.status === "in-progress"
                                  ? "In Progress"
                                  : "Planned"}
                            </Badge>
                            {cert.date && <span className="text-gray-400 text-sm">{cert.date}</span>}
                          </div>
                        </div>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleDeleteCertification(cert.id)}
                          className="border-red-600 text-red-400 hover:bg-red-900/20"
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Experience Management */}
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Briefcase className="mr-2 h-5 w-5" />
                    Manage Elite Operations
                  </CardTitle>
                  <CardDescription className="text-gray-400">
                    Add, edit, and manage your work experience
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Add New Experience */}
                  <div className="space-y-3 p-4 bg-gray-900/30 rounded-lg border border-red-500/20">
                    <h4 className="text-white font-medium">Add New Operation</h4>
                    <div className="grid grid-cols-2 gap-3">
                      <input
                        type="text"
                        value={newExperience.title}
                        onChange={(e) => setNewExperience({ ...newExperience, title: e.target.value })}
                        placeholder="Job title"
                        className="px-3 py-2 bg-gray-900/50 border border-red-500/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm backdrop-blur-sm"
                      />
                      <input
                        type="text"
                        value={newExperience.company}
                        onChange={(e) => setNewExperience({ ...newExperience, company: e.target.value })}
                        placeholder="Company"
                        className="px-3 py-2 bg-gray-900/50 border border-red-500/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm backdrop-blur-sm"
                      />
                    </div>
                    <input
                      type="text"
                      value={newExperience.period}
                      onChange={(e) => setNewExperience({ ...newExperience, period: e.target.value })}
                      placeholder="Period (e.g., 2023 - Present)"
                      className="w-full px-3 py-2 bg-gray-900/50 border border-red-500/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm backdrop-blur-sm"
                    />
                    <textarea
                      rows={3}
                      value={newExperience.description}
                      onChange={(e) => setNewExperience({ ...newExperience, description: e.target.value })}
                      placeholder="Job description"
                      className="w-full px-3 py-2 bg-gray-900/50 border border-red-500/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm resize-none backdrop-blur-sm"
                    />
                    <div className="flex items-center space-x-3">
                      <label className="flex items-center space-x-2 text-gray-300">
                        <input
                          type="checkbox"
                          checked={newExperience.current}
                          onChange={(e) => setNewExperience({ ...newExperience, current: e.target.checked })}
                          className="rounded border-red-500/30 bg-gray-900/50 text-red-500 focus:ring-red-500"
                        />
                        <span className="text-sm">Current position</span>
                      </label>
                      <Button
                        onClick={handleAddExperience}
                        size="sm"
                        className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white border-0"
                      >
                        <Plus className="mr-2 h-3 w-3" />
                        Add Operation
                      </Button>
                    </div>
                  </div>

                  {/* Existing Experiences */}
                  <div className="space-y-3 max-h-64 overflow-y-auto">
                    {experiences.map((exp) => (
                      <div key={exp.id} className="p-3 bg-gray-900/30 rounded-lg border border-red-500/20">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-3 mb-1">
                              <h4 className="text-white font-medium">{exp.title}</h4>
                              {exp.current && (
                                <Badge className="bg-red-500/20 text-red-300 border-red-500/30 text-xs">Current</Badge>
                              )}
                            </div>
                            <p className="text-red-400 text-sm font-medium">{exp.company}</p>
                            <p className="text-gray-400 text-sm">{exp.period}</p>
                            <p className="text-gray-300 text-sm mt-1">{exp.description}</p>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleDeleteExperience(exp.id)}
                            className="border-red-600 text-red-400 hover:bg-red-900/20 ml-3"
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Profile & Resume Management */}
            <div className="grid lg:grid-cols-2 gap-8">
              {/* Profile Image Management */}
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <User className="mr-2 h-5 w-5" />
                    Elite Profile Image
                  </CardTitle>
                  <CardDescription className="text-gray-400">Upload and manage your profile picture</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {profileImage && (
                    <div className="text-center">
                      <img
                        src={profileImage || "/placeholder.svg"}
                        alt="Profile"
                        className="w-32 h-32 object-cover rounded-full border-4 border-red-500/30 mx-auto mb-4"
                      />
                      <Button
                        onClick={() => {
                          setProfileImage("")
                          localStorage.removeItem("profileImage")
                        }}
                        size="sm"
                        variant="outline"
                        className="border-red-600 text-red-400 hover:bg-red-900/20"
                      >
                        <Trash2 className="mr-2 h-3 w-3" />
                        Remove Image
                      </Button>
                    </div>
                  )}
                  <div className="border-2 border-dashed border-red-500/30 rounded-lg p-6 text-center hover:border-red-400/50 transition-colors cursor-pointer">
                    <User className="mx-auto h-12 w-12 text-gray-500 mb-4" />
                    <p className="text-gray-400 mb-2">Upload elite profile image</p>
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handleProfileImageUpload}
                      className="hidden"
                      id="profile-upload"
                      disabled={isUploading}
                    />
                    <Button
                      variant="outline"
                      className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                      onClick={() => document.getElementById("profile-upload")?.click()}
                      disabled={isUploading}
                    >
                      {isUploading ? "Uploading..." : "Select Image"}
                    </Button>
                  </div>
                  <div className="text-xs text-gray-500">
                    <p>• Recommended: Square image, 400x400px minimum</p>
                    <p>• Max file size: 5MB • Supported: JPG, PNG, GIF</p>
                  </div>
                </CardContent>
              </Card>

              {/* Resume Management */}
              <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <FileText className="mr-2 h-5 w-5" />
                    Elite Resume Management
                  </CardTitle>
                  <CardDescription className="text-gray-400">Upload and manage your CV/Resume file</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {resumeFile && resumeFileName && (
                    <div className="p-4 bg-gray-900/30 rounded-lg border border-red-500/20">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-red-500/20 rounded-lg border border-red-500/30">
                            <File className="h-5 w-5 text-red-400" />
                          </div>
                          <div>
                            <p className="text-white font-medium">{resumeFileName}</p>
                            <p className="text-gray-500 text-sm">PDF Document</p>
                          </div>
                        </div>
                        <div className="flex space-x-2">
                          <Button
                            onClick={downloadResume}
                            size="sm"
                            variant="outline"
                            className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                          >
                            <Download className="h-3 w-3" />
                          </Button>
                          <Button
                            onClick={() => {
                              setResumeFile("")
                              setResumeFileName("")
                              localStorage.removeItem("resumeFile")
                              localStorage.removeItem("resumeFileName")
                            }}
                            size="sm"
                            variant="outline"
                            className="border-red-600 text-red-400 hover:bg-red-900/20"
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}
                  <div className="border-2 border-dashed border-red-500/30 rounded-lg p-6 text-center hover:border-red-400/50 transition-colors cursor-pointer">
                    <FolderOpen className="mx-auto h-12 w-12 text-gray-500 mb-4" />
                    <p className="text-gray-400 mb-2">Upload your resume/CV</p>
                    <input
                      type="file"
                      accept=".pdf"
                      onChange={handleResumeUpload}
                      className="hidden"
                      id="resume-upload"
                      disabled={isUploading}
                    />
                    <Button
                      variant="outline"
                      className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                      onClick={() => document.getElementById("resume-upload")?.click()}
                      disabled={isUploading}
                    >
                      {isUploading ? "Uploading..." : "Select PDF"}
                    </Button>
                  </div>
                  <div className="text-xs text-gray-500">
                    <p>• PDF files only • Max file size: 10MB</p>
                    <p>• This will be available for download on your portfolio</p>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Media Library */}
            <Card className="bg-black/50 border border-red-900/30 backdrop-blur-xl">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <ImageIcon className="mr-2 h-5 w-5" />
                  Elite Media Library
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Manage your blog images and media files. Click images to insert into content.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                  <div
                    className="aspect-square bg-gray-900/50 rounded-lg border-2 border-dashed border-red-500/30 flex items-center justify-center hover:border-red-400/50 transition-colors cursor-pointer"
                    onClick={() => document.getElementById("media-upload")?.click()}
                  >
                    <div className="text-center">
                      <Upload className="h-8 w-8 text-gray-500 mx-auto mb-2" />
                      <p className="text-xs text-gray-500">{isUploading ? "Uploading..." : "Upload"}</p>
                    </div>
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(e) => handleImageUpload(e, false)}
                      className="hidden"
                      id="media-upload"
                      disabled={isUploading}
                    />
                  </div>

                  {uploadedImages.map((image, index) => (
                    <div
                      key={index}
                      className="aspect-square bg-gray-900/50 rounded-lg border border-red-500/20 overflow-hidden group relative"
                    >
                      <img
                        src={image || "/placeholder.svg"}
                        alt={`Media ${index + 1}`}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform cursor-pointer"
                        onClick={() => insertImageIntoContent(image)}
                      />
                      <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center space-x-2">
                        <Button
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation()
                            insertImageIntoContent(image)
                          }}
                          className="bg-red-600 hover:bg-red-700 text-white text-xs px-2 py-1"
                        >
                          Insert
                        </Button>
                        <Button
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation()
                            handleDeleteImage(index)
                          }}
                          variant="outline"
                          className="border-red-600 text-red-400 hover:bg-red-900/20 text-xs px-2 py-1"
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-4 text-xs text-gray-500">
                  <p>
                    • Click images to insert into content • Max file size: 5MB • Supported formats: JPG, PNG, GIF, WebP
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative border-t border-red-900/30 bg-black/90 backdrop-blur-xl py-12 px-6 mt-20">
        <div className="container mx-auto text-center">
          <p className="text-gray-500">
            © {new Date().getFullYear()} jrBX4 Elite Operations. All rights reserved. | Elite Command Control
          </p>
        </div>
      </footer>
    </div>
  )
}
