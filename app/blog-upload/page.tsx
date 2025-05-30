"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Shield,
  Edit,
  Upload,
  Save,
  Eye,
  FileText,
  Trash2,
  ImageIcon,
  Plus,
  BarChart3,
  LogOut,
  Code,
  Settings,
  Key,
  User,
  FolderOpen,
  Download,
  File,
} from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"

// Simple markdown to HTML converter for preview
const markdownToHtml = (markdown: string): string => {
  const html = markdown
    // Images
    .replace(
      /!\[([^\]]*)\]$$([^)]+)$$/g,
      '<img src="$2" alt="$1" class="w-full max-w-md mx-auto rounded-lg border border-gray-600 my-4" />',
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
      '<pre class="bg-gray-800 p-4 rounded-lg border border-gray-600 my-4 overflow-x-auto"><code class="text-green-400 text-sm">$2</code></pre>',
    )
    // Inline code
    .replace(/`(.*?)`/g, '<code class="bg-gray-700 px-2 py-1 rounded text-red-400 text-sm">$1</code>')
    // Links
    .replace(
      /\[([^\]]+)\]$$([^)]+)$$/g,
      '<a href="$2" class="text-red-400 hover:text-red-300 underline" target="_blank">$1</a>',
    )
    // Line breaks
    .replace(/\n\n/g, '</p><p class="text-gray-300 mb-4">')
    .replace(/\n/g, "<br>")
    // Lists
    .replace(/^- (.*$)/gim, '<li class="text-gray-300 mb-1">• $1</li>')

  return `<div class="prose prose-invert max-w-none"><p class="text-gray-300 mb-4">${html}</p></div>`
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
  const [posts, setPosts] = useState([
    {
      id: 1,
      title: "Advanced SQL Injection Techniques",
      category: "Web Security",
      status: "published",
      date: "Dec 15, 2024",
      views: "1.2k",
      content:
        "# Advanced SQL Injection Techniques\n\nSQL injection remains one of the most critical vulnerabilities...",
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
      content:
        "# Active Directory Privilege Escalation\n\nThis guide covers common AD privilege escalation techniques...",
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
      content: "# HTB Machine Writeup: Buffer Overflow\n\nStep-by-step walkthrough of exploiting a custom binary...",
      featuredImage: "/placeholder.svg?height=300&width=400",
      slug: "htb-machine-writeup-buffer-overflow",
    },
    {
      id: 4,
      title: "Zero-Day Discovery Methodology",
      category: "Research",
      status: "draft",
      date: "Draft",
      views: "0",
      content: "# Zero-Day Discovery Methodology\n\nMethodology and tools for discovering zero-day vulnerabilities...",
      featuredImage: "/placeholder.svg?height=300&width=400",
      slug: "zero-day-discovery-methodology",
    },
  ])
  const [uploadedImages, setUploadedImages] = useState<string[]>([
    "/placeholder.svg?height=150&width=150",
    "/placeholder.svg?height=150&width=150",
    "/placeholder.svg?height=150&width=150",
    "/placeholder.svg?height=150&width=150",
    "/placeholder.svg?height=150&width=150",
  ])
  const [featuredImage, setFeaturedImage] = useState<string>("")
  const [isUploading, setIsUploading] = useState(false)
  const [profileImage, setProfileImage] = useState<string>("")
  const [resumeFile, setResumeFile] = useState<string>("")
  const [resumeFileName, setResumeFileName] = useState<string>("")
  const router = useRouter()

  useEffect(() => {
    // Check authentication status
    const authToken = localStorage.getItem("adminAuth")
    if (authToken) {
      setIsAuthenticated(true)

      // Load saved posts from localStorage
      const savedPosts = localStorage.getItem("blogPosts")
      if (savedPosts) {
        setPosts(JSON.parse(savedPosts))
      }

      // Load saved profile image
      const savedProfileImage = localStorage.getItem("profileImage")
      if (savedProfileImage) {
        setProfileImage(savedProfileImage)
      }

      // Load saved resume
      const savedResume = localStorage.getItem("resumeFile")
      const savedResumeFileName = localStorage.getItem("resumeFileName")
      if (savedResume && savedResumeFileName) {
        setResumeFile(savedResume)
        setResumeFileName(savedResumeFileName)
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
      id: Date.now(), // Use timestamp for unique ID
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
      const updatedPosts = posts.filter((post) => post.id !== id)
      setPosts(updatedPosts)

      // Update localStorage to sync across all pages
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

    // Remove the post from the list since we're editing it
    const updatedPosts = posts.filter((p) => p.id !== post.id)
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

    // In production, this would update the password on the server
    alert("Password changed successfully!")
    setShowChangePassword(false)
    setCurrentPassword("")
    setNewPassword("")
    setConfirmPassword("")
  }

  const handleImageUpload = async (event: React.ChangeEvent<HTMLInputElement>, isFeatured = false) => {
    const file = event.target.files?.[0]
    if (!file) return

    // Validate file type
    if (!file.type.startsWith("image/")) {
      alert("Please select a valid image file")
      return
    }

    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      alert("Image size must be less than 5MB")
      return
    }

    setIsUploading(true)

    try {
      // Create a data URL for the image
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

    // Validate file type
    if (!file.type.startsWith("image/")) {
      alert("Please select a valid image file")
      return
    }

    // Validate file size (max 5MB)
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

    // Validate file type (PDF only)
    if (file.type !== "application/pdf") {
      alert("Please select a PDF file")
      return
    }

    // Validate file size (max 10MB)
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

    // Get the current cursor position in the textarea
    const textarea = document.querySelector("textarea") as HTMLTextAreaElement
    if (textarea) {
      const start = textarea.selectionStart
      const end = textarea.selectionEnd
      const currentContent = markdownContent || ""

      // Insert the image markdown at the cursor position
      const newContent = currentContent.substring(0, start) + imageMarkdown + currentContent.substring(end)
      setMarkdownContent(newContent)

      // Set focus back to textarea and position cursor after inserted text
      setTimeout(() => {
        textarea.focus()
        textarea.setSelectionRange(start + imageMarkdown.length, start + imageMarkdown.length)
      }, 0)
    } else {
      // Fallback: append to end if textarea not found
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

  // Sample markdown content
  const sampleMarkdown = `# Advanced SQL Injection Techniques

## Introduction

SQL injection remains one of the most critical vulnerabilities in web applications. This article explores advanced techniques used in modern penetration testing.

## Key Techniques

### 1. Union-Based Injection

\`\`\`sql
' UNION SELECT 1,2,3,database(),5-- -
\`\`\`

### 2. Boolean-Based Blind Injection

\`\`\`sql
' AND (SELECT SUBSTRING(@@version,1,1))='5'-- -
\`\`\`

## Tools Used

- **Burp Suite**: For intercepting requests
- **SQLMap**: Automated SQL injection tool
- **Custom Scripts**: Python-based payloads

## Conclusion

Understanding these techniques helps security professionals better defend against SQL injection attacks.

---

*Published by Ye Yint Thu | OSI Team Member*`

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-white">Loading...</div>
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
        <div className="absolute inset-0 bg-gradient-to-br from-red-900/5 via-black to-blue-900/5"></div>
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
                <div className="text-xs text-red-400 font-medium">ADMIN PANEL</div>
              </div>
            </div>
            <div className="flex items-center space-x-6">
              <Link href="/" className="text-gray-300 hover:text-white transition-colors">
                Home
              </Link>
              <Link href="/blog" className="text-gray-300 hover:text-white transition-colors">
                Blog
              </Link>
              <Button
                onClick={() => setShowChangePassword(true)}
                variant="outline"
                size="sm"
                className="border-gray-700 text-gray-300 hover:bg-gray-800"
              >
                <Settings className="mr-2 h-4 w-4" />
                Settings
              </Button>
              <Button
                onClick={handleLogout}
                variant="outline"
                size="sm"
                className="border-gray-700 text-gray-300 hover:bg-gray-800"
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
          <Card className="bg-gray-900/90 border-gray-800 w-full max-w-md backdrop-blur-xl">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Key className="mr-2 h-5 w-5" />
                Change Password
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {passwordError && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl">
                  <p className="text-red-400 text-sm">{passwordError}</p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Current Password</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">New Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Confirm New Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>

              <div className="flex space-x-3">
                <Button onClick={handleChangePassword} className="bg-red-600 hover:bg-red-700 text-white flex-1">
                  Change Password
                </Button>
                <Button
                  onClick={() => setShowChangePassword(false)}
                  variant="outline"
                  className="border-gray-700 text-gray-300 hover:bg-gray-800"
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
            <h1 className="text-5xl md:text-7xl font-bold mb-6">
              <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">Blog</span>
              <span className="text-red-500 block">Administration</span>
            </h1>
            <p className="text-xl text-gray-400 mb-8 max-w-2xl mx-auto">
              Create, manage, and publish your cybersecurity insights with advanced tools and media management.
            </p>
          </div>
        </div>
      </section>

      {/* Dashboard Stats */}
      <section className="relative py-8 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="grid md:grid-cols-4 gap-6">
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardContent className="p-6 text-center">
                  <FileText className="h-8 w-8 text-red-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{posts.length}</p>
                  <p className="text-sm text-gray-400">Total Posts</p>
                </CardContent>
              </Card>
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardContent className="p-6 text-center">
                  <BarChart3 className="h-8 w-8 text-green-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">2.4k</p>
                  <p className="text-sm text-gray-400">Total Views</p>
                </CardContent>
              </Card>
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardContent className="p-6 text-center">
                  <Eye className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{posts.filter((p) => p.status === "draft").length}</p>
                  <p className="text-sm text-gray-400">Draft Posts</p>
                </CardContent>
              </Card>
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardContent className="p-6 text-center">
                  <ImageIcon className="h-8 w-8 text-purple-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{uploadedImages.length}</p>
                  <p className="text-sm text-gray-400">Media Files</p>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Main Content */}
      <section className="relative py-12 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="grid lg:grid-cols-2 gap-8">
              {/* Create New Post */}
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Plus className="mr-2 h-5 w-5" />
                    Create New Post
                  </CardTitle>
                  <CardDescription className="text-gray-400">
                    Write and publish a new cybersecurity article with Markdown support
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Post Title</label>
                    <input
                      type="text"
                      value={postTitle}
                      onChange={(e) => setPostTitle(e.target.value)}
                      placeholder="Enter post title..."
                      className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">Category</label>
                      <select
                        value={postCategory}
                        onChange={(e) => setPostCategory(e.target.value)}
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                      >
                        <option value="">Select category...</option>
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
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                      >
                        <option value="draft">Draft</option>
                        <option value="published">Published</option>
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
                          className="w-full h-32 object-cover rounded-xl border border-gray-800"
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
                    <div className="border-2 border-dashed border-gray-700 rounded-xl p-6 text-center hover:border-gray-600 transition-colors cursor-pointer">
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
                        className="border-gray-700 text-gray-300 hover:bg-gray-800"
                        onClick={() => document.getElementById("featured-upload")?.click()}
                        disabled={isUploading}
                      >
                        {isUploading ? "Uploading..." : "Choose File"}
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
                          className={!previewMode ? "bg-red-600 hover:bg-red-700" : "border-gray-700 text-gray-300"}
                        >
                          <Code className="mr-1 h-3 w-3" />
                          Edit
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant={previewMode ? "default" : "outline"}
                          onClick={() => setPreviewMode(true)}
                          className={previewMode ? "bg-red-600 hover:bg-red-700" : "border-gray-700 text-gray-300"}
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
                          placeholder="Write your blog post content in Markdown format..."
                          className="w-full px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 resize-none font-mono text-sm"
                        />
                        <div className="absolute top-2 right-2">
                          <Badge variant="secondary" className="bg-gray-700 text-gray-300 text-xs">
                            Markdown
                          </Badge>
                        </div>
                      </div>
                    ) : (
                      <div className="w-full min-h-[300px] px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl text-white overflow-auto">
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
                    <Button onClick={handlePublishPost} className="bg-red-600 hover:bg-red-700 text-white">
                      <Save className="mr-2 h-4 w-4" />
                      {postStatus === "published" ? "Publish Post" : "Save Draft"}
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
                      className="border-gray-700 text-gray-300 hover:bg-gray-800"
                    >
                      <FileText className="mr-2 h-4 w-4" />
                      Clear Form
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Manage Existing Posts */}
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <FileText className="mr-2 h-5 w-5" />
                    Manage Posts
                  </CardTitle>
                  <CardDescription className="text-gray-400">
                    Edit, delete, or view your published articles
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4 max-h-96 overflow-y-auto">
                    {posts.map((post) => (
                      <div
                        key={post.id}
                        className="flex items-center justify-between p-4 bg-gray-900/30 rounded-xl border border-gray-800"
                      >
                        <div className="flex-1">
                          <h4 className="text-white font-medium">{post.title}</h4>
                          <div className="flex items-center space-x-4 mt-1">
                            <Badge
                              variant="secondary"
                              className={`text-xs ${
                                post.category === "Web Security"
                                  ? "bg-red-500/10 text-red-400 border-red-500/20"
                                  : post.category === "Network Security"
                                    ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
                                    : post.category === "CTF Writeup"
                                      ? "bg-green-500/10 text-green-400 border-green-500/20"
                                      : post.category === "Research"
                                        ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                                        : "bg-purple-500/10 text-purple-400 border-purple-500/20"
                              }`}
                            >
                              {post.category}
                            </Badge>
                            <span className="text-xs text-gray-500">
                              {post.status === "published" ? `Published ${post.date}` : "Draft"}
                            </span>
                            <span className="text-xs text-green-400">{post.views} views</span>
                            <Badge variant="outline" className="border-green-600 text-green-400 text-xs">
                              Markdown
                            </Badge>
                          </div>
                        </div>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleEditPost(post)}
                            className="border-gray-700 text-gray-300 hover:bg-gray-800"
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

                  <div className="mt-6 pt-4 border-t border-gray-800">
                    <Button variant="outline" className="w-full border-gray-700 text-gray-300 hover:bg-gray-800">
                      View All Posts
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Profile & Resume Management */}
            <div className="grid lg:grid-cols-2 gap-8 mt-8">
              {/* Profile Image Management */}
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <User className="mr-2 h-5 w-5" />
                    Profile Image
                  </CardTitle>
                  <CardDescription className="text-gray-400">Upload and manage your profile picture</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {profileImage && (
                    <div className="text-center">
                      <img
                        src={profileImage || "/placeholder.svg"}
                        alt="Profile"
                        className="w-32 h-32 object-cover rounded-full border-4 border-gray-800 mx-auto mb-4"
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
                  <div className="border-2 border-dashed border-gray-700 rounded-xl p-6 text-center hover:border-gray-600 transition-colors cursor-pointer">
                    <User className="mx-auto h-12 w-12 text-gray-500 mb-4" />
                    <p className="text-gray-400 mb-2">Upload profile image</p>
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
                      className="border-gray-700 text-gray-300 hover:bg-gray-800"
                      onClick={() => document.getElementById("profile-upload")?.click()}
                      disabled={isUploading}
                    >
                      {isUploading ? "Uploading..." : "Choose Image"}
                    </Button>
                  </div>
                  <div className="text-xs text-gray-500">
                    <p>• Recommended: Square image, 400x400px minimum</p>
                    <p>• Max file size: 5MB • Supported: JPG, PNG, GIF</p>
                  </div>
                </CardContent>
              </Card>

              {/* Resume Management */}
              <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <FileText className="mr-2 h-5 w-5" />
                    Resume Management
                  </CardTitle>
                  <CardDescription className="text-gray-400">Upload and manage your CV/Resume file</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {resumeFile && resumeFileName && (
                    <div className="p-4 bg-gray-900/30 rounded-xl border border-gray-800">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-red-500/10 rounded-lg">
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
                            className="border-gray-700 text-gray-300 hover:bg-gray-800"
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
                  <div className="border-2 border-dashed border-gray-700 rounded-xl p-6 text-center hover:border-gray-600 transition-colors cursor-pointer">
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
                      className="border-gray-700 text-gray-300 hover:bg-gray-800"
                      onClick={() => document.getElementById("resume-upload")?.click()}
                      disabled={isUploading}
                    >
                      {isUploading ? "Uploading..." : "Choose PDF"}
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
            <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 backdrop-blur-xl border-gray-800/50 mt-8">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <ImageIcon className="mr-2 h-5 w-5" />
                  Media Library
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Manage your blog images and media files. Click images to insert into content.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                  <div
                    className="aspect-square bg-gray-900/50 rounded-xl border-2 border-dashed border-gray-700 flex items-center justify-center hover:border-gray-600 transition-colors cursor-pointer"
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
                      className="aspect-square bg-gray-900/50 rounded-xl border border-gray-800 overflow-hidden group relative"
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
                          className="bg-green-600 hover:bg-green-700 text-white text-xs px-2 py-1"
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
      <footer className="relative border-t border-gray-800/50 bg-black/80 backdrop-blur-xl py-8 px-6 mt-20">
        <div className="container mx-auto text-center">
          <p className="text-gray-500">
            © {new Date().getFullYear()} Ye Yint Thu. All rights reserved. | Blog Administration
          </p>
        </div>
      </footer>
    </div>
  )
}
