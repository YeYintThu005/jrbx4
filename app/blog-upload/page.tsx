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
} from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"

// Simple markdown to HTML converter for preview
const markdownToHtml = (markdown: string): string => {
  const html = markdown
    // Images
    .replace(
      /!\[([^\]]*)\]$$([^)]+)$$/g,
      '<img src="$2" alt="$1" class="w-full max-w-md mx-auto rounded-lg border border-slate-600 my-4" />',
    )
    // Headers
    .replace(/^### (.*$)/gim, '<h3 class="text-lg font-semibold text-white mb-2">$1</h3>')
    .replace(/^## (.*$)/gim, '<h2 class="text-xl font-bold text-white mb-3">$1</h2>')
    .replace(/^# (.*$)/gim, '<h1 class="text-2xl font-bold text-white mb-4">$1</h1>')
    // Bold and italic
    .replace(/\*\*(.*?)\*\*/g, '<strong class="font-bold text-white">$1</strong>')
    .replace(/\*(.*?)\*/g, '<em class="italic text-slate-300">$1</em>')
    // Code blocks
    .replace(
      /```(\w+)?\n([\s\S]*?)```/g,
      '<pre class="bg-slate-800 p-4 rounded-lg border border-slate-600 my-4 overflow-x-auto"><code class="text-green-400 text-sm">$2</code></pre>',
    )
    // Inline code
    .replace(/`(.*?)`/g, '<code class="bg-slate-700 px-2 py-1 rounded text-red-400 text-sm">$1</code>')
    // Links
    .replace(
      /\[([^\]]+)\]$$([^)]+)$$/g,
      '<a href="$2" class="text-red-400 hover:text-red-300 underline" target="_blank">$1</a>',
    )
    // Line breaks
    .replace(/\n\n/g, '</p><p class="text-slate-300 mb-4">')
    .replace(/\n/g, "<br>")
    // Lists
    .replace(/^- (.*$)/gim, '<li class="text-slate-300 mb-1">• $1</li>')

  return `<div class="prose prose-invert max-w-none"><p class="text-slate-300 mb-4">${html}</p></div>`
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
    },
    {
      id: 3,
      title: "HTB Machine Writeup: Buffer Overflow",
      category: "CTF Writeup",
      status: "published",
      date: "Nov 28, 2024",
      views: "654",
      content: "# HTB Machine Writeup: Buffer Overflow\n\nStep-by-step walkthrough of exploiting a custom binary...",
    },
    {
      id: 4,
      title: "Zero-Day Discovery Methodology",
      category: "Research",
      status: "draft",
      date: "Draft",
      views: "0",
      content: "# Zero-Day Discovery Methodology\n\nMethodology and tools for discovering zero-day vulnerabilities...",
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

    // Save to localStorage so it persists
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
      setPosts(posts.filter((post) => post.id !== id))
      alert("Post deleted successfully!")
    }
  }

  const handleEditPost = (post: any) => {
    setPostTitle(post.title)
    setPostCategory(post.category)
    setMarkdownContent(post.content)
    setPostStatus(post.status)
    // Remove the post from the list since we're editing it
    setPosts(posts.filter((p) => p.id !== post.id))
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

  const handleDeleteImage = (index: number) => {
    if (confirm("Are you sure you want to delete this image?")) {
      setUploadedImages((prev) => prev.filter((_, i) => i !== index))
      alert("Image deleted successfully!")
    }
  }

  const insertImageIntoContent = (imageUrl: string) => {
    const imageMarkdown = `![Image description](${imageUrl})\n\n`
    setMarkdownContent((prev) => prev + imageMarkdown)
    alert("Image inserted into content!")
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
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return null
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
              <Badge variant="secondary" className="bg-red-900/30 text-red-300 border-red-700 ml-4">
                Admin Panel
              </Badge>
            </div>
            <div className="flex items-center space-x-6">
              <Link href="/" className="text-slate-300 hover:text-white transition-colors">
                Home
              </Link>
              <Link href="/blog" className="text-slate-300 hover:text-white transition-colors">
                Blog
              </Link>
              <Button
                onClick={() => setShowChangePassword(true)}
                variant="outline"
                size="sm"
                className="border-slate-600 text-slate-300 hover:bg-slate-700"
              >
                <Settings className="mr-2 h-4 w-4" />
                Settings
              </Button>
              <Button
                onClick={handleLogout}
                variant="outline"
                size="sm"
                className="border-slate-600 text-slate-300 hover:bg-slate-700"
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
          <Card className="bg-slate-800 border-slate-700 w-full max-w-md">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Key className="mr-2 h-5 w-5" />
                Change Password
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {passwordError && (
                <div className="p-3 bg-red-900/20 border border-red-700 rounded-md">
                  <p className="text-red-400 text-sm">{passwordError}</p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Current Password</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">New Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Confirm New Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>

              <div className="flex space-x-3">
                <Button onClick={handleChangePassword} className="bg-red-600 hover:bg-red-700 text-white flex-1">
                  Change Password
                </Button>
                <Button
                  onClick={() => setShowChangePassword(false)}
                  variant="outline"
                  className="border-slate-600 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Hero Section */}
      <section className="py-16 px-4">
        <div className="container mx-auto">
          <div className="max-w-4xl mx-auto text-center">
            <h1 className="text-4xl md:text-6xl font-bold text-white mb-6">
              Blog
              <span className="text-red-500 block">Administration</span>
            </h1>
            <p className="text-xl text-slate-300 mb-8 max-w-2xl mx-auto">
              Create, manage, and publish your cybersecurity insights with Markdown support.
            </p>
          </div>
        </div>
      </section>

      {/* Dashboard Stats */}
      <section className="py-8 px-4 bg-slate-800/30">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="grid md:grid-cols-4 gap-6">
              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6 text-center">
                  <FileText className="h-8 w-8 text-red-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{posts.length}</p>
                  <p className="text-sm text-slate-400">Total Posts</p>
                </CardContent>
              </Card>
              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6 text-center">
                  <BarChart3 className="h-8 w-8 text-green-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">2.4k</p>
                  <p className="text-sm text-slate-400">Total Views</p>
                </CardContent>
              </Card>
              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6 text-center">
                  <Eye className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">{posts.filter((p) => p.status === "draft").length}</p>
                  <p className="text-sm text-slate-400">Draft Posts</p>
                </CardContent>
              </Card>
              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6 text-center">
                  <ImageIcon className="h-8 w-8 text-purple-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-white">45</p>
                  <p className="text-sm text-slate-400">Media Files</p>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Main Content */}
      <section className="py-12 px-4">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            <div className="grid lg:grid-cols-2 gap-8">
              {/* Create New Post */}
              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Plus className="mr-2 h-5 w-5" />
                    Create New Post
                  </CardTitle>
                  <CardDescription className="text-slate-400">
                    Write and publish a new cybersecurity article with Markdown support
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">Post Title</label>
                    <input
                      type="text"
                      value={postTitle}
                      onChange={(e) => setPostTitle(e.target.value)}
                      placeholder="Enter post title..."
                      className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Category</label>
                      <select
                        value={postCategory}
                        onChange={(e) => setPostCategory(e.target.value)}
                        className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
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
                      <label className="block text-sm font-medium text-slate-300 mb-2">Status</label>
                      <select
                        value={postStatus}
                        onChange={(e) => setPostStatus(e.target.value)}
                        className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                      >
                        <option value="draft">Draft</option>
                        <option value="published">Published</option>
                        <option value="scheduled">Scheduled</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">Featured Image</label>
                    {featuredImage && (
                      <div className="mb-4 relative">
                        <img
                          src={featuredImage || "/placeholder.svg"}
                          alt="Featured"
                          className="w-full h-32 object-cover rounded-lg border border-slate-600"
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
                    <div className="border-2 border-dashed border-slate-600 rounded-lg p-6 text-center hover:border-slate-500 transition-colors cursor-pointer">
                      <Upload className="mx-auto h-12 w-12 text-slate-400 mb-4" />
                      <p className="text-slate-400 mb-2">Drop image here or click to upload</p>
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
                        className="border-slate-600 text-slate-300 hover:bg-slate-700"
                        onClick={() => document.getElementById("featured-upload")?.click()}
                        disabled={isUploading}
                      >
                        {isUploading ? "Uploading..." : "Choose File"}
                      </Button>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-sm font-medium text-slate-300">Content (Markdown)</label>
                      <div className="flex space-x-2">
                        <Button
                          type="button"
                          size="sm"
                          variant={!previewMode ? "default" : "outline"}
                          onClick={() => setPreviewMode(false)}
                          className={!previewMode ? "bg-red-600 hover:bg-red-700" : "border-slate-600 text-slate-300"}
                        >
                          <Code className="mr-1 h-3 w-3" />
                          Edit
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant={previewMode ? "default" : "outline"}
                          onClick={() => setPreviewMode(true)}
                          className={previewMode ? "bg-red-600 hover:bg-red-700" : "border-slate-600 text-slate-300"}
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
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500 resize-none font-mono text-sm"
                        />
                        <div className="absolute top-2 right-2">
                          <Badge variant="secondary" className="bg-slate-600 text-slate-300 text-xs">
                            Markdown
                          </Badge>
                        </div>
                      </div>
                    ) : (
                      <div className="w-full min-h-[300px] px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white overflow-auto">
                        <div
                          dangerouslySetInnerHTML={{
                            __html: markdownToHtml(markdownContent || sampleMarkdown),
                          }}
                        />
                      </div>
                    )}

                    <div className="mt-2 text-xs text-slate-400">
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
                      }}
                      variant="outline"
                      className="border-slate-600 text-slate-300 hover:bg-slate-700"
                    >
                      <FileText className="mr-2 h-4 w-4" />
                      Clear Form
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Manage Existing Posts */}
              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <FileText className="mr-2 h-5 w-5" />
                    Manage Posts
                  </CardTitle>
                  <CardDescription className="text-slate-400">
                    Edit, delete, or view your published articles
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4 max-h-96 overflow-y-auto">
                    {posts.map((post) => (
                      <div
                        key={post.id}
                        className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg border border-slate-600"
                      >
                        <div className="flex-1">
                          <h4 className="text-white font-medium">{post.title}</h4>
                          <div className="flex items-center space-x-4 mt-1">
                            <Badge
                              variant="secondary"
                              className={`text-xs ${
                                post.category === "Web Security"
                                  ? "bg-red-900/30 text-red-300 border-red-700"
                                  : post.category === "Network Security"
                                    ? "bg-blue-900/30 text-blue-300 border-blue-700"
                                    : post.category === "CTF Writeup"
                                      ? "bg-green-900/30 text-green-300 border-green-700"
                                      : post.category === "Research"
                                        ? "bg-yellow-900/30 text-yellow-300 border-yellow-700"
                                        : "bg-purple-900/30 text-purple-300 border-purple-700"
                              }`}
                            >
                              {post.category}
                            </Badge>
                            <span className="text-xs text-slate-400">
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
                            className="border-slate-600 text-slate-300 hover:bg-slate-600"
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

                  <div className="mt-6 pt-4 border-t border-slate-600">
                    <Button variant="outline" className="w-full border-slate-600 text-slate-300 hover:bg-slate-700">
                      View All Posts
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Media Library */}
            <Card className="bg-slate-800/50 border-slate-700 mt-8">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <ImageIcon className="mr-2 h-5 w-5" />
                  Media Library
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Manage your blog images and media files. Click images to insert into content.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                  <div
                    className="aspect-square bg-slate-700 rounded-lg border-2 border-dashed border-slate-600 flex items-center justify-center hover:border-slate-500 transition-colors cursor-pointer"
                    onClick={() => document.getElementById("media-upload")?.click()}
                  >
                    <div className="text-center">
                      <Upload className="h-8 w-8 text-slate-400 mx-auto mb-2" />
                      <p className="text-xs text-slate-400">{isUploading ? "Uploading..." : "Upload"}</p>
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
                      className="aspect-square bg-slate-700 rounded-lg border border-slate-600 overflow-hidden group relative"
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

                <div className="mt-4 text-xs text-slate-400">
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
      <footer className="border-t border-slate-700 bg-slate-900/50 py-8 px-4 mt-20">
        <div className="container mx-auto text-center">
          <p className="text-slate-400">
            © {new Date().getFullYear()} Ye Yint Thu. All rights reserved. | Blog Administration
          </p>
        </div>
      </footer>
    </div>
  )
}
