import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Shield,
  Search,
  CheckCircle,
  Mail,
  Phone,
  MapPin,
  Github,
  Linkedin,
  Download,
  ExternalLink,
} from "lucide-react"
import Link from "next/link"

export default function Portfolio() {
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
              <Link href="#about" className="text-slate-300 hover:text-white transition-colors">
                About
              </Link>
              <Link href="#services" className="text-slate-300 hover:text-white transition-colors">
                Services
              </Link>
              <Link href="#skills" className="text-slate-300 hover:text-white transition-colors">
                Skills
              </Link>
              <Link href="/blog" className="text-slate-300 hover:text-white transition-colors">
                Blog
              </Link>
              <Link href="#contact" className="text-slate-300 hover:text-white transition-colors">
                Contact
              </Link>
            </div>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 px-4">
        <div className="container mx-auto text-center">
          <div className="max-w-4xl mx-auto">
            <h1 className="text-5xl md:text-7xl font-bold text-white mb-6">
              Ye Yint Thu
              <span className="text-red-500 block">Penetration Tester</span>
            </h1>
            <p className="text-xl text-slate-300 mb-8 max-w-2xl mx-auto">
              Protecting your digital assets through comprehensive security assessments, vulnerability analysis, and
              ethical hacking services.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Button size="lg" className="bg-red-600 hover:bg-red-700 text-white">
                <Mail className="mr-2 h-5 w-5" />
                Get Security Assessment
              </Button>
              <Button size="lg" variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-800">
                <Download className="mr-2 h-5 w-5" />
                Download Resume
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="py-20 px-4 bg-slate-800/30">
        <div className="container mx-auto">
          <div className="max-w-4xl mx-auto">
            <h2 className="text-3xl font-bold text-white mb-8 text-center">About Me</h2>
            <div className="grid md:grid-cols-2 gap-12 items-center">
              <div>
                <p className="text-slate-300 text-lg mb-6">
                  With over 2 years of experience in cybersecurity, I specialize in identifying and exploiting
                  vulnerabilities to help organizations strengthen their security posture. My expertise spans web
                  applications, network infrastructure, and mobile applications.
                </p>
                <p className="text-slate-300 text-lg mb-6">
                  I hold multiple industry certifications and have successfully conducted security assessments for
                  Fortune 500 companies, startups, and government agencies. I am also a proud team member of OSI (The
                  Offensive Security Initiative).
                </p>
                <div className="flex flex-wrap gap-2 mb-6">
                  <Badge variant="secondary" className="bg-red-900/30 text-red-300 border-red-700">
                    eCPPT v2
                  </Badge>
                  <Badge variant="secondary" className="bg-red-900/30 text-red-300 border-red-700">
                    CRTA
                  </Badge>
                  <Badge variant="secondary" className="bg-red-900/30 text-red-300 border-red-700">
                    CPTS
                  </Badge>
                </div>

                {/* OSI Team Member */}
                <div className="mb-6 p-4 bg-gradient-to-r from-red-900/20 to-orange-900/20 rounded-lg border border-red-700/50">
                  <div className="flex items-center space-x-3 mb-2">
                    <div className="w-8 h-8 bg-red-500 rounded flex items-center justify-center">
                      <span className="text-white font-bold text-sm">OSI</span>
                    </div>
                    <div>
                      <p className="text-white font-semibold">Team Member - The Offensive Security Initiative</p>
                      <p className="text-slate-300 text-sm">
                        Cybersecurity team specializing in offensive security, red teaming, and threat simulation
                      </p>
                    </div>
                  </div>
                  <Link
                    href="https://www.offsecinitiative.net/about"
                    target="_blank"
                    className="inline-flex items-center text-red-400 hover:text-red-300 text-sm transition-colors"
                  >
                    Learn more about OSI
                    <ExternalLink className="ml-1 h-3 w-3" />
                  </Link>
                </div>

                <div className="p-4 bg-slate-700/30 rounded-lg border border-slate-600">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-green-500 rounded flex items-center justify-center">
                      <span className="text-white font-bold text-sm">HTB</span>
                    </div>
                    <div>
                      <p className="text-white font-semibold">Hack The Box Profile</p>
                      <p className="text-slate-300">Username: jrBX4</p>
                    </div>
                  </div>
                </div>
              </div>
              <div className="space-y-4">
                <div className="flex items-center space-x-3">
                  <CheckCircle className="h-6 w-6 text-green-500" />
                  <span className="text-slate-300">500+ Vulnerabilities Discovered</span>
                </div>
                <div className="flex items-center space-x-3">
                  <CheckCircle className="h-6 w-6 text-green-500" />
                  <span className="text-slate-300">100+ Security Assessments</span>
                </div>
                <div className="flex items-center space-x-3">
                  <CheckCircle className="h-6 w-6 text-green-500" />
                  <span className="text-slate-300">Zero False Positives</span>
                </div>
                <div className="flex items-center space-x-3">
                  <CheckCircle className="h-6 w-6 text-green-500" />
                  <span className="text-slate-300">24/7 Security Monitoring</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section id="services" className="py-20 px-4">
        <div className="container mx-auto">
          <h2 className="text-3xl font-bold text-white mb-12 text-center">Security Services</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <div className="flex items-center space-x-3">
                  <Search className="h-8 w-8 text-red-500" />
                  <CardTitle className="text-white">Web Application Testing</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <CardDescription className="text-slate-300">
                  Comprehensive security assessment of web applications including OWASP Top 10 vulnerabilities,
                  authentication bypass, and business logic flaws.
                </CardDescription>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <div className="flex items-center space-x-3">
                  <Shield className="h-8 w-8 text-red-500" />
                  <CardTitle className="text-white">Network Penetration Testing</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <CardDescription className="text-slate-300">
                  Internal and external network security assessments, including vulnerability scanning, privilege
                  escalation, and lateral movement testing.
                </CardDescription>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <div className="flex items-center space-x-3">
                  <Shield className="h-8 w-8 text-red-500" />
                  <CardTitle className="text-white">Red Team Operations</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <CardDescription className="text-slate-300">
                  Advanced persistent threat simulation, multi-vector attacks, and comprehensive security posture
                  evaluation through realistic attack scenarios.
                </CardDescription>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Skills Section */}
      <section id="skills" className="py-20 px-4 bg-slate-800/30">
        <div className="container mx-auto">
          <h2 className="text-3xl font-bold text-white mb-12 text-center">Technical Skills</h2>
          <div className="max-w-4xl mx-auto">
            <div className="grid md:grid-cols-2 gap-8">
              <div>
                <h3 className="text-xl font-semibold text-white mb-4">Penetration Testing Tools</h3>
                <div className="flex flex-wrap gap-2 mb-6">
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Metasploit
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Burp Suite
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Nmap
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Wireshark
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Kali Linux
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    OWASP ZAP
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Cobalt Strike
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Bloodhound
                  </Badge>
                </div>

                <h3 className="text-xl font-semibold text-white mb-4">Programming Languages</h3>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Python
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Bash
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    PowerShell
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    JavaScript
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    C/C++
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    SQL
                  </Badge>
                </div>
              </div>

              <div>
                <h3 className="text-xl font-semibold text-white mb-4">Specializations</h3>
                <div className="flex flex-wrap gap-2 mb-6">
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Web App Security
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Network Security
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Active Directory
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Cloud Security
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    Mobile Security
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    API Security
                  </Badge>
                </div>

                <h3 className="text-xl font-semibold text-white mb-4">Certifications</h3>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    eCPPT v2
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    CRTA
                  </Badge>
                  <Badge variant="outline" className="border-slate-600 text-slate-300">
                    CPTS
                  </Badge>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Contact Section */}
      <section id="contact" className="py-20 px-4">
        <div className="container mx-auto">
          <div className="max-w-4xl mx-auto text-center">
            <h2 className="text-3xl font-bold text-white mb-8">Get In Touch</h2>
            <p className="text-xl text-slate-300 mb-12">
              Ready to secure your digital infrastructure? Let's discuss your security needs.
            </p>

            <div className="grid md:grid-cols-3 gap-8 mb-12">
              <div className="flex flex-col items-center">
                <Mail className="h-12 w-12 text-red-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">Email</h3>
                <p className="text-slate-300">jrbx4@osi.com</p>
              </div>
              <div className="flex flex-col items-center">
                <Phone className="h-12 w-12 text-red-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">Phone</h3>
                <p className="text-slate-300">+1 (555) 123-4567</p>
              </div>
              <div className="flex flex-col items-center">
                <MapPin className="h-12 w-12 text-red-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">Location</h3>
                <p className="text-slate-300">Remote / Global</p>
              </div>
            </div>

            <div className="flex justify-center space-x-6">
              <Link href="#" className="text-slate-400 hover:text-white transition-colors">
                <Github className="h-8 w-8" />
              </Link>
              <Link href="#" className="text-slate-400 hover:text-white transition-colors">
                <Linkedin className="h-8 w-8" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-700 bg-slate-900/50 py-8 px-4">
        <div className="container mx-auto text-center">
          <p className="text-slate-400">
            © {new Date().getFullYear()} SecureTest Pro. All rights reserved. | Ethical Hacking & Security Consulting
          </p>
        </div>
      </footer>
    </div>
  )
}
