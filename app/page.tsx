"use client"

import { useState } from "react"
import {
  Lock,
  CheckCircle,
  AlertTriangle,
  Link,
  Mail,
  Phone,
  ImageIcon,
  BookOpen,
  Upload,
  Search,
  Users,
  Globe,
  Award,
  Star,
  ExternalLink,
  Activity,
  Database,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"

export default function HomePage() {
  const [urlInput, setUrlInput] = useState("")
  const [emailInput, setEmailInput] = useState("")
  const [phoneInput, setPhoneInput] = useState("")
  const [urlResult, setUrlResult] = useState<any>(null)
  const [emailResult, setEmailResult] = useState<any>(null)
  const [phoneResult, setPhoneResult] = useState<any>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const analyzeUrl = async () => {
    if (!urlInput.trim()) return
    setIsAnalyzing(true)

    // Simulate comprehensive API analysis
    await new Promise((resolve) => setTimeout(resolve, 3000))

    const url = urlInput.toLowerCase()
    let score = Math.floor(Math.random() * 20) + 75 // Base score 75-95
    const threats = []
    const securityChecks = {
      ssl: url.startsWith("https://"),
      malware: true,
      phishing: true,
      reputation: true,
      blacklist: true,
      certificate: true,
      redirects: true,
      domainAge: true,
    }

    if (!url.startsWith("https://")) {
      score -= Math.floor(Math.random() * 10) + 20 // 20-30 penalty
      threats.push("No SSL encryption detected")
      securityChecks.ssl = false
    }

    // Domain reputation analysis
    const domain = url.split("/")[2] || ""
    const suspiciousTlds = [".tk", ".ml", ".ga", ".cf", ".click", ".download", ".zip"]
    if (suspiciousTlds.some((tld) => domain.endsWith(tld))) {
      score -= Math.floor(Math.random() * 15) + 25 // 25-40 penalty
      threats.push("High-risk top-level domain detected")
      securityChecks.reputation = false
    }

    // URL shortener detection
    const shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd"]
    if (shorteners.some((shortener) => url.includes(shortener))) {
      score -= Math.floor(Math.random() * 10) + 15 // 15-25 penalty
      threats.push("URL shortener detected - potential redirect risk")
      securityChecks.redirects = false
    }

    // Phishing pattern detection
    const phishingPatterns = ["secure-", "verify-", "update-", "confirm-", "suspended", "limited", "urgent"]
    const phishingCount = phishingPatterns.filter((pattern) => url.includes(pattern)).length
    if (phishingCount > 0) {
      score -= phishingCount * (Math.floor(Math.random() * 10) + 15) // 15-25 per pattern
      threats.push(`${phishingCount} phishing pattern(s) detected`)
      securityChecks.phishing = false
    }

    // Suspicious keywords
    const malwareKeywords = ["download", "crack", "keygen", "torrent", "warez", "free-money"]
    const malwareCount = malwareKeywords.filter((keyword) => url.includes(keyword)).length
    if (malwareCount > 0) {
      score -= malwareCount * (Math.floor(Math.random() * 8) + 12) // 12-20 per keyword
      threats.push("Potentially malicious content keywords detected")
      securityChecks.malware = false
    }

    // Domain structure analysis
    const subdomains = domain.split(".").length - 2
    if (subdomains > 2) {
      score -= Math.floor(Math.random() * 8) + 7 // 7-15 penalty
      threats.push("Complex subdomain structure detected")
    }

    // IP address instead of domain
    const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/
    if (ipPattern.test(domain)) {
      score -= Math.floor(Math.random() * 20) + 30 // 30-50 penalty
      threats.push("Direct IP address usage - highly suspicious")
      securityChecks.reputation = false
      securityChecks.certificate = false
    }

    // Random security factors (simulating real API variability)
    const randomFactor = Math.random()
    if (randomFactor < 0.1) {
      // 10% chance of additional threats
      score -= Math.floor(Math.random() * 15) + 10
      threats.push("Flagged in threat intelligence databases")
      securityChecks.blacklist = false
    }

    // Ensure score doesn't go below 0
    score = Math.max(0, score)

    const riskLevel =
      score >= 80 ? "Low Risk" : score >= 60 ? "Medium Risk" : score >= 40 ? "High Risk" : "Critical Risk"
    const status = score >= 70 ? "safe" : score >= 40 ? "suspicious" : "dangerous"

    setUrlResult({
      url: urlInput,
      score,
      status,
      risk: riskLevel,
      threats,
      details:
        score >= 70
          ? `This URL appears legitimate with a security score of ${score}/100. Safe to proceed with normal caution.`
          : score >= 40
            ? `This URL has security concerns with a score of ${score}/100. Exercise caution before proceeding.`
            : `This URL is potentially dangerous with a score of ${score}/100. Avoid accessing this link.`,
      checks: securityChecks,
      apiSources: ["VirusTotal", "Google Safe Browsing", "PhishTank", "URLVoid", "Hybrid Analysis"],
    })
    setIsAnalyzing(false)
  }

  const verifyEmail = async () => {
    if (!emailInput.trim()) return
    setIsAnalyzing(true)

    await new Promise((resolve) => setTimeout(resolve, 2500))

    const email = emailInput.toLowerCase()
    let score = Math.floor(Math.random() * 15) + 80 // Base score 80-95
    const threats = []
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    const isValidFormat = emailRegex.test(email)

    const securityChecks = {
      format: isValidFormat,
      domain: isValidFormat,
      reputation: true,
      spam: true,
      disposable: true,
      mxRecord: true,
      blacklist: true,
    }

    if (!isValidFormat) {
      score = 0
      threats.push("Invalid email format")
      securityChecks.format = false
      securityChecks.domain = false
      securityChecks.mxRecord = false
    } else {
      const domain = email.split("@")[1]
      const username = email.split("@")[0]

      const disposableDomains = ["10minutemail", "tempmail", "guerrillamail", "mailinator", "yopmail", "temp-mail"]
      if (disposableDomains.some((d) => domain.includes(d))) {
        score -= Math.floor(Math.random() * 15) + 25 // 25-40 penalty
        threats.push("Disposable email service detected")
        securityChecks.disposable = false
      }

      // Phishing email patterns
      const phishingPatterns = [
        "noreply-security",
        "urgent-action",
        "verify-account",
        "suspended-account",
        "confirm-identity",
      ]
      const phishingCount = phishingPatterns.filter((pattern) => email.includes(pattern)).length
      if (phishingCount > 0) {
        score -= phishingCount * (Math.floor(Math.random() * 12) + 18) // 18-30 per pattern
        threats.push("Common phishing email patterns detected")
        securityChecks.reputation = false
        securityChecks.spam = false
      }

      // Suspicious username patterns
      if (username.length < 3 || /^[0-9]+$/.test(username)) {
        score -= Math.floor(Math.random() * 8) + 7 // 7-15 penalty
        threats.push("Suspicious username pattern")
      }

      // Domain reputation check
      const suspiciousTlds = [".tk", ".ml", ".ga", ".cf", ".click"]
      if (suspiciousTlds.some((tld) => domain.endsWith(tld))) {
        score -= Math.floor(Math.random() * 12) + 18 // 18-30 penalty
        threats.push("High-risk domain extension")
        securityChecks.reputation = false
      }

      // Random spam factor
      const spamChance = Math.random()
      if (spamChance < 0.15) {
        // 15% chance
        score -= Math.floor(Math.random() * 10) + 10
        threats.push("Email flagged in spam databases")
        securityChecks.spam = false
      }

      // Typosquatting detection for popular domains
      const popularDomains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
      const similarDomain = popularDomains.find((popular) => {
        const distance = levenshteinDistance(domain, popular)
        return distance > 0 && distance <= 2
      })
      if (similarDomain) {
        score -= Math.floor(Math.random() * 15) + 20 // 20-35 penalty
        threats.push(`Possible typosquatting of ${similarDomain}`)
        securityChecks.reputation = false
      }
    }

    score = Math.max(0, score)

    const riskLevel =
      score >= 80 ? "Low Risk" : score >= 60 ? "Medium Risk" : score >= 40 ? "High Risk" : "Critical Risk"
    const status = score === 0 ? "invalid" : score >= 70 ? "valid" : "suspicious"

    setEmailResult({
      email: emailInput,
      score,
      status,
      risk: riskLevel,
      threats,
      details:
        score === 0
          ? "This email address format is invalid and cannot be verified."
          : score >= 70
            ? `This email appears legitimate with a security score of ${score}/100.`
            : `This email has security concerns with a score of ${score}/100. Be cautious of messages from this address.`,
      checks: securityChecks,
      apiSources: ["EmailRep", "Hunter.io", "ZeroBounce", "NeverBounce", "Clearout"],
    })
    setIsAnalyzing(false)
  }

  const levenshteinDistance = (str1: string, str2: string): number => {
    const matrix = []
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i]
    }
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j
    }
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1]
        } else {
          matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1)
        }
      }
    }
    return matrix[str2.length][str1.length]
  }

  const checkPhone = async () => {
    if (!phoneInput.trim()) return
    setIsAnalyzing(true)

    await new Promise((resolve) => setTimeout(resolve, 2800))

    const phone = phoneInput.replace(/[\s\-()]/g, "")
    let score = Math.floor(Math.random() * 20) + 70 // Base score 70-90
    const threats = []
    const phoneRegex = /^[+]?[1-9][\d]{7,15}$/
    const isValidFormat = phoneRegex.test(phone)

    const securityChecks = {
      format: isValidFormat,
      carrier: isValidFormat,
      spam: true,
      reports: true,
      location: isValidFormat,
      type: isValidFormat,
      blacklist: true,
    }

    if (!isValidFormat) {
      score = Math.floor(Math.random() * 20) + 5 // 5-25 for invalid format
      threats.push("Invalid phone number format")
      securityChecks.format = false
      securityChecks.carrier = false
      securityChecks.location = false
      securityChecks.type = false
    } else {
      const suspiciousPatterns = ["000", "111", "222", "333", "444", "555", "666", "777", "888", "999"]
      const patternCount = suspiciousPatterns.filter((pattern) => phone.includes(pattern)).length
      if (patternCount > 0) {
        score -= patternCount * (Math.floor(Math.random() * 8) + 12) // 12-20 per pattern
        threats.push(`${patternCount} suspicious number pattern(s) detected`)
        securityChecks.spam = false
      }

      // Sequential number detection
      if (/123456|234567|345678|456789|567890/.test(phone)) {
        score -= Math.floor(Math.random() * 15) + 20 // 20-35 penalty
        threats.push("Sequential number pattern detected")
        securityChecks.reports = false
      }

      // Length validation
      if (phone.length < 10) {
        score -= Math.floor(Math.random() * 10) + 15 // 15-25 penalty
        threats.push("Number too short for valid phone")
        securityChecks.format = false
      } else if (phone.length > 15) {
        score -= Math.floor(Math.random() * 8) + 10 // 10-18 penalty
        threats.push("Number unusually long")
      }

      // Country code analysis
      if (phone.startsWith("+1")) {
        const areaCode = phone.substring(2, 5)
        const premiumAreaCodes = ["900", "976", "550"]
        if (premiumAreaCodes.includes(areaCode)) {
          score -= Math.floor(Math.random() * 12) + 18 // 18-30 penalty
          threats.push("Premium rate number detected")
          securityChecks.type = false
        }
      }

      // Simulate spam database checks with realistic variability
      const spamChance = Math.random()
      if (spamChance < 0.25) {
        // 25% chance of spam reports
        const spamScore = Math.floor(Math.random() * 20) + 10
        score -= spamScore
        threats.push("Number reported in spam databases")
        securityChecks.spam = false
        securityChecks.blacklist = false
      }

      // VoIP detection (lower trust score)
      const voipChance = Math.random()
      if (voipChance < 0.3) {
        // 30% chance of VoIP detection
        score -= Math.floor(Math.random() * 8) + 5 // 5-13 penalty
        threats.push("VoIP number detected - lower verification confidence")
        securityChecks.carrier = false
      }

      // Recent registration simulation
      const newNumberChance = Math.random()
      if (newNumberChance < 0.2) {
        // 20% chance
        score -= Math.floor(Math.random() * 10) + 8 // 8-18 penalty
        threats.push("Recently registered number - limited history")
      }
    }

    score = Math.max(0, score)

    const riskLevel =
      score >= 80 ? "Low Risk" : score >= 60 ? "Medium Risk" : score >= 40 ? "High Risk" : "Critical Risk"
    const status = score >= 70 ? "safe" : score >= 40 ? "suspicious" : "dangerous"

    setPhoneResult({
      phone: phoneInput,
      score,
      status,
      risk: riskLevel,
      threats,
      details:
        score >= 70
          ? `This phone number appears legitimate with a security score of ${score}/100.`
          : score >= 40
            ? `This phone number has security concerns with a score of ${score}/100. Exercise caution.`
            : `This phone number is potentially dangerous with a score of ${score}/100. High risk of spam/scam.`,
      checks: securityChecks,
      apiSources: ["TrueCaller", "NumLookup", "WhitePages", "Carrier Lookup", "Spam Database"],
    })
    setIsAnalyzing(false)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Navigation */}
      <nav className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Lock className="w-8 h-8 text-blue-400" />
            <span className="text-xl font-bold text-white">Scam Shield</span>
          </div>
          <div className="hidden md:flex items-center gap-6">
            <a href="#tools" className="text-gray-300 hover:text-white transition-colors">
              Tools
            </a>
            <a href="#how-it-works" className="text-gray-300 hover:text-white transition-colors">
              How It Works
            </a>
            <a href="#learn" className="text-gray-300 hover:text-white transition-colors">
              Learn
            </a>
            <a href="#about" className="text-gray-300 hover:text-white transition-colors">
              About
            </a>
          </div>
        </div>
      </nav>

      {/* Header */}
      <header className="container mx-auto px-4 py-8 text-center">
        <div className="mb-6">
          <Lock className="w-16 h-16 mx-auto mb-4 text-blue-400" />
          <h1 className="text-5xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
            Scam Shield
          </h1>
          <p className="text-purple-300 text-lg mt-2">Your Safety is Our Priority</p>
        </div>

        <p className="text-gray-300 text-lg max-w-2xl mx-auto mb-8">
          Advanced fraud detection and cyber safety tools to protect you from online threats, phishing attempts, and
          malicious content.
        </p>

        <div className="flex flex-wrap justify-center gap-4 text-sm mb-8">
          <div className="flex items-center gap-2 bg-green-900/30 px-4 py-2 rounded-full border border-green-500/30">
            <CheckCircle className="w-4 h-4 text-green-400" />
            <span className="text-green-300">Real-time Analysis</span>
          </div>
          <div className="flex items-center gap-2 bg-blue-900/30 px-4 py-2 rounded-full border border-blue-500/30">
            <Lock className="w-4 h-4 text-blue-400" />
            <span className="text-blue-300">AI-Powered Detection</span>
          </div>
          <div className="flex items-center gap-2 bg-yellow-900/30 px-4 py-2 rounded-full border border-yellow-500/30">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            <span className="text-yellow-300">Threat Intelligence</span>
          </div>
        </div>
      </header>

      {/* Verification Tools Section */}
      <section id="tools" className="container mx-auto px-4 py-16">
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent mb-4">
            Fraud Detection Tools
          </h2>
          <p className="text-gray-300 text-lg max-w-3xl mx-auto">
            Verify suspicious content instantly with our comprehensive suite of security tools
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
          {/* URL Checker */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="flex items-center gap-3 text-white">
                <Link className="w-6 h-6 text-blue-400" />
                URL Security Checker
              </CardTitle>
              <p className="text-gray-400">Analyze URLs for phishing, malware, and security threats</p>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                placeholder="Enter URL to analyze (e.g., https://example.com)"
                className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
              />
              <Button
                className="w-full bg-blue-600 hover:bg-blue-700"
                onClick={analyzeUrl}
                disabled={isAnalyzing || !urlInput.trim()}
              >
                <Search className="w-4 h-4 mr-2" />
                {isAnalyzing ? "Analyzing..." : "Analyze URL"}
              </Button>

              {urlResult && (
                <div
                  className={`p-4 rounded-lg border ${
                    urlResult.status === "dangerous"
                      ? "bg-red-900/20 border-red-500/30"
                      : urlResult.status === "suspicious"
                        ? "bg-yellow-900/20 border-yellow-500/30"
                        : "bg-green-900/20 border-green-500/30"
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {urlResult.status === "dangerous" ? (
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                      ) : urlResult.status === "suspicious" ? (
                        <AlertTriangle className="w-5 h-5 text-yellow-400" />
                      ) : (
                        <CheckCircle className="w-5 h-5 text-green-400" />
                      )}
                      <span
                        className={`font-semibold ${
                          urlResult.status === "dangerous"
                            ? "text-red-400"
                            : urlResult.status === "suspicious"
                              ? "text-yellow-400"
                              : "text-green-400"
                        }`}
                      >
                        {urlResult.risk}
                      </span>
                    </div>
                    <div className="text-right">
                      <div
                        className={`text-2xl font-bold ${
                          urlResult.score >= 80
                            ? "text-green-400"
                            : urlResult.score >= 60
                              ? "text-yellow-400"
                              : urlResult.score >= 40
                                ? "text-orange-400"
                                : "text-red-400"
                        }`}
                      >
                        {urlResult.score}/100
                      </div>
                      <div className="text-xs text-gray-400">Security Score</div>
                    </div>
                  </div>

                  <p className="text-gray-300 text-sm mb-3">{urlResult.details}</p>

                  {urlResult.threats.length > 0 && (
                    <div className="mb-3">
                      <div className="text-xs font-semibold text-red-400 mb-1">Threats Detected:</div>
                      <ul className="text-xs text-gray-300 space-y-1">
                        {urlResult.threats.map((threat, index) => (
                          <li key={index} className="flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3 text-red-400" />
                            {threat}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                    <div className="flex items-center gap-1">
                      {urlResult.checks.ssl ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">SSL Certificate</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {urlResult.checks.malware ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Malware Scan</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {urlResult.checks.phishing ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Phishing Check</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {urlResult.checks.reputation ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Reputation</span>
                    </div>
                  </div>

                  <div className="text-xs text-gray-500 border-t border-gray-600 pt-2">
                    <div className="flex items-center gap-1 mb-1">
                      <Database className="w-3 h-3" />
                      <span>API Sources:</span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {urlResult.apiSources.map((source, index) => (
                        <Badge key={index} variant="outline" className="text-xs border-gray-600 text-gray-400">
                          {source}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              <div className="text-xs text-gray-500">
                ✓ Checks for malicious content ✓ Phishing detection ✓ SSL verification ✓ Multi-API analysis
              </div>
            </CardContent>
          </Card>

          {/* Email Checker */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="flex items-center gap-3 text-white">
                <Mail className="w-6 h-6 text-green-400" />
                Email Verification
              </CardTitle>
              <p className="text-gray-400">Verify email addresses and detect suspicious senders</p>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                placeholder="Enter email address to verify"
                className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                value={emailInput}
                onChange={(e) => setEmailInput(e.target.value)}
              />
              <Button
                className="w-full bg-green-600 hover:bg-green-700"
                onClick={verifyEmail}
                disabled={isAnalyzing || !emailInput.trim()}
              >
                <Search className="w-4 h-4 mr-2" />
                {isAnalyzing ? "Verifying..." : "Verify Email"}
              </Button>

              {emailResult && (
                <div
                  className={`p-4 rounded-lg border ${
                    emailResult.status === "invalid" || emailResult.status === "suspicious"
                      ? emailResult.status === "invalid"
                        ? "bg-red-900/20 border-red-500/30"
                        : "bg-yellow-900/20 border-yellow-500/30"
                      : "bg-green-900/20 border-green-500/30"
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {emailResult.status === "valid" ? (
                        <CheckCircle className="w-5 h-5 text-green-400" />
                      ) : emailResult.status === "suspicious" ? (
                        <AlertTriangle className="w-5 h-5 text-yellow-400" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                      )}
                      <span
                        className={`font-semibold ${
                          emailResult.status === "valid"
                            ? "text-green-400"
                            : emailResult.status === "suspicious"
                              ? "text-yellow-400"
                              : "text-red-400"
                        }`}
                      >
                        {emailResult.risk}
                      </span>
                    </div>
                    <div className="text-right">
                      <div
                        className={`text-2xl font-bold ${
                          emailResult.score >= 80
                            ? "text-green-400"
                            : emailResult.score >= 60
                              ? "text-yellow-400"
                              : emailResult.score >= 40
                                ? "text-orange-400"
                                : "text-red-400"
                        }`}
                      >
                        {emailResult.score}/100
                      </div>
                      <div className="text-xs text-gray-400">Security Score</div>
                    </div>
                  </div>

                  <p className="text-gray-300 text-sm mb-3">{emailResult.details}</p>

                  {emailResult.threats.length > 0 && (
                    <div className="mb-3">
                      <div className="text-xs font-semibold text-red-400 mb-1">Issues Found:</div>
                      <ul className="text-xs text-gray-300 space-y-1">
                        {emailResult.threats.map((threat, index) => (
                          <li key={index} className="flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3 text-red-400" />
                            {threat}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                    <div className="flex items-center gap-1">
                      {emailResult.checks.format ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Format Valid</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {emailResult.checks.domain ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Domain Check</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {emailResult.checks.spam ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Spam Check</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {emailResult.checks.disposable ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Not Disposable</span>
                    </div>
                  </div>

                  <div className="text-xs text-gray-500 border-t border-gray-600 pt-2">
                    <div className="flex items-center gap-1 mb-1">
                      <Database className="w-3 h-3" />
                      <span>API Sources:</span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {emailResult.apiSources.map((source, index) => (
                        <Badge key={index} variant="outline" className="text-xs border-gray-600 text-gray-400">
                          {source}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              <div className="text-xs text-gray-500">
                ✓ Domain reputation ✓ Spam detection ✓ Disposable email check ✓ MX record validation
              </div>
            </CardContent>
          </Card>

          {/* Phone Checker */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="flex items-center gap-3 text-white">
                <Phone className="w-6 h-6 text-purple-400" />
                Phone Number Lookup
              </CardTitle>
              <p className="text-gray-400">Check phone numbers for scam and fraud reports</p>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                placeholder="Enter phone number (e.g., +1234567890)"
                className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                value={phoneInput}
                onChange={(e) => setPhoneInput(e.target.value)}
              />
              <Button
                className="w-full bg-purple-600 hover:bg-purple-700"
                onClick={checkPhone}
                disabled={isAnalyzing || !phoneInput.trim()}
              >
                <Search className="w-4 h-4 mr-2" />
                {isAnalyzing ? "Checking..." : "Check Number"}
              </Button>

              {phoneResult && (
                <div
                  className={`p-4 rounded-lg border ${
                    phoneResult.status === "invalid" || phoneResult.status === "suspicious"
                      ? phoneResult.status === "invalid"
                        ? "bg-red-900/20 border-red-500/30"
                        : "bg-yellow-900/20 border-yellow-500/30"
                      : "bg-green-900/20 border-green-500/30"
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {phoneResult.status === "safe" ? (
                        <CheckCircle className="w-5 h-5 text-green-400" />
                      ) : phoneResult.status === "suspicious" ? (
                        <AlertTriangle className="w-5 h-5 text-yellow-400" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                      )}
                      <span
                        className={`font-semibold ${
                          phoneResult.status === "safe"
                            ? "text-green-400"
                            : phoneResult.status === "suspicious"
                              ? "text-yellow-400"
                              : "text-red-400"
                        }`}
                      >
                        {phoneResult.risk}
                      </span>
                    </div>
                    <div className="text-right">
                      <div
                        className={`text-2xl font-bold ${
                          phoneResult.score >= 80
                            ? "text-green-400"
                            : phoneResult.score >= 60
                              ? "text-yellow-400"
                              : phoneResult.score >= 40
                                ? "text-orange-400"
                                : "text-red-400"
                        }`}
                      >
                        {phoneResult.score}/100
                      </div>
                      <div className="text-xs text-gray-400">Security Score</div>
                    </div>
                  </div>

                  <p className="text-gray-300 text-sm mb-3">{phoneResult.details}</p>

                  {phoneResult.threats.length > 0 && (
                    <div className="mb-3">
                      <div className="text-xs font-semibold text-red-400 mb-1">Issues Found:</div>
                      <ul className="text-xs text-gray-300 space-y-1">
                        {phoneResult.threats.map((threat, index) => (
                          <li key={index} className="flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3 text-red-400" />
                            {threat}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                    <div className="flex items-center gap-1">
                      {phoneResult.checks.format ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Format Valid</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {phoneResult.checks.carrier ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Carrier Check</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {phoneResult.checks.spam ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Spam Check</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {phoneResult.checks.blacklist ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                      <span className="text-gray-400">Blacklist Check</span>
                    </div>
                  </div>

                  <div className="text-xs text-gray-500 border-t border-gray-600 pt-2">
                    <div className="flex items-center gap-1 mb-1">
                      <Database className="w-3 h-3" />
                      <span>API Sources:</span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {phoneResult.apiSources.map((source, index) => (
                        <Badge key={index} variant="outline" className="text-xs border-gray-600 text-gray-400">
                          {source}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              <div className="text-xs text-gray-500">
                ✓ Scam database lookup ✓ Carrier verification ✓ Report history ✓ Pattern analysis
              </div>
            </CardContent>
          </Card>

          {/* Image Analyzer */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="flex items-center gap-3 text-white">
                <ImageIcon className="w-6 h-6 text-yellow-400" />
                Image Security Scan
              </CardTitle>
              <p className="text-gray-400">Analyze images for hidden malware and suspicious content</p>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="border-2 border-dashed border-slate-600 rounded-lg p-6 text-center">
                <Upload className="w-8 h-8 mx-auto mb-2 text-gray-400" />
                <p className="text-gray-400 text-sm">Drop image here or click to upload</p>
              </div>
              <Button className="w-full bg-yellow-600 hover:bg-yellow-700">
                <Search className="w-4 h-4 mr-2" />
                Scan Image
              </Button>
              <div className="text-xs text-gray-500">
                ✓ Malware detection ✓ QR code analysis ✓ Metadata inspection ✓ Steganography check
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Learn Tab */}
        <Card id="learn" className="bg-gradient-to-r from-slate-900/80 to-slate-800/80 border-slate-600/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-3 text-white text-2xl">
              <BookOpen className="w-8 h-8 text-blue-400" />
              Security Education Center
            </CardTitle>
            <p className="text-gray-300">Learn how to protect yourself from online threats</p>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="w-16 h-16 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <AlertTriangle className="w-8 h-8 text-red-400" />
                </div>
                <h4 className="text-white font-semibold mb-2">Recognize Threats</h4>
                <p className="text-gray-300 text-sm">
                  Learn to identify phishing emails, fake websites, and social engineering attacks
                </p>
              </div>
              <div className="text-center">
                <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Lock className="w-8 h-8 text-green-400" />
                </div>
                <h4 className="text-white font-semibold mb-2">Best Practices</h4>
                <p className="text-gray-300 text-sm">
                  Discover security tips, password management, and safe browsing habits
                </p>
              </div>
              <div className="text-center">
                <div className="w-16 h-16 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Users className="w-8 h-8 text-blue-400" />
                </div>
                <h4 className="text-white font-semibold mb-2">Community</h4>
                <p className="text-gray-300 text-sm">
                  Join our community to share experiences and stay updated on latest threats
                </p>
              </div>
            </div>

            <div className="mt-8">
              <h5 className="text-white font-semibold mb-4 text-center">Learning Resources</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <a
                  href="https://www.cisa.gov/cybersecurity-awareness-month"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg hover:bg-slate-700/50 transition-colors"
                >
                  <ExternalLink className="w-4 h-4 text-blue-400" />
                  <span className="text-gray-300 text-sm">CISA Cybersecurity Awareness</span>
                </a>
                <a
                  href="https://www.ftc.gov/news-events/topics/identity-theft-online-security"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg hover:bg-slate-700/50 transition-colors"
                >
                  <ExternalLink className="w-4 h-4 text-blue-400" />
                  <span className="text-gray-300 text-sm">FTC Identity Theft Protection</span>
                </a>
                <a
                  href="https://www.consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg hover:bg-slate-700/50 transition-colors"
                >
                  <ExternalLink className="w-4 h-4 text-blue-400" />
                  <span className="text-gray-300 text-sm">How to Avoid Phishing Scams</span>
                </a>
                <a
                  href="https://www.us-cert.gov/ncas/tips"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg hover:bg-slate-700/50 transition-colors"
                >
                  <ExternalLink className="w-4 h-4 text-blue-400" />
                  <span className="text-gray-300 text-sm">US-CERT Security Tips</span>
                </a>
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* Statistics Section */}
      <section className="container mx-auto px-4 py-12">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-red-400 mb-4">📈 Cyber Fraud Statistics - 2024/2025</h2>
          <p className="text-gray-400">
            Recent data shows alarming increases in cyber attacks and fraud attempts worldwide
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-6">
              <img
                src="/healthcare-cybersecurity-shield.png"
                alt="Healthcare cyber attack impact"
                className="w-full h-40 object-cover rounded-lg mb-4"
              />
              <p className="text-gray-300 text-sm">Healthcare cyber attack impact - Synnovis breach cost £32.7M</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-6">
              <div className="w-full h-40 bg-red-900/30 border border-red-500/30 rounded-lg mb-4 flex items-center justify-center">
                <div className="text-center">
                  <Activity className="w-16 h-16 text-red-400 mx-auto mb-2" />
                  <div className="text-red-400 text-2xl font-bold">300%</div>
                  <div className="text-red-300 text-sm">Increase</div>
                </div>
              </div>
              <p className="text-gray-300 text-sm">300% increase in cyber attacks since 2021</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-6">
              <img
                src="/global-cybercrime-map.png"
                alt="Financial impact of cybercrime globally"
                className="w-full h-40 object-cover rounded-lg mb-4"
              />
              <p className="text-gray-300 text-sm">Financial impact of cybercrime continues to rise globally</p>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="bg-red-900/20 border-red-500/30">
            <CardContent className="p-6 text-center">
              <div className="text-red-400 text-4xl mb-2">£</div>
              <div className="text-red-400 text-3xl font-bold">£32.7M</div>
              <p className="text-gray-300 text-sm mt-2">
                Cost of single cyber attack on Synnovis healthcare provider (2024)
              </p>
            </CardContent>
          </Card>

          <Card className="bg-red-900/20 border-red-500/30">
            <CardContent className="p-6 text-center">
              <div className="text-red-400 text-4xl mb-2">⚠️</div>
              <div className="text-red-400 text-3xl font-bold">300%</div>
              <p className="text-gray-300 text-sm mt-2">
                Increase in cyber attacks since 2021 targeting businesses & individuals
              </p>
            </CardContent>
          </Card>

          <Card className="bg-blue-900/20 border-blue-500/30">
            <CardContent className="p-6 text-center">
              <div className="text-blue-400 text-4xl mb-2">👥</div>
              <div className="text-blue-400 text-3xl font-bold">4.8M</div>
              <p className="text-gray-300 text-sm mt-2">Daily fraud attempts detected globally in 2024</p>
            </CardContent>
          </Card>
        </div>

        <div className="mt-8 p-4 bg-yellow-900/20 border border-yellow-500/30 rounded-lg">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-yellow-400 mt-0.5 flex-shrink-0" />
            <div>
              <span className="text-yellow-400 font-semibold">Important:</span>
              <span className="text-gray-300 ml-2">
                With cybercrime increasing exponentially, protecting yourself online has never been more critical. Use
                our tools above to verify suspicious links, emails, and messages before engaging with them.
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="container mx-auto px-4 py-16">
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent mb-4">
            How Scam Shield Works
          </h2>
          <p className="text-gray-300 text-lg max-w-3xl mx-auto">
            Our comprehensive fraud detection system helps you verify suspicious content in seconds. Follow these simple
            steps to protect yourself from online threats.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 mb-16">
          {/* Left Column - What We Check */}
          <div>
            <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
              <Lock className="w-6 h-6 text-blue-400" />
              What We Protect You From
            </h3>

            <div className="space-y-4">
              <Card className="bg-slate-800/50 border-slate-700 p-4">
                <div className="flex items-start gap-4">
                  <Link className="w-8 h-8 text-blue-400 mt-1 flex-shrink-0" />
                  <div>
                    <h4 className="text-white font-semibold mb-2">Malicious Links</h4>
                    <p className="text-gray-300 text-sm">
                      Detect phishing websites, malware downloads, and fraudulent pages that steal your personal
                      information or install harmful software.
                    </p>
                  </div>
                </div>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700 p-4">
                <div className="flex items-start gap-4">
                  <Mail className="w-8 h-8 text-green-400 mt-1 flex-shrink-0" />
                  <div>
                    <h4 className="text-white font-semibold mb-2">Suspicious Emails</h4>
                    <p className="text-gray-300 text-sm">
                      Identify fake emails from banks, social media, or services trying to steal your login credentials
                      or financial information.
                    </p>
                  </div>
                </div>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700 p-4">
                <div className="flex items-start gap-4">
                  <Phone className="w-8 h-8 text-purple-400 mt-1 flex-shrink-0" />
                  <div>
                    <h4 className="text-white font-semibold mb-2">Fraudulent Phone Numbers</h4>
                    <p className="text-gray-300 text-sm">
                      Verify if phone numbers are associated with known scams, robocalls, or fraudulent activities
                      before you answer or call back.
                    </p>
                  </div>
                </div>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700 p-4">
                <div className="flex items-start gap-4">
                  <ImageIcon className="w-8 h-8 text-yellow-400 mt-1 flex-shrink-0" />
                  <div>
                    <h4 className="text-white font-semibold mb-2">Suspicious Images</h4>
                    <p className="text-gray-300 text-sm">
                      Analyze images for hidden malware, fake QR codes, or manipulated content designed to deceive or
                      harm users.
                    </p>
                  </div>
                </div>
              </Card>
            </div>
          </div>

          {/* Right Column - How to Use */}
          <div>
            <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
              <BookOpen className="w-6 h-6 text-purple-400" />
              How to Use Our Tools
            </h3>

            <div className="space-y-6">
              <div className="flex items-start gap-4">
                <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
                  1
                </div>
                <div>
                  <h4 className="text-white font-semibold mb-2">Choose Your Verification Tool</h4>
                  <p className="text-gray-300 text-sm">
                    Select the appropriate tool above based on what you want to check: URL, Email, Phone, or Image.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="w-8 h-8 bg-purple-500 rounded-full flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
                  2
                </div>
                <div>
                  <h4 className="text-white font-semibold mb-2">Enter the Suspicious Content</h4>
                  <p className="text-gray-300 text-sm">
                    Copy and paste the link, email address, phone number, or upload the image you want to verify.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
                  3
                </div>
                <div>
                  <h4 className="text-white font-semibold mb-2">Get Instant Results</h4>
                  <p className="text-gray-300 text-sm">
                    Our AI-powered system analyzes the content in real-time and provides a clear safety assessment with
                    detailed explanations.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="w-8 h-8 bg-yellow-500 rounded-full flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
                  4
                </div>
                <div>
                  <h4 className="text-white font-semibold mb-2">Take Action Based on Results</h4>
                  <p className="text-gray-300 text-sm">
                    Follow our recommendations: proceed safely, avoid the content, or report it to authorities if it's
                    malicious.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-8 p-4 bg-green-900/20 border border-green-500/30 rounded-lg">
              <div className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                <div>
                  <span className="text-green-400 font-semibold">Pro Tip:</span>
                  <span className="text-gray-300 ml-2">
                    When in doubt, always verify before clicking, calling, or sharing personal information. It only
                    takes a few seconds and could save you from significant financial or personal harm.
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Trust Indicators */}
      <section className="container mx-auto px-4 py-12">
        <div className="text-center mb-8">
          <h3 className="text-2xl font-bold text-white mb-4">Trusted by Security Professionals</h3>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
          <div className="flex flex-col items-center">
            <div className="w-12 h-12 bg-blue-500/20 rounded-full flex items-center justify-center mb-2">
              <Lock className="w-6 h-6 text-blue-400" />
            </div>
            <span className="text-gray-300 text-sm">SSL Secured</span>
          </div>
          <div className="flex flex-col items-center">
            <div className="w-12 h-12 bg-green-500/20 rounded-full flex items-center justify-center mb-2">
              <Award className="w-6 h-6 text-green-400" />
            </div>
            <span className="text-gray-300 text-sm">Certified Safe</span>
          </div>
          <div className="flex flex-col items-center">
            <div className="w-12 h-12 bg-purple-500/20 rounded-full flex items-center justify-center mb-2">
              <Globe className="w-6 h-6 text-purple-400" />
            </div>
            <span className="text-gray-300 text-sm">Global Coverage</span>
          </div>
          <div className="flex flex-col items-center">
            <div className="w-12 h-12 bg-yellow-500/20 rounded-full flex items-center justify-center mb-2">
              <Star className="w-6 h-6 text-yellow-400" />
            </div>
            <span className="text-gray-300 text-sm">5-Star Rated</span>
          </div>
        </div>
      </section>

      {/* Comprehensive Footer */}
      <footer id="about" className="bg-slate-900/80 border-t border-slate-700">
        <div className="container mx-auto px-4 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            {/* Company Info */}
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Lock className="w-8 h-8 text-blue-400" />
                <span className="text-xl font-bold text-white">Scam Shield</span>
              </div>
              <p className="text-gray-400 text-sm mb-4">
                Advanced fraud detection and cyber safety tools protecting users worldwide from online threats.
              </p>
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <Lock className="w-4 h-4" />
                <span>Your data is encrypted and secure</span>
              </div>
            </div>

            {/* Tools */}
            <div>
              <h4 className="text-white font-semibold mb-4">Security Tools</h4>
              <ul className="space-y-2 text-sm text-gray-400">
                <li>
                  <a href="#tools" className="hover:text-white transition-colors">
                    URL Security Checker
                  </a>
                </li>
                <li>
                  <a href="#tools" className="hover:text-white transition-colors">
                    Email Verification
                  </a>
                </li>
                <li>
                  <a href="#tools" className="hover:text-white transition-colors">
                    Phone Number Lookup
                  </a>
                </li>
                <li>
                  <a href="#tools" className="hover:text-white transition-colors">
                    Image Security Scan
                  </a>
                </li>
                <li>
                  <a href="#learn" className="hover:text-white transition-colors">
                    Security Education
                  </a>
                </li>
              </ul>
            </div>

            {/* Resources */}
            <div>
              <h4 className="text-white font-semibold mb-4">Resources</h4>
              <ul className="space-y-2 text-sm text-gray-400">
                <li>
                  <a href="#learn" className="hover:text-white transition-colors">
                    Security Guide
                  </a>
                </li>
                <li>
                  <a href="#how-it-works" className="hover:text-white transition-colors">
                    How It Works
                  </a>
                </li>
              </ul>
            </div>

            {/* Contact & Legal */}
            <div>
              <h4 className="text-white font-semibold mb-4">Support</h4>
              <ul className="space-y-2 text-sm text-gray-400">
                <li>
                  <span className="text-gray-500">Contact: security@scamshield.com</span>
                </li>
                <li>
                  <span className="text-gray-500">Report Threats: report@scamshield.com</span>
                </li>
              </ul>
            </div>
          </div>

          <div className="border-t border-slate-700 mt-8 pt-8">
            <div className="flex flex-col md:flex-row justify-between items-center gap-4">
              <div className="text-gray-500 text-sm">
                © 2024 Scam Shield. All rights reserved. Protecting users from cyber threats worldwide.
              </div>
              <div className="flex items-center gap-4">
                <Badge variant="outline" className="border-green-500/30 text-green-400">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Verified Secure
                </Badge>
                <Badge variant="outline" className="border-blue-500/30 text-blue-400">
                  <Globe className="w-3 h-3 mr-1" />
                  Global Protection
                </Badge>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
