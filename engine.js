/**
 * Sentinel AI — Digital Trust Inspector
 * Heuristic Detection & Risk Assessment Engine (engine.js)
 * 
 * Production-grade deterministic analysis engine.
 * Computes Trust DNA 2.0 vector indices, performs structural URL decomposition,
 * derives composite risk scores, and generates explainable forensic findings.
 */

class SentinelEngine {
    constructor(rules = window.THREAT_RULES) {
        this.rules = rules;
        this.version = "Sentinel Heuristics Engine v2.5 (Enterprise Deterministic)";
    }

    /**
     * Extracts full URLs found within arbitrary text.
     */
    extractUrls(text) {
        const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+)/gi;
        const matches = text.match(urlRegex);
        return matches ? Array.from(new Set(matches)) : [];
    }

    /**
     * Validates and parses a URL safely without navigating.
     */
    parseUrl(urlString) {
        try {
            if (!urlString || typeof urlString !== "string") {
                return { valid: false, error: "Empty or invalid URL string." };
            }

            let normalized = urlString.trim();

            // Check if string contains spaces
            if (/\s/.test(normalized)) {
                return { valid: false, error: "URL contains spaces which are invalid in a web address." };
            }

            // If missing scheme, prepend https:// for syntax inspection
            let schemePrepended = false;
            if (!/^https?:\/\//i.test(normalized)) {
                normalized = "https://" + normalized;
                schemePrepended = true;
            }

            const parsed = new URL(normalized);

            // Hostname must contain at least a valid domain or IP
            if (!parsed.hostname || parsed.hostname.length < 3 || !parsed.hostname.includes(".")) {
                return { valid: false, error: "URL is missing a valid hostname or registered domain name." };
            }

            return { 
                valid: true, 
                urlObj: parsed, 
                raw: urlString.trim(),
                schemePrepended
            };
        } catch (e) {
            return { valid: false, error: e.message || "Malformed URL syntax." };
        }
    }

    /**
     * Deconstructs a URL into an in-depth structural inspection object.
     */
    deconstructUrl(urlObj, rawString) {
        const hostname = urlObj.hostname.toLowerCase();
        const parts = hostname.split(".");
        const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
        
        let tld = "";
        let domainRoot = hostname;
        let subdomains = [];

        if (!isIp && parts.length >= 2) {
            tld = parts[parts.length - 1];
            domainRoot = parts.slice(-2).join(".");
            subdomains = parts.slice(0, -2);
        }

        const shortenerList = [
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly",
            "cutt.ly", "shorturl.at", "rebrand.ly", "tiny.cc",
            "rb.gy", "bl.ink", "lnkd.in"
        ];
        const isShortener = shortenerList.includes(hostname);

        const suspiciousTLDList = [
            "xyz", "top", "click", "work", "link", "club", "surf",
            "monster", "loan", "stream", "cam", "kim", "vip", "gq",
            "cf", "ml", "tk", "ga", "fit", "buzz"
        ];
        const isSuspiciousTLD = suspiciousTLDList.includes(tld);

        const brands = ["paypal", "chase", "wells-fargo", "apple", "microsoft", "google", "netflix", "amazon", "dhl", "usps", "bankofamerica"];
        let spoofedBrandFound = null;
        if (subdomains.length > 0) {
            const subStr = subdomains.join(".");
            for (const b of brands) {
                if (subStr.includes(b) && !domainRoot.includes(b)) {
                    spoofedBrandFound = b;
                    break;
                }
            }
        }

        const isPunycode = hostname.startsWith("xn--") || hostname.includes(".xn--");
        const hasUserInfo = rawString.includes("@") || (urlObj.username && urlObj.username.length > 0);
        const hasSuspiciousExt = [".exe", ".scr", ".bat", ".vbs", ".cmd", ".msi", ".apk", ".ps1", ".hta", ".zip", ".iso"].some(ext => urlObj.pathname.toLowerCase().endsWith(ext));

        return {
            rawUrl: rawString,
            protocol: urlObj.protocol,
            isHttps: urlObj.protocol === "https:",
            hostname: hostname,
            domainRoot: domainRoot,
            subdomains: subdomains,
            subdomainCount: subdomains.length,
            tld: tld ? "." + tld : "N/A",
            isIpAddress: isIp,
            isShortener: isShortener,
            isSuspiciousTLD: isSuspiciousTLD,
            spoofedBrand: spoofedBrandFound,
            isPunycode: isPunycode,
            hasUserInfo: hasUserInfo,
            hasSuspiciousExt: hasSuspiciousExt,
            pathname: urlObj.pathname,
            hasQueryParams: urlObj.search.length > 1
        };
    }

    /**
     * Primary inspection method.
     * @param {string} input - Text message or URL to analyze.
     * @param {string} type - 'message' | 'url'
     */
    analyze(input, type = "message") {
        if (!input || typeof input !== "string" || input.trim().length === 0) {
            throw new Error("Input payload cannot be empty. Please provide text or a URL to analyze.");
        }

        const trimmedInput = input.trim();
        const findings = [];
        const detectedCategories = new Set();
        let primaryUrlAnalysis = null;
        let embeddedUrls = [];

        // Trust DNA 2.0 raw category scores (0-100)
        const vectorScores = {
            urgency: 0,
            impersonation: 0,
            credentials: 0,
            payment: 0,
            urlRisk: 0
        };

        if (type === "url") {
            // URL Mode
            const parseResult = this.parseUrl(trimmedInput);
            if (!parseResult.valid) {
                throw new Error("Invalid URL syntax: " + parseResult.error);
            }
            primaryUrlAnalysis = this.deconstructUrl(parseResult.urlObj, parseResult.raw);
            this.evaluateUrl(parseResult.urlObj, parseResult.raw, findings, vectorScores, detectedCategories);
        } else {
            // Message Mode
            // 1. Evaluate Text Vectors (Urgency, Impersonation, Credentials, Payment)
            this.evaluateTextPatterns(trimmedInput, findings, vectorScores, detectedCategories);

            // 2. Check for embedded URLs in the message text
            embeddedUrls = this.extractUrls(trimmedInput);
            if (embeddedUrls.length > 0) {
                embeddedUrls.forEach((rawUrl, idx) => {
                    const parsed = this.parseUrl(rawUrl);
                    if (parsed.valid) {
                        if (idx === 0) {
                            primaryUrlAnalysis = this.deconstructUrl(parsed.urlObj, parsed.raw);
                        }
                        this.evaluateUrl(parsed.urlObj, parsed.raw, findings, vectorScores, detectedCategories);
                    }
                });
            }
        }

        // Normalize vector scores to 0-100 range
        for (const key of Object.keys(vectorScores)) {
            vectorScores[key] = Math.min(100, Math.round(vectorScores[key]));
        }

        // Calculate Composite Risk Score (0-100)
        const { riskScore, riskLevel, scoreExplanation } = this.calculateRiskScore(vectorScores, detectedCategories, findings.length);

        // Generate tailored Action Plan
        const actionPlan = this.generateActionPlan(detectedCategories, findings, riskLevel);

        // Metadata summary
        const metadata = {
            timestamp: new Date().toISOString(),
            formattedTime: new Date().toLocaleString(),
            inputType: type,
            inputLength: trimmedInput.length,
            embeddedUrlsFound: embeddedUrls.length,
            findingsCount: findings.length,
            engineVersion: this.version,
            disclaimer: "This risk score is computed deterministically from local heuristic signatures. It is an analytical indicator and does not constitute a guaranteed threat determination or certified live threat intelligence."
        };

        return {
            metadata,
            inputSummary: this.sanitizePreview(trimmedInput, type),
            riskScore,
            riskLevel,
            scoreExplanation,
            vectorScores,
            findings,
            actionPlan,
            embeddedUrls,
            urlAnalysis: primaryUrlAnalysis
        };
    }

    /**
     * Evaluates text message content against regex heuristic groups.
     */
    evaluateTextPatterns(text, findings, vectorScores, detectedCategories) {
        // 1. Urgency
        this.rules.URGENCY.forEach(rule => {
            const match = text.match(rule.pattern);
            if (match) {
                findings.push({
                    category: "Urgency & Coercion",
                    ruleId: rule.id,
                    name: rule.name,
                    severity: rule.severity,
                    matchedSnippet: match[0],
                    explanation: rule.explanation,
                    weight: rule.weight
                });
                vectorScores.urgency += rule.weight * 2.2;
                detectedCategories.add("URGENCY");
            }
        });

        // 2. Credentials
        this.rules.CREDENTIALS.forEach(rule => {
            const match = text.match(rule.pattern);
            if (match) {
                findings.push({
                    category: "Credential Harvesting",
                    ruleId: rule.id,
                    name: rule.name,
                    severity: rule.severity,
                    matchedSnippet: match[0],
                    explanation: rule.explanation,
                    weight: rule.weight
                });
                vectorScores.credentials += rule.weight * 2.0;
                detectedCategories.add("CREDENTIALS");
            }
        });

        // 3. Payment
        this.rules.PAYMENT.forEach(rule => {
            const match = text.match(rule.pattern);
            if (match) {
                findings.push({
                    category: "Payment Manipulation",
                    ruleId: rule.id,
                    name: rule.name,
                    severity: rule.severity,
                    matchedSnippet: match[0],
                    explanation: rule.explanation,
                    weight: rule.weight
                });
                vectorScores.payment += rule.weight * 2.0;
                detectedCategories.add("PAYMENT");
            }
        });

        // 4. Impersonation
        this.rules.IMPERSONATION.forEach(rule => {
            const match = text.match(rule.pattern);
            if (match) {
                findings.push({
                    category: "Impersonation & Authority",
                    ruleId: rule.id,
                    name: rule.name,
                    severity: rule.severity,
                    matchedSnippet: match[0],
                    explanation: rule.explanation,
                    weight: rule.weight
                });
                vectorScores.impersonation += rule.weight * 2.0;
                detectedCategories.add("IMPERSONATION");
            }
        });
    }

    /**
     * Evaluates URL structure, domain characteristics, and indicators.
     */
    evaluateUrl(urlObj, rawString, findings, vectorScores, detectedCategories) {
        this.rules.URL_INDICATORS.forEach(rule => {
            if (rule.check(urlObj, rawString)) {
                findings.push({
                    category: "Suspicious URL Infrastructure",
                    ruleId: rule.id,
                    name: rule.name,
                    severity: rule.severity,
                    matchedSnippet: this.extractUrlSnippet(rule.id, urlObj, rawString),
                    explanation: rule.explanation,
                    weight: rule.weight
                });
                vectorScores.urlRisk += rule.weight * 2.1;
                detectedCategories.add("URL");
            }
        });
    }

    /**
     * Extracts a human-readable snippet showing why the URL flagged.
     */
    extractUrlSnippet(ruleId, urlObj, rawString) {
        switch (ruleId) {
            case "URL_001":
                return `IP Host: ${urlObj.hostname}`;
            case "URL_002": {
                const parts = urlObj.hostname.split(".");
                return `High-Risk TLD: .${parts[parts.length - 1]}`;
            }
            case "URL_003":
                return `Link Shortener: ${urlObj.hostname}`;
            case "URL_004":
                return `Brand Subdomain Mimicry: ${urlObj.hostname}`;
            case "URL_005":
                return `Punycode Domain: ${urlObj.hostname}`;
            case "URL_006":
                return `Embedded Auth Symbol (@): ${rawString.slice(0, 45)}...`;
            case "URL_007":
                return `Insecure Protocol: ${urlObj.protocol}//`;
            case "URL_008":
                return `Executable File Payload: ${urlObj.pathname.split("/").pop()}`;
            case "URL_009":
                return `Abnormal Subdomain Depth: ${urlObj.hostname}`;
            default:
                return urlObj.hostname;
        }
    }

    /**
     * Derives composite risk score and risk classification.
     */
    calculateRiskScore(vectorScores, detectedCategories, findingsCount) {
        if (findingsCount === 0) {
            return {
                riskScore: 0,
                riskLevel: "Low",
                scoreExplanation: "No known phishing signals, coercion tactics, or suspicious domain infrastructure patterns were detected. The analyzed input does not exhibit typical social engineering markers."
            };
        }

        // Weighted category blend
        const weights = {
            urgency: 0.18,
            impersonation: 0.22,
            credentials: 0.28,
            payment: 0.22,
            urlRisk: 0.25
        };

        let weightedSum = (
            vectorScores.urgency * weights.urgency +
            vectorScores.impersonation * weights.impersonation +
            vectorScores.credentials * weights.credentials +
            vectorScores.payment * weights.payment +
            vectorScores.urlRisk * weights.urlRisk
        );

        // Compound Threat Multiplier:
        // Phishing attacks that combine multiple vectors simultaneously (e.g. Impersonation + Payment + URL)
        // represent significantly higher danger than an isolated word.
        const categoryCount = detectedCategories.size;
        let multiVectorBoost = 0;
        if (categoryCount >= 4) {
            multiVectorBoost = 30;
        } else if (categoryCount === 3) {
            multiVectorBoost = 24;
        } else if (categoryCount === 2) {
            multiVectorBoost = 12;
        }

        // Synergy: Suspicious Link + Brand Impersonation is the hallmark of phishing delivery
        if (detectedCategories.has("URL") && detectedCategories.has("IMPERSONATION")) {
            multiVectorBoost += 10;
        }

        let rawScore = weightedSum + multiVectorBoost;

        // Ensure floor if high-severity items exist
        const hasCritical = (vectorScores.credentials >= 60 || vectorScores.urlRisk >= 60 || vectorScores.payment >= 60);
        if (hasCritical && rawScore < 70) {
            rawScore = 72;
        }

        const finalScore = Math.min(100, Math.max(12, Math.round(rawScore)));

        let riskLevel = "Low";
        let scoreExplanation = "";

        if (finalScore >= 85) {
            riskLevel = "Critical";
            scoreExplanation = `Critical threat level (${finalScore}/100). The analysis identified multiple active exploit markers across ${categoryCount} distinct vector categories, strongly characteristic of a credential harvesting or financial fraud lure.`;
        } else if (finalScore >= 60) {
            riskLevel = "High";
            scoreExplanation = `High risk detected (${finalScore}/100). Found significant manipulation indicators such as brand impersonation, urgent time coercion, or suspicious link structures. Caution is strongly advised.`;
        } else if (finalScore >= 30) {
            riskLevel = "Medium";
            scoreExplanation = `Moderate concern (${finalScore}/100). Found isolated cautionary signals (such as artificial urgency or shortened links). Independent out-of-band verification is recommended.`;
        } else {
            riskLevel = "Low";
            scoreExplanation = `Low risk profile (${finalScore}/100). Minimal suspicious indicators were matched. Standard security hygiene should be maintained.`;
        }

        return {
            riskScore: finalScore,
            riskLevel,
            scoreExplanation
        };
    }

    /**
     * Generates a targeted, actionable safety plan.
     */
    generateActionPlan(detectedCategories, findings, riskLevel) {
        const steps = [];

        if (riskLevel === "Low") {
            steps.push({
                priority: "Standard",
                action: "Verify Sender Authenticity",
                detail: "Confirm the sender's full email address or phone number, not merely the displayed friendly name."
            });
            steps.push({
                priority: "Standard",
                action: "Maintain Baseline Vigilance",
                detail: "If this communication was unexpected, verify its context with the sender via an established secondary channel."
            });
            return steps;
        }

        // Dynamic tailored actions based on triggered categories
        if (detectedCategories.has("CREDENTIALS")) {
            steps.push({
                priority: "Immediate",
                action: "Never Disclose Passwords or OTP Verification Codes",
                detail: "Legitimate organizations, banks, and IT departments will never ask for your one-time passwords, login credentials, or PINs. Never share them."
            });
            steps.push({
                priority: "High",
                action: "If Credentials Were Entered, Reset Immediately",
                detail: "Visit the genuine service provider's official portal directly, change your password, and terminate all active sessions."
            });
        }

        if (detectedCategories.has("PAYMENT")) {
            steps.push({
                priority: "Immediate",
                action: "Halt All Unverified Financial Transfers",
                detail: "Do not execute wire transfers, cryptocurrency payments, or purchase gift cards. Requests for retail gift cards to resolve bills are fraudulent."
            });
            steps.push({
                priority: "High",
                action: "Execute Out-of-Band Payment Verification",
                detail: "Call the billing contact using a pre-existing, verified telephone number from your official contract records—never the number in the message."
            });
        }

        if (detectedCategories.has("URL")) {
            steps.push({
                priority: "Immediate",
                action: "Do Not Click or Follow Suspicious Links",
                detail: "Avoid opening the link on your personal or corporate device. Never execute downloaded files (.exe, .zip, .bat) received from unverified sources."
            });
            steps.push({
                priority: "High",
                action: "Inspect Without Visiting Directly",
                detail: "If forensic inspection is required, use dedicated URL sandbox scanners (such as urlscan.io) rather than a live web browser."
            });
        }

        if (detectedCategories.has("IMPERSONATION")) {
            steps.push({
                priority: "High",
                action: "Verify Identity via Official Directory",
                detail: "Contact the alleged company or sender directly using their verified public directory number or official mobile app."
            });
        }

        if (detectedCategories.has("URGENCY")) {
            steps.push({
                priority: "Caution",
                action: "Pause and Break the Pressure Loop",
                detail: "Attackers manufacture artificial deadlines ('within 24 hours') to bypass rational scrutiny. Step back and independently confirm before acting."
            });
        }

        // Universal step
        steps.push({
            priority: "Standard",
            action: "Report to Your Security Administrator",
            detail: "Forward suspicious messages to your organization's IT security team or report as phishing in your email platform."
        });

        return steps;
    }

    /**
     * Sanitizes input to protect user privacy in history records and reports.
     */
    sanitizePreview(input, type) {
        if (type === "url") {
            try {
                const parsed = new URL(input.startsWith("http") ? input : "https://" + input);
                return `${parsed.protocol}//${parsed.hostname}${parsed.pathname.slice(0, 35)}${parsed.pathname.length > 35 ? "..." : ""}`;
            } catch {
                return input.slice(0, 60);
            }
        }
        // Mask potential 6-digit OTPs or credit card numbers in preview
        const sanitized = input
            .replace(/\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, "[CARD MASKED]")
            .replace(/\b\d{6}\b/g, "[CODE MASKED]");
        return sanitized.length > 100 ? sanitized.slice(0, 100) + "..." : sanitized;
    }
}

// Export for global access in browser
if (typeof window !== "undefined") {
    window.SentinelEngine = SentinelEngine;
}
