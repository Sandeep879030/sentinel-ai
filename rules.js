/**
 * Sentinel AI — Digital Trust Inspector
 * Cybersecurity Heuristic Rules & Threat Signatures
 * 
 * Modular rule definitions for message content, social engineering tactics,
 * and malicious URL patterns.
 */

const THREAT_RULES = {
    // CATEGORY 1: Urgency, Fear & Coercion Patterns
    URGENCY: [
        {
            id: "URG_001",
            name: "Artificial Time Constraint",
            pattern: /\b(?:within\s+(?:\d{1,2}\s*(?:hours?|hrs?|mins?|minutes?)|24\s*hours?|48\s*hours?)|immediate\s+(?:action|attention|verification|response|payment|transfer|wire|reply|update|termination|suspension|review)|act\s+immediately|immediately\b|act\s+now|without\s+delay|expires?\s+(?:today|soon|in\s+\d+\s*min)|time-sensitive|hurry|final\s+(?:warning|notice)|before\s+\d{1,2}(?::\d{2})?\s*(?:am|pm|today))\b/i,
            weight: 22,
            severity: "High",
            description: "Creates an artificial sense of urgency to bypass rational scrutiny and induce impulsive action.",
            explanation: "Attackers deliberately impose tight deadlines (e.g., 'within 24 hours') so victims act before verifying authenticity."
        },
        {
            id: "URG_002",
            name: "Threat of Account Suspension or Penalty",
            pattern: /\b(?:account\s+(?:will\s+be\s+)?(?:suspended|terminated|locked|closed|frozen|disabled|deactivated)|legal\s+action|law\s+enforcement|arrest\s+warrant|penalty\s+fee|loss\s+of\s+access|security\s+breach\s+detected)\b/i,
            weight: 25,
            severity: "Critical",
            description: "Threatens punitive consequences or account loss to intimidate the target.",
            explanation: "Fear-based intimidation leverages emotional stress to make victims click links or provide credentials without thinking."
        },
        {
            id: "URG_003",
            name: "High-Priority Directive / Executive Coercion",
            pattern: /\b(?:strictly\s+confidential|do\s+not\s+call\s+me|i'm\s+in\s+a\s+meeting|in\s+conference|urgent\s+(?:executive\s+)?meeting|need\s+this\s+done\s+asap|urgent\s+task|executive\s+request|need\s+a\s+favor)\b/i,
            weight: 18,
            severity: "Medium",
            description: "Mimics high-priority executive instruction while discouraging secondary out-of-band verification.",
            explanation: "Impersonators frequently claim to be trapped in meetings to prevent targets from calling them directly to verify."
        }
    ],

    // CATEGORY 2: Credential & Sensitive Identity Harvesting
    CREDENTIALS: [
        {
            id: "CRED_001",
            name: "One-Time Password (OTP) or 2FA Solicitation",
            pattern: /\b(?:otp|one-time\s+passcode|one-time\s+password|2fa\s+code|verification\s+code|auth\s+code|share\s+the\s+code|enter\s+the\s+6-digit|send\s+me\s+the\s+code)\b/i,
            weight: 35,
            severity: "Critical",
            description: "Direct request for two-factor authentication or one-time verification codes.",
            explanation: "Legitimate organizations NEVER request OTP codes via SMS, chat, or phone. Attackers harvest OTPs to hijack 2FA-protected accounts."
        },
        {
            id: "CRED_002",
            name: "Password / PIN Verification Lure",
            pattern: /\b(?:enter\s+your\s+password|confirm\s+your\s+pin|update\s+your\s+login|verify\s+your\s+credentials|login\s+to\s+restore|unlock\s+by\s+entering\s+password|submit\s+your\s+secret\s+key)\b/i,
            weight: 30,
            severity: "Critical",
            description: "Prompts the recipient to disclose their secret passwords, PINs, or private keys.",
            explanation: "Credential harvesting lures trick users into entering credentials on clone/spoofed phishing pages."
        },
        {
            id: "CRED_003",
            name: "Government / Identity Token Harvesting",
            pattern: /\b(?:social\s+security\s+number|ssn|national\s+insurance|driver'?s\s+licen[sc]e|passport\s+number|mother'?s\s+maiden\s+name|date\s+of\s+birth\s+and\s+ssn)\b/i,
            weight: 28,
            severity: "High",
            description: "Requests high-value PII (Personally Identifiable Information) suitable for identity theft.",
            explanation: "Compromised national IDs allow scammers to open fraudulent credit lines and execute SIM-swap attacks."
        }
    ],

    // CATEGORY 3: Payment Manipulation & Financial Fraud
    PAYMENT: [
        {
            id: "PAY_001",
            name: "Non-Standard / Untraceable Payment Demand",
            pattern: /\b(?:wire\s+transfer|gift\s+card|apple\s+gift|google\s+play\s+card|steam\s+card|vanilla\s+visa|western\s+union|moneygram|zelle|cash\s+app\s+payment|crypto(?:currency)?|bitcoin|btc\s+address|ethereum|usdt)\b/i,
            weight: 32,
            severity: "Critical",
            description: "Requests irreversible or untraceable payment mechanisms (Gift Cards, Wire Transfers, Crypto).",
            explanation: "Scammers insist on gift cards or cryptocurrency because transactions are instant, anonymous, and impossible to charge back."
        },
        {
            id: "PAY_002",
            name: "Unsolicited Refund, Lottery, or Prize Lure",
            pattern: /\b(?:you\s+have\s+won|lottery\s+winner|prize\s+money|unclaimed\s+funds?|tax\s+refund\s+pending|compensation\s+payout|claim\s+your\s+\$?\d+[\d,]*|eligible\s+for\s+refund|overpaid\s+amount)\b/i,
            weight: 24,
            severity: "High",
            description: "Dangles unexpected wealth or refunds to tempt the user into paying an 'advance fee' or sharing banking credentials.",
            explanation: "Advance-fee scams promise substantial windfalls in exchange for a small upfront handling or clearance fee."
        },
        {
            id: "PAY_003",
            name: "Overdue Invoice / Delivery Fee Coercion",
            pattern: /\b(?:unpaid\s+invoice|overdue\s+bill|past\s+due|delivery\s+fee|redelivery\s+(?:charge|fee)|(?:street\s+)?address\s+fee|settle\s+payment|customs\s+duty\s+fee|fee\s*(?:\([^\)]*\))?\s*(?:of\s*)?\$?\d+(?:\.\d{2})?|clearance\s+payment\s+required)\b/i,
            weight: 20,
            severity: "Medium",
            description: "Fabricates an unexpected fee or invoice that must be settled to release packages or avoid penalties.",
            explanation: "Attackers send fake $1-$5 package redelivery fees to collect active credit card numbers and CVV codes."
        }
    ],

    // CATEGORY 4: Impersonation & Authority Spoofing
    IMPERSONATION: [
        {
            id: "IMP_001",
            name: "Financial Institution / Payment Gateway Impersonation",
            pattern: /\b(?:chase(?:\s+(?:bank|checking|alert|security|account|online))?|wells\s+fargo|bank\s+of\s+america|citibank|hsbc|barclays|paypal(?:\s+(?:security|account|support))?|venmo\s+support|stripe\s+billing|cash\s+app\s+team|fraud\s+prevention\s+department)\b/i,
            weight: 25,
            severity: "High",
            description: "Claims to represent recognized major banks or payment processing services.",
            explanation: "Bank impersonation exploits customer trust to divert attention toward fake security verifications."
        },
        {
            id: "IMP_002",
            name: "Logistics & Package Delivery Impersonation",
            pattern: /\b(?:usps(?:\s+(?:tracking|parcel|notification|notice|delivery))?|fedex(?:\s+express)?|dhl(?:\s+courier)?|ups(?:\s+tracking)?|royal\s+mail|parcel\s+pending\s+delivery|package\s+#\w+)\b/i,
            weight: 22,
            severity: "High",
            description: "Spoofs national postal services and commercial delivery couriers.",
            explanation: "Package lures exploit the ubiquity of online shopping to bait users into clicking tracking links."
        },
        {
            id: "IMP_003",
            name: "Tech Support / Platform Security Impersonation",
            pattern: /\b(?:microsoft\s+(?:support|security|defender)|apple\s+security\s+alert|google\s+account\s+team|netflix\s+billing|amazon\s+security|it\s+helpdesk|cloud\s+administrator|system\s+administrator)\b/i,
            weight: 24,
            severity: "High",
            description: "Impersonates platform operators or IT support warning of malware or subscription troubles.",
            explanation: "Targets are fooled into granting remote desktop access or providing enterprise SSO credentials."
        },
        {
            id: "IMP_004",
            name: "Government, Tax & Law Enforcement Impersonation",
            pattern: /\b(?:irs\s+notice|internal\s+revenue|hmrc\s+tax|social\s+security\s+administration|fbi\s+cyber|police\s+department|customs\s+and\s+border|department\s+of\s+justice)\b/i,
            weight: 30,
            severity: "Critical",
            description: "Claims authority from state, tax, or legal regulatory agencies.",
            explanation: "Legal and government authorities almost never initiate contact via SMS or unsolicited email demanding immediate action."
        }
    ],

    // CATEGORY 5: URL Structure, Domain Entropy & Red Flags
    URL_INDICATORS: [
        {
            id: "URL_001",
            name: "Raw IP Address as Hostname",
            check: (urlObj) => {
                const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
                return ipv4Regex.test(urlObj.hostname);
            },
            weight: 35,
            severity: "Critical",
            description: "URL connects directly to a numerical IP address instead of a registered domain name.",
            explanation: "Legitimate public web services use standard domain names. Raw IP addresses evade domain reputation filters."
        },
        {
            id: "URL_002",
            name: "High-Risk Top-Level Domain (TLD)",
            check: (urlObj) => {
                const suspiciousTLDs = [
                    "xyz", "top", "click", "work", "link", "club", "surf",
                    "monster", "loan", "stream", "cam", "kim", "vip", "gq",
                    "cf", "ml", "tk", "ga", "fit", "buzz"
                ];
                const hostname = urlObj.hostname.toLowerCase();
                const parts = hostname.split(".");
                if (parts.length > 1) {
                    const tld = parts[parts.length - 1];
                    return suspiciousTLDs.includes(tld);
                }
                return false;
            },
            weight: 22,
            severity: "Medium",
            description: "Utilizes a budget or frequently abused TLD known for high spam/phishing density.",
            explanation: "While not inherently malicious, budget TLDs are disproportionately favored by disposable phishing campaigns."
        },
        {
            id: "URL_003",
            name: "URL Shortener / Obfuscation Service",
            check: (urlObj) => {
                const shorteners = [
                    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly",
                    "cutt.ly", "shorturl.at", "rebrand.ly", "tiny.cc",
                    "rb.gy", "bl.ink", "lnkd.in"
                ];
                return shorteners.includes(urlObj.hostname.toLowerCase());
            },
            weight: 20,
            severity: "Medium",
            description: "Uses a link-shortening service that masks the real destination endpoint.",
            explanation: "Shortened links obscure the final domain from preview, preventing users from seeing where they will be redirected."
        },
        {
            id: "URL_004",
            name: "Subdomain Stacking & Brand Masquerade",
            check: (urlObj) => {
                const brands = ["paypal", "chase", "wells-fargo", "apple", "microsoft", "google", "netflix", "amazon", "dhl", "usps", "bankofamerica"];
                const hostname = urlObj.hostname.toLowerCase();
                const parts = hostname.split(".");
                if (parts.length >= 3) {
                    const rootDomain = parts.slice(-2).join(".");
                    // Check if any brand name is in subdomains but not in root domain
                    const subdomains = parts.slice(0, -2).join(".");
                    for (const brand of brands) {
                        if (subdomains.includes(brand) && !rootDomain.includes(brand)) {
                            return true;
                        }
                    }
                }
                return false;
            },
            weight: 35,
            severity: "Critical",
            description: "Deceptive subdomain manipulation embedding trusted brand names into an unrelated domain.",
            explanation: "Example: 'paypal.com.account-verify.xyz' is controlled by 'account-verify.xyz', NOT PayPal."
        },
        {
            id: "URL_005",
            name: "Punycode / Homograph Character Attack",
            check: (urlObj) => {
                return urlObj.hostname.toLowerCase().startsWith("xn--") || urlObj.hostname.includes(".xn--");
            },
            weight: 32,
            severity: "High",
            description: "Utilizes internationalized domain (IDN) punycode encoding.",
            explanation: "Attackers use Cyrillic or Greek lookalike characters (e.g., 'а' instead of Latin 'a') to mimic legitimate domain names."
        },
        {
            id: "URL_006",
            name: "Embedded Credential / Userinfo Symbol (@)",
            check: (urlObj, rawString) => {
                return rawString.includes("@") || (urlObj.username && urlObj.username.length > 0);
            },
            weight: 30,
            severity: "High",
            description: "Contains an '@' symbol in the URL authority section.",
            explanation: "Browsers treat text before '@' as authentication credentials, causing the user to navigate to whatever comes AFTER the '@'."
        },
        {
            id: "URL_007",
            name: "Insecure Plaintext Transport (HTTP)",
            check: (urlObj) => {
                return urlObj.protocol === "http:";
            },
            weight: 15,
            severity: "Medium",
            description: "Connects via unencrypted HTTP rather than HTTPS.",
            explanation: "Unencrypted connections expose all transmitted passwords and session cookies to local network eavesdroppers."
        },
        {
            id: "URL_008",
            name: "Suspicious Executable / Script Extension",
            check: (urlObj) => {
                const path = urlObj.pathname.toLowerCase();
                const dangerousExts = [".exe", ".scr", ".bat", ".vbs", ".cmd", ".msi", ".apk", ".ps1", ".hta", ".zip", ".iso"];
                return dangerousExts.some(ext => path.endsWith(ext));
            },
            weight: 34,
            severity: "Critical",
            description: "Direct link to download an executable, script, or compressed archive.",
            explanation: "Drive-by downloads disguised as invoices or receipts attempt to execute malware payloads directly on the victim's device."
        },
        {
            id: "URL_009",
            name: "Excessive Subdomain Depth & Entropy",
            check: (urlObj) => {
                const parts = urlObj.hostname.split(".");
                return parts.length >= 5 || urlObj.hostname.length > 45;
            },
            weight: 16,
            severity: "Low",
            description: "Unusually deep subdomain nesting or abnormally long hostname.",
            explanation: "Adversaries often use automated domain generation algorithms (DGAs) or dynamic DNS trees to bypass blacklists."
        }
    ]
};

// Export to window for browser usage without modules
if (typeof window !== "undefined") {
    window.THREAT_RULES = THREAT_RULES;
}
