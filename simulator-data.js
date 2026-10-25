/**
 * Sentinel AI — Digital Trust Inspector
 * Simulator Scenarios & Educational Quiz (simulator-data.js)
 */

const SIMULATOR_DATA = {
    scenarios: [
        {
            id: "bank_smish",
            title: "Simulated Mobile Banking Alert (Smishing)",
            context: "A text message received from an unknown shortcode on a Friday evening.",
            sender: "+1 (833) 492-0199",
            subject: "Chase Fraud Prevention Alert",
            rawBody: "CHASE ALERT: Suspicious transaction of $749.00 at BestBuy detected. If this wasn't you, verify identity immediately at http://chase-security-verify.xyz/auth or your card will be permanently blocked within 2 hours.",
            hotspots: [
                {
                    text: "+1 (833) 492-0199",
                    title: "Unknown Toll-Free / Virtual Number",
                    tip: "Legitimate banks primarily communicate transactional SMS via registered 5-to-6 digit shortcodes, not random toll-free VoIP numbers."
                },
                {
                    text: "verify identity immediately",
                    title: "Manufactured Urgency & Panic",
                    tip: "Attackers manufacture high anxiety (e.g. '$749 charge') so victims immediately click the link before checking their genuine bank app."
                },
                {
                    text: "http://chase-security-verify.xyz/auth",
                    title: "Deceptive Domain & Insecure Protocol",
                    tip: "Notice 'chase-security-verify.xyz'. Chase Bank operates strictly on 'chase.com'. The .xyz extension and insecure 'http://' are giant red flags."
                },
                {
                    text: "permanently blocked within 2 hours",
                    title: "Coercive Time Window",
                    tip: "Banks do not permanently cancel accounts without prior formal written notice. Arbitrary deadlines prevent out-of-band verification."
                }
            ],
            correctAssessment: "Phishing (Smishing)",
            takeaway: "Never click link triggers in bank text alerts. Open your verified mobile banking app or call the number stamped on your physical card."
        },
        {
            id: "ceo_spear",
            title: "Executive Impersonation (Business Email Compromise)",
            context: "An internal email appearing to come from the CEO while you are at work.",
            sender: "David Henderson <d.henderson.ceo@executive-mailer-cloud.com>",
            subject: "URGENT: Confidential Request from David",
            rawBody: "Hi, I am currently locked in an all-day confidential board meeting and cannot take calls. I need you to immediately buy 5 Apple Gift Cards ($200 each) for client bonuses. Send me the scratched PIN codes directly by 2 PM. Keep this quiet until announced.",
            hotspots: [
                {
                    text: "d.henderson.ceo@executive-mailer-cloud.com",
                    title: "Mismatched Sender Domain",
                    tip: "The display name says David Henderson, but the sender domain is 'executive-mailer-cloud.com' rather than your company's actual domain."
                },
                {
                    text: "cannot take calls",
                    title: "Blocking Verification Channels",
                    tip: "Scammers deliberately claim to be unavailable by voice or video to prevent the victim from making a quick confirmation phone call."
                },
                {
                    text: "Apple Gift Cards ($200 each)",
                    title: "Gift Card Payment Demand",
                    tip: "Gift cards are untraceable, non-refundable currency. Legitimate corporate procurement NEVER utilizes retail gift cards for client bonuses."
                },
                {
                    text: "Keep this quiet",
                    title: "Isolation Tactic",
                    tip: "Instructing employees to bypass standard accounting protocols and maintain secrecy prevents peer review from catching the fraud."
                }
            ],
            correctAssessment: "Business Email Compromise (BEC)",
            takeaway: "Any executive asking for gift cards, wire transfers, or secrecy via email is virtually always an impersonation scam. Verify in person or via trusted company chat."
        },
        {
            id: "delivery_lure",
            title: "Postal Package Delivery Interception",
            context: "An SMS claiming a failed postal package delivery.",
            sender: "USPS-TrackNotice",
            subject: "Parcel Exception Notification",
            rawBody: "USPS Notice: Your package #US-883921 could not be delivered due to an incorrect address format. A minor redirection fee ($1.45) is required. Update details at https://bit.ly/usps-package-redirection to avoid return.",
            hotspots: [
                {
                    text: "USPS Notice",
                    title: "Broad Spoofed Brand",
                    tip: "USPS delivers billions of packages, making this lure relevant to nearly anyone who has ordered an item recently."
                },
                {
                    text: "minor redirection fee ($1.45)",
                    title: "Micro-Charge Credit Card Trap",
                    tip: "The small fee ($1.45) lowers suspicion. However, entering your card details on the fake form hands your full credit card and CVV to credit card skimming rings."
                },
                {
                    text: "https://bit.ly/usps-package-redirection",
                    title: "Masked URL Shortener",
                    tip: "Official postal carriers never use generic URL shorteners like bit.ly. Official tracking links are strictly on 'tools.usps.com'."
                }
            ],
            correctAssessment: "Credential & Financial Theft (Phishing)",
            takeaway: "Official delivery services do not collect redelivery address fees via shortened links. Always track packages directly on the carrier's primary portal."
        }
    ],

    quizQuestions: [
        {
            id: "q1",
            scenario: "You receive an email from 'IT Support Desk' with the subject 'Password Expiry in 1 Hour'. It asks you to click a button to 'Keep Your Current Password' before your workstation is locked.",
            options: [
                { text: "Click the button promptly so you don't lose access to work files.", isCorrect: false },
                { text: "Treat it as suspicious: legitimate IT departments don't send 1-hour expiry links to keep an old password.", isCorrect: true },
                { text: "Reply to the email with your password in plain text to verify identity.", isCorrect: false },
                { text: "Forward the email to all coworkers with an urgent warning.", isCorrect: false }
            ],
            explanation: "Passwords expire according to enterprise directory policy, and standard IT systems never allow you to 'keep an old password' by clicking a web link. This is a classic credential harvesting tactic."
        },
        {
            id: "q2",
            scenario: "You get a text: 'PayPal Alert: $450 sent to CryptoVault. If this wasn't you, call +1-888-555-0142 now.' When you call, the operator asks you to install AnyDesk or TeamViewer to assist.",
            options: [
                { text: "Install the software immediately because the agent sounds professional and helpful.", isCorrect: false },
                { text: "Refuse and hang up: scammers use fake transaction scares to trick victims into installing remote access tools.", isCorrect: true },
                { text: "Provide your online banking password so they can block the payment on their end.", isCorrect: false },
                { text: "Ask them to send the $450 back in gift cards.", isCorrect: false }
            ],
            explanation: "This is a Tech Support / Refund scam. Scammers send fake payment notifications to get you on the phone, then request Remote Access Software (TeamViewer, AnyDesk) to take over your computer and transfer money."
        },
        {
            id: "q3",
            scenario: "An incoming email link reads: 'https://login.microsoftonline.com.auth-service-redirect.top/login'. Which domain actually hosts this page?",
            options: [
                { text: "Microsoft (microsoftonline.com)", isCorrect: false },
                { text: "auth-service-redirect.top", isCorrect: true },
                { text: "Both domains are working together.", isCorrect: false },
                { text: "It cannot be determined from the URL.", isCorrect: false }
            ],
            explanation: "The true domain is determined by looking just before the first single slash '/'. In 'login.microsoftonline.com.auth-service-redirect.top', 'microsoftonline.com' is merely a deceptive subdomain string! The actual registered domain is 'auth-service-redirect.top'."
        },
        {
            id: "q4",
            scenario: "Your bank sends you a text message with a 6-digit passcode: '582910 is your One-Time Passcode. DO NOT SHARE THIS WITH ANYONE. Chase will NEVER call to ask for this code.' 30 seconds later, a caller claiming to be Chase asks for that code to cancel a fraud attempt.",
            options: [
                { text: "Give them the code because the caller has your name and phone number.", isCorrect: false },
                { text: "Never share the code under any circumstance: the caller is the attacker trying to log in.", isCorrect: true },
                { text: "Give them only the first 3 digits to be safe.", isCorrect: false },
                { text: "Ask them to text you their employee badge number first.", isCorrect: false }
            ],
            explanation: "The attacker already has your username/password and initiated a login. The bank sent YOU the 2FA code. If you read the code to the caller, they gain full access to your account."
        },
        {
            id: "q5",
            scenario: "An email from 'Netflix Billing' says 'Your membership payment failed. Update your card here: http://netflix.billing-update.com'. What is the safest way to respond?",
            options: [
                { text: "Click the link and fill in your credit card details.", isCorrect: false },
                { text: "Ignore the email link, open a new browser tab, go directly to netflix.com, and check your account status there.", isCorrect: true },
                { text: "Reply to the email with a screenshot of your credit card.", isCorrect: false },
                { text: "Click 'Unsubscribe' at the bottom of the email.", isCorrect: false }
            ],
            explanation: "Always navigate independently to the known official domain (netflix.com) by typing it into your browser address bar or opening the official app. Never use email links to settle payment issues."
        }
    ]
};

if (typeof window !== "undefined") {
    window.SIMULATOR_DATA = SIMULATOR_DATA;
}
