# Sentinel AI — Digital Trust Inspector

> **Enterprise Cybersecurity & Heuristic Trust Verification Platform**  
> Built for hackathons, security education, and rapid social engineering triage.

![Sentinel Theme](https://img.shields.io/badge/Theme-Obsidian%20%26%20Champagne%20Gold-D4AF37?style=flat-square)
![Engine](https://img.shields.io/badge/Engine-v2.4%20Deterministic%20Local-00E676?style=flat-square)
![Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Vanilla%20JS-blue?style=flat-square)
![Zero Dependency](https://img.shields.io/badge/External%20APIs-Zero%20(100%25%20Client--Side)-gold?style=flat-square)

---

## 🛡️ Overview

**Sentinel AI — Digital Trust Inspector** is a modern cybersecurity web application engineered to dissect suspicious messages (SMS, email, spear-phishing lures) and fraudulent web URLs.

Instead of making unverifiable claims of external AI black-boxes or leaking user credentials to third-party APIs, Sentinel AI operates a **fully explainable, local rule-based heuristic matrix**. It breaks threats down into a 5-dimensional **Trust DNA™ profile**, computes a deterministic **Risk Score (0–100)**, highlights the exact incriminating text snippets, and generates a context-aware **Safety Action Plan**.

---

## ✨ Key Features

1. **Enterprise Cybersecurity Dashboard**:
   - Polished Obsidian-Black (`#08090C`) and Champagne Gold (`#D4AF37`) design system.
   - Real-time audit metrics: Active heuristic count, scans performed, and threats mitigated.

2. **Smart Threat Scanner**:
   - **Dual Mode**: Message / Email / SMS Analysis and URL & Domain Deep Dive.
   - 6 Instant Test Presets: Bank Account Lock SMS, USPS Parcel Redelivery Fee, CEO Urgent Wire Lure, Tech Support Alert with Raw IP, Spoofed PayPal Subdomain URL, and a Legitimate Receipt (Clean / Safe baseline).
   - Animated Laser HUD scanning animation with multi-stage diagnostics.

3. **Rule-Based Heuristic Matrix (`rules.js` & `engine.js`)**:
   - **Urgency & Fear Coercion**: Artificial time limits, suspension threats, executive intimidation.
   - **Credential & Identity Harvesting**: One-time passcodes (OTP), 2FA lures, password theft, SSN requests.
   - **Payment Manipulation & Financial Fraud**: Untraceable wire demands, retail gift cards, crypto addresses, fabricated delivery fees.
   - **Impersonation & Brand Spoofing**: Major financial institutions (Chase, Wells Fargo, PayPal), postal couriers (USPS, DHL, FedEx), and tech providers.
   - **Suspicious URL & Infrastructure Red Flags**: Raw IP addresses as hostnames, high-risk TLDs (`.xyz`, `.top`, `.click`), URL shortener masking (`bit.ly`, `tinyurl`), subdomain brand masquerading, punycode encoding, and unencrypted HTTP.

4. **Trust DNA™ Risk Profile**:
   - 5-axis interactive HTML5 Canvas Radar Chart.
   - Animated visual progress meters showing the threat percentage across each category.

5. **Explainable Findings & Quoted Evidence**:
   - Every detected threat lists its category, severity level (`Critical`, `High`, `Medium`, `Low`), the exact quoted evidence snippet, and a human-readable explanation of attacker tactics.

6. **Prescribed Safety Action Plan**:
   - Dynamic checklist prioritized by threat severity (e.g. OTP entered $\rightarrow$ immediate session revocation; Wire transfer $\rightarrow$ dual-channel verification).

7. **Export Dossier / Threat Report**:
   - One-click export that generates a formal incident report (`.txt` / `.md`) and opens a high-resolution, print-optimized document view (`window.print()`).

8. **Interactive Scam Simulator**:
   - Probe simulated attacks (Bank SMS, Executive Spear-Phish, Package Lure).
   - Clickable interactive hotspots reveal attacker tradecraft, social engineering psychology, and defender rules.

9. **"Spot the Phish" Certification Quiz**:
   - 5 scenario-based interactive challenges with instant feedback and a Cyber Hygiene rating.

10. **Local Privacy-First Scan History**:
    - Stores past scans locally in `localStorage`.
    - Automatically masks sensitive numbers (passwords, OTPs, card numbers) from history previews.
    - One-click scan re-inspection or history clearance.

---

## 🚀 How to Run Locally

Sentinel AI requires **no complex build steps**, no Node.js packages, and no Python environment.

### Option 1: Native Windows PowerShell Server (Recommended)
Open PowerShell in the project directory and execute:
```powershell
.\start-server.ps1
```
This runs a lightweight local server on `http://localhost:8080/` and automatically launches your browser.

### Option 2: Direct File Opening
Double-click `index.html` or open it in any modern browser (Chrome, Edge, Firefox, Safari, Brave):
```
file:///C:/Users/ADMIN/.gemini/antigravity/scratch/sentinel-ai/index.html
```

### Option 3: Python (if available)
```bash
python -m http.server 8080
```

### Option 4: VS Code Live Server
Right-click `index.html` $\rightarrow$ "Open with Live Server".

---

## 🧪 Testing & Verification

Automated test suites are included to verify heuristic accuracy and DOM integration:

- **Engine Unit Tests (`run-tests.ps1` & `engine.test.html`)**:
  - Tests 20 rigorous assertions including multi-vector attacks, spoofed subdomains, raw IP addresses, and clean benign messages.
  - Run via:
    ```powershell
    powershell -ExecutionPolicy Bypass -File .\run-tests.ps1
    ```

- **DOM Integration Tests (`test-runner.ps1`)**:
  - Executes headless Edge browser validation confirming that all interactive components (Radar chart canvas, Quiz, Simulator, and Accordions) mount without JavaScript exceptions.
  - Run via:
    ```powershell
    powershell -ExecutionPolicy Bypass -File .\test-runner.ps1
    ```

---

## 🌐 Deployment Guide

Because Sentinel AI is 100% client-side with zero secret API keys, it can be deployed for free in seconds:

1. **GitHub Pages**:
   - Push this directory to a GitHub repository.
   - Go to **Settings $\rightarrow$ Pages $\rightarrow$ Source: Deploy from branch (`main` / root)**.
   - Live URL is provisioned immediately with HTTPS.

2. **Cloudflare Pages / Vercel / Netlify**:
   - Drag and drop this folder into the dashboard or link your Git repository.
   - Set Build Command to `None` and Output Directory to `./`.

---

## 🔒 Security & Privacy Statement

- **Deterministic Evaluation**: Sentinel AI does not guess or hallucinate. Rules are transparent and inspectable in the "Detection Rules" tab.
- **Privacy by Design**: No analyzed message text, emails, or entered URLs are sent across the Internet. All processing is executed strictly inside your local browser sandbox.
- **Defensive Safeguards**: Sentinel AI never automatically opens or redirects to submitted suspicious URLs.
