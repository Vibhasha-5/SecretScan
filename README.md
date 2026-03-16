# 🔐 SecretScan — Secret & API Key Detector

> A production-grade DevSecOps tool that detects hardcoded secrets, API keys, tokens, and high-entropy strings in source code.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-red)

---

## 🎯 Features

- **30+ Detection Patterns** — AWS, GitHub, Stripe, OpenAI, Slack, SendGrid, Twilio, Google, Azure, and more
- **Shannon Entropy Analysis** — Catches secrets that don't match known patterns via information-theoretic analysis
- **Three Specialized Detectors** — API keys, Auth tokens, and Generic secrets (modular, single-responsibility design)
- **False Positive Suppression** — Automatically ignores known placeholder values
- **Dual Output Modes** — Human-readable terminal output + machine-readable JSON (for CI/CD pipelines)
- **Web UI** — Cinematic dark-mode interface with real-time scanning
- **CLI Tool** — Full-featured command-line interface with severity filtering
- **Exit Codes** — Returns exit code 1 on CRITICAL/HIGH findings (perfect for CI gates)

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/yourusername/secret-api-key-detector.git
cd secret-api-key-detector

# Create virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. CLI Usage

```bash
# Scan a directory (text output)
python cli.py scan ./my_project

# Scan with JSON output
python cli.py scan ./my_project --format json

# Save JSON report to specific file
python cli.py scan ./my_project --format json --output report.json

# Filter by minimum severity
python cli.py scan ./my_project --severity HIGH

# Disable entropy analysis (faster, fewer false positives)
python cli.py scan ./my_project --no-entropy

# Scan the demo samples
python cli.py scan ./samples
```

### 3. Web UI

```bash
python app.py
# Open http://localhost:5000
```

---

## 🧪 Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Individual test suites
python tests/test_api_keys.py
python tests/test_entropy.py
python tests/test_scanner.py
```

---

## 📁 Project Structure

```
secret-api-key-detector/
├── cli.py                    # CLI entry point
├── app.py                    # Flask web UI
├── requirements.txt
│
├── config/
│   ├── patterns.yaml         # 30+ regex patterns
│   └── settings.py           # Thresholds, file extensions, ignore rules
│
├── src/
│   ├── scanner/
│   │   ├── file_scanner.py       # Scans individual files
│   │   ├── directory_scanner.py  # Recursive directory walking
│   │   └── entropy_checker.py    # Shannon entropy analysis
│   │
│   ├── detectors/
│   │   ├── api_key_detector.py   # Cloud + SaaS API keys
│   │   ├── token_detector.py     # JWTs, OAuth, GitHub tokens
│   │   └── secret_detector.py    # Passwords, DB strings, private keys
│   │
│   ├── utils/
│   │   ├── file_utils.py
│   │   ├── regex_utils.py
│   │   └── logger.py
│   │
│   └── report/
│       ├── formatter.py          # Human-readable terminal output
│       └── json_reporter.py      # Machine-readable JSON output
│
├── tests/
│   ├── test_api_keys.py
│   ├── test_entropy.py
│   └── test_scanner.py
│
├── samples/
│   ├── insecure_sample.py        # Demo: 15+ hardcoded secrets
│   └── insecure_config.env       # Demo: .env with real-looking secrets
│
└── output/
    └── reports/                  # JSON scan reports saved here
```

---

## 🔍 How It Works

### 1. Pattern Detection
Each detector uses curated regex patterns for specific secret types. Patterns are organized by category (API keys vs tokens vs generic secrets) following the **Single Responsibility Principle**.

### 2. Shannon Entropy Analysis
For every string in the scanned file, we compute:

```
H = -Σ p(x) * log₂(p(x))
```

High-entropy strings (H ≥ 4.5) that look like base64 or hex are flagged as potential secrets — even when they don't match any known pattern.

### 3. False Positive Suppression
Known placeholders (`your_api_key_here`, `changeme`, etc.) are automatically ignored.

### 4. Severity Levels
| Level    | Examples                              |
|----------|---------------------------------------|
| CRITICAL | AWS keys, DB passwords, private keys  |
| HIGH     | GitHub tokens, Slack tokens, JWTs     |
| MEDIUM   | Test credentials, webhooks            |
| LOW      | Public/publishable keys               |

---

## 🏗️ CI/CD Integration

SecretScan returns **exit code 1** if any CRITICAL or HIGH findings are found, making it a drop-in CI gate:

```yaml
# .github/workflows/secret-scan.yml
- name: Scan for secrets
  run: |
    pip install -r requirements.txt
    python cli.py scan . --format json --output scan-results.json
  # Job fails automatically on CRITICAL/HIGH findings
```

---

## 📊 Example Output

```
🔴 [CRITICAL] Line 12 — AWS Access Key ID
     Matched : AKIA****EXAMPLE
     Context : AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

🟠 [HIGH] Line 34 — GitHub Personal Access Token
     Matched : ghp_****178B4a
     Context : GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

  CRITICAL   : 4 finding(s)
  HIGH       : 7 finding(s)
  Total      : 11 findings
```

---

## 🛡️ Supported Secret Types

AWS Access Keys · AWS Secret Keys · GitHub PATs · GitHub OAuth · GitLab Tokens · Google API Keys · Google OAuth · OpenAI API Keys · Stripe Live/Test Keys · Slack Tokens · Slack Webhooks · Twilio SIDs · Twilio Auth Tokens · SendGrid Keys · Mailgun Keys · HubSpot Keys · PayPal/Braintree Tokens · Discord Bot Tokens · Telegram Bot Tokens · NPM Tokens · Azure Storage · Heroku API Keys · JWT Tokens · RSA/EC Private Keys · MongoDB URIs · PostgreSQL URIs · MySQL URIs · Redis URIs · Hardcoded Passwords · Hardcoded Secrets · Bearer Tokens · Basic Auth Headers

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

*Built for the DevSecOps community. Shift security left.*
