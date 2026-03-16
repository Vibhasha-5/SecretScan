#!/usr/bin/env python3
"""
app.py — Web UI for Secret & API Key Detector

Run with:
    python app.py
Then open http://localhost:5000
"""

import os
import sys
import json
import tempfile
import zipfile
import shutil
from pathlib import Path

from flask import Flask, render_template, request, jsonify

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.scanner.directory_scanner import DirectoryScanner
from src.report.json_reporter import generate_json_report

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan/text", methods=["POST"])
def scan_text():
    """Scan pasted code/text snippet."""
    data = request.get_json()
    code = data.get("code", "")
    filename = data.get("filename", "snippet.py")

    if not code.strip():
        return jsonify({"error": "No code provided"}), 400

    # Write to temp file and scan
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=os.path.splitext(filename)[1] or ".py",
        delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        tmp_path = f.name

    try:
        scanner = DirectoryScanner(enable_entropy=True, entropy_threshold=4.5)
        findings = scanner.scan_directory(tmp_path)
        stats = scanner.get_stats()
        report = generate_json_report(findings, filename, stats)
        return jsonify(report)
    finally:
        os.unlink(tmp_path)


@app.route("/api/scan/file", methods=["POST"])
def scan_file():
    """Scan an uploaded file or zip archive."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "Empty filename"}), 400

    tmp_dir = tempfile.mkdtemp()
    try:
        save_path = os.path.join(tmp_dir, uploaded.filename)
        uploaded.save(save_path)

        # If zip, extract it
        if uploaded.filename.endswith(".zip"):
            extract_dir = os.path.join(tmp_dir, "extracted")
            os.makedirs(extract_dir)
            with zipfile.ZipFile(save_path, "r") as zf:
                zf.extractall(extract_dir)
            scan_path = extract_dir
        else:
            scan_path = save_path

        scanner = DirectoryScanner(enable_entropy=True, entropy_threshold=4.5)
        findings = scanner.scan_directory(scan_path)
        stats = scanner.get_stats()
        report = generate_json_report(findings, uploaded.filename, stats)
        return jsonify(report)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/api/chat", methods=["POST"])
def chat():
    """
    Proxy chat messages to OpenAI (if API key provided).
    Falls back to built-in FAQ answers if no key given.
    """
    data = request.get_json()
    message = data.get("message", "").strip()
    api_key = data.get("api_key", "").strip()
    history = data.get("history", [])

    if not message:
        return jsonify({"error": "No message provided"}), 400

    # Built-in FAQ engine (no API key needed)
    faq_reply = _faq_answer(message)

    if not api_key:
        return jsonify({"reply": faq_reply, "source": "faq"})

    # Try OpenAI if key provided
    try:
        import urllib.request, json as _json
        system_prompt = (
            "You are SecretBot, an expert assistant for the SecretScan tool — "
            "a DevSecOps secret and API key detector. You help users understand "
            "how to use the tool, interpret scan results, fix vulnerabilities, "
            "set up CI/CD integrations, and follow secure coding best practices. "
            "Be concise, practical, and friendly. Use bullet points when listing steps."
        )
        messages_payload = [{"role": "system", "content": system_prompt}]
        for h in history[-6:]:
            messages_payload.append({"role": h["role"], "content": h["content"]})
        messages_payload.append({"role": "user", "content": message})

        payload = _json.dumps({
            "model": "gpt-3.5-turbo",
            "messages": messages_payload,
            "max_tokens": 500,
            "temperature": 0.7,
        }).encode()

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = _json.loads(resp.read())
            reply = result["choices"][0]["message"]["content"]
            return jsonify({"reply": reply, "source": "openai"})
    except Exception as e:
        # Fall back to FAQ on any OpenAI error
        return jsonify({"reply": faq_reply + f"\n\n*(OpenAI unavailable: {str(e)[:60]})*", "source": "faq"})


def _faq_answer(message: str) -> str:
    """Simple keyword-based FAQ engine."""
    msg = message.lower()

    if any(w in msg for w in ["cicd", "ci/cd", "github action", "pipeline", "workflow", "integrate"]):
        return (
            "**CI/CD Integration**\n\n"
            "Add this to `.github/workflows/secret-scan.yml`:\n\n"
            "```yaml\n- name: Scan for secrets\n  run: |\n    pip install -r requirements.txt\n    python cli.py scan . --format json --output scan.json\n```\n\n"
            "The tool returns **exit code 1** on CRITICAL/HIGH findings, so your pipeline will automatically fail if secrets are found. Check the CI/CD tab for a full workflow template."
        )
    if any(w in msg for w in ["entropy", "shannon", "high entropy"]):
        return (
            "**Entropy Analysis** uses Shannon's formula `H = -Σ p(x) log₂(p(x))` to detect secrets that don't match known patterns.\n\n"
            "Any string with entropy ≥ 4.5 and length 20–200 chars gets flagged. Random-looking strings like API keys score 4.5–5.5, while plain English scores 2–3.\n\n"
            "Use `--no-entropy` to disable it if you're getting too many false positives."
        )
    if any(w in msg for w in ["severity", "critical", "high", "medium", "low"]):
        return (
            "**Severity Levels:**\n\n"
            "🔴 **CRITICAL** — AWS keys, DB passwords, private keys, OpenAI keys\n"
            "🟠 **HIGH** — GitHub tokens, Slack tokens, JWTs, SendGrid\n"
            "🟡 **MEDIUM** — Test credentials, webhooks\n"
            "🟢 **LOW** — Publishable/public keys\n\n"
            "Filter with `--severity HIGH` to only see HIGH and above."
        )
    if any(w in msg for w in ["false positive", "placeholder", "ignore", "skip"]):
        return (
            "**Reducing False Positives:**\n\n"
            "• Common placeholders like `your_api_key_here`, `changeme` are auto-ignored\n"
            "• Use `--no-entropy` to disable entropy-based detection\n"
            "• Repeated characters (AAAAAAA) are automatically skipped\n"
            "• Add custom ignore rules in `config/settings.py` under `KNOWN_PLACEHOLDERS`"
        )
    if any(w in msg for w in ["upload", "file", "zip", "scan file"]):
        return (
            "**Scanning Files:**\n\n"
            "• Click **Upload File** tab and drag & drop any file\n"
            "• Supports: `.py .js .ts .env .yaml .json .sh .zip` and more\n"
            "• Upload a `.zip` to scan an entire project folder\n"
            "• Max file size: 50MB"
        )
    if any(w in msg for w in ["json", "report", "output", "export"]):
        return (
            "**Exporting Reports:**\n\n"
            "CLI: `python cli.py scan ./myproject --format json --output report.json`\n\n"
            "Reports are saved to `output/reports/` with a timestamp. JSON reports are perfect for SIEM tools, dashboards, or feeding into other DevSecOps pipelines."
        )
    if any(w in msg for w in ["aws", "amazon", "access key"]):
        return (
            "**AWS Key Detection:**\n\n"
            "SecretScan detects both `AKIA...` Access Key IDs and Secret Access Keys.\n\n"
            "**If you find one:** Immediately rotate it in AWS IAM → revoke the old key → check CloudTrail for unauthorized usage → store secrets in AWS Secrets Manager or environment variables instead."
        )
    if any(w in msg for w in ["fix", "remediate", "how to fix", "what to do"]):
        return (
            "**Remediating Exposed Secrets:**\n\n"
            "1. **Rotate immediately** — generate a new key/token right now\n"
            "2. **Revoke the old one** — don't just stop using it\n"
            "3. **Audit usage** — check logs for unauthorized access\n"
            "4. **Move to env vars** — use `.env` files (never committed) or a secrets manager\n"
            "5. **Add to `.gitignore`** — ensure `.env` is ignored\n"
            "6. **Use pre-commit hooks** — run SecretScan before every commit"
        )
    if any(w in msg for w in ["hello", "hi", "hey", "start", "help", "what can you do"]):
        return (
            "👋 **Hi! I'm SecretBot.**\n\n"
            "I can help you with:\n"
            "• Understanding scan results & severity levels\n"
            "• Setting up CI/CD integration\n"
            "• Remediating exposed secrets\n"
            "• How entropy analysis works\n"
            "• Reducing false positives\n"
            "• Exporting JSON reports\n\n"
            "Just ask me anything about SecretScan!"
        )
    return (
        "I can help with: **scan results**, **CI/CD setup**, **entropy analysis**, "
        "**severity levels**, **fixing exposed secrets**, **false positives**, and **JSON reports**.\n\n"
        "Try asking something like *\"How do I integrate this with GitHub Actions?\"* or *\"What does CRITICAL mean?\"*\n\n"
        "For more complex questions, add your OpenAI API key in the chat panel for full AI assistance."
    )


if __name__ == "__main__":
    print("\n🔐  Secret & API Key Detector — Web UI")
    print("   Starting server at http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
