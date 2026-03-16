"""
Configuration settings for the Secret & API Key Detector.
"""

import os

# ─────────────────────────────────────────
# File Scanning Settings
# ─────────────────────────────────────────

# Extensions to scan
SCANNABLE_EXTENSIONS = {
    # Code
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt", ".scala",
    # Config / Data
    ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".xml", ".plist",
    # Web
    ".html", ".htm", ".css", ".vue", ".svelte",
    # Shell
    ".sh", ".bash", ".zsh", ".fish",
    # Docs (sometimes contain keys)
    ".md", ".txt", ".log",
    # Docker / CI
    ".dockerfile", ".Dockerfile",
}

# Specific filenames to always scan (regardless of extension)
SCANNABLE_FILENAMES = {
    "Dockerfile", ".env", ".env.local", ".env.production",
    ".env.development", "Makefile", "Procfile", "Jenkinsfile",
    ".travis.yml", ".github", "docker-compose.yml",
}

# Directories to skip entirely
IGNORED_DIRECTORIES = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", "dist", "build", ".idea", ".vscode", ".pytest_cache",
    "coverage", ".mypy_cache", "site-packages", "eggs", ".eggs",
}

# File patterns to ignore
IGNORED_FILE_PATTERNS = [
    "*.pyc", "*.pyo", "*.class", "*.o", "*.so", "*.dylib",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
    "*.zip", "*.tar", "*.gz", "*.pdf", "*.lock",
    "package-lock.json", "yarn.lock", "poetry.lock",
]

# Max file size to scan (5 MB)
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# ─────────────────────────────────────────
# Entropy Settings
# ─────────────────────────────────────────

# Shannon entropy threshold to flag a string as potentially a secret
ENTROPY_THRESHOLD = 4.5

# Minimum length for entropy analysis
ENTROPY_MIN_LENGTH = 20

# Maximum length for entropy analysis (avoid huge base64 blobs)
ENTROPY_MAX_LENGTH = 200

# ─────────────────────────────────────────
# Severity Levels
# ─────────────────────────────────────────

SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH": "\033[93m",      # Yellow
    "MEDIUM": "\033[94m",    # Blue
    "LOW": "\033[92m",       # Green
    "INFO": "\033[37m",      # Grey
    "RESET": "\033[0m",
}

# ─────────────────────────────────────────
# Output Settings
# ─────────────────────────────────────────

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "reports")

DEFAULT_REPORT_FORMAT = "text"  # "text" or "json"

# ─────────────────────────────────────────
# False Positive Suppression
# ─────────────────────────────────────────

# Common placeholder values to skip
KNOWN_PLACEHOLDERS = {
    "your_api_key_here", "api_key_here", "your-secret-key", "changeme",
    "replace_me", "todo", "placeholder", "example", "test123",
    "xxxxxxxxxxxx", "aaaaaaaaaaaaaa", "1234567890",
    "your_token_here", "insert_key_here", "xxxxxxxx",
}

# Common test/example key patterns to downgrade severity
TEST_PATTERNS = [
    r"test[_-]?key", r"example[_-]?key", r"sample[_-]?key",
    r"fake[_-]?key", r"dummy[_-]?key",
]
