"""
secret_detector.py

Detects generic hardcoded secrets:
  Passwords, private keys, database credentials, connection strings.
"""

from typing import List, Dict
from .base_detector import BaseDetector


class SecretDetector(BaseDetector):
    """Detects generic hardcoded secrets and credentials."""

    def _load_patterns(self) -> List[Dict]:
        return [
            {
                "name": "rsa_private_key",
                "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                "severity": "CRITICAL",
                "description": "Private Key (RSA/EC/DSA/OpenSSH)",
            },
            {
                "name": "certificate",
                "regex": r"-----BEGIN CERTIFICATE-----",
                "severity": "MEDIUM",
                "description": "X.509 Certificate",
            },
            {
                "name": "mongodb_connection_string",
                "regex": r"mongodb(\+srv)?://[a-zA-Z0-9_\-]+:[^@\s\"']+@[a-zA-Z0-9.\-]+",
                "severity": "CRITICAL",
                "description": "MongoDB Connection String with Credentials",
            },
            {
                "name": "postgresql_connection_string",
                "regex": r"postgres(ql)?://[a-zA-Z0-9_\-]+:[^@\s\"']+@[a-zA-Z0-9.\-]+",
                "severity": "CRITICAL",
                "description": "PostgreSQL Connection String with Credentials",
            },
            {
                "name": "mysql_connection_string",
                "regex": r"mysql://[a-zA-Z0-9_\-]+:[^@\s\"']+@[a-zA-Z0-9.\-]+",
                "severity": "CRITICAL",
                "description": "MySQL Connection String with Credentials",
            },
            {
                "name": "redis_connection_string",
                "regex": r"redis://:[^@\s\"']+@[a-zA-Z0-9.\-]+",
                "severity": "HIGH",
                "description": "Redis Connection String with Password",
            },
            {
                "name": "hardcoded_password",
                "regex": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
                "severity": "HIGH",
                "description": "Hardcoded Password",
            },
            {
                "name": "hardcoded_secret",
                "regex": r'(?i)(secret|api_secret|client_secret|app_secret)\s*[=:]\s*["\']([^"\']{8,})["\']',
                "severity": "HIGH",
                "description": "Hardcoded Secret",
            },
            {
                "name": "hardcoded_token",
                "regex": r'(?i)(token|auth_token|access_token|bearer_token)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                "severity": "MEDIUM",
                "description": "Hardcoded Token",
            },
            {
                "name": "hardcoded_api_key",
                "regex": r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
                "severity": "HIGH",
                "description": "Hardcoded API Key",
            },
            {
                "name": "basic_auth_header",
                "regex": r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}",
                "severity": "HIGH",
                "description": "HTTP Basic Auth Header",
            },
            {
                "name": "bearer_token_header",
                "regex": r"Authorization:\s*Bearer\s+[A-Za-z0-9\-_\.]{20,}",
                "severity": "HIGH",
                "description": "HTTP Bearer Token Header",
            },
            {
                "name": "ssh_password",
                "regex": r"(?i)(ssh_password|ssh_pass)\s*[=:]\s*[\"']([^\"']{6,})[\"']",
                "severity": "CRITICAL",
                "description": "SSH Password",
            },
            {
                "name": "ftp_credentials",
                "regex": r"ftp://[a-zA-Z0-9_\-]+:[^@\s\"']+@",
                "severity": "HIGH",
                "description": "FTP Credentials in URL",
            },
        ]
