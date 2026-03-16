"""
token_detector.py

Detects authentication tokens:
  GitHub tokens, Slack tokens, JWTs, OAuth tokens, Telegram, etc.
"""

from typing import List, Dict
from .base_detector import BaseDetector


class TokenDetector(BaseDetector):
    """Detects authentication and authorization tokens."""

    def _load_patterns(self) -> List[Dict]:
        return [
            {
                "name": "github_personal_access_token",
                "regex": r"ghp_[a-zA-Z0-9]{36}",
                "severity": "CRITICAL",
                "description": "GitHub Personal Access Token",
            },
            {
                "name": "github_fine_grained_pat",
                "regex": r"github_pat_[a-zA-Z0-9_]{82}",
                "severity": "CRITICAL",
                "description": "GitHub Fine-Grained Personal Access Token",
            },
            {
                "name": "github_oauth_token",
                "regex": r"gho_[a-zA-Z0-9]{36}",
                "severity": "HIGH",
                "description": "GitHub OAuth Token",
            },
            {
                "name": "github_actions_token",
                "regex": r"ghs_[a-zA-Z0-9]{36}",
                "severity": "HIGH",
                "description": "GitHub Actions Token",
            },
            {
                "name": "github_refresh_token",
                "regex": r"ghr_[a-zA-Z0-9]{76}",
                "severity": "HIGH",
                "description": "GitHub Refresh Token",
            },
            {
                "name": "slack_bot_token",
                "regex": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
                "severity": "HIGH",
                "description": "Slack Bot Token",
            },
            {
                "name": "slack_user_token",
                "regex": r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}",
                "severity": "HIGH",
                "description": "Slack User Token",
            },
            {
                "name": "slack_webhook_url",
                "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
                "severity": "HIGH",
                "description": "Slack Incoming Webhook URL",
            },
            {
                "name": "jwt_token",
                "regex": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                "severity": "HIGH",
                "description": "JSON Web Token (JWT)",
            },
            {
                "name": "telegram_bot_token",
                "regex": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
                "severity": "HIGH",
                "description": "Telegram Bot Token",
            },
            {
                "name": "npm_access_token",
                "regex": r"npm_[A-Za-z0-9]{36}",
                "severity": "HIGH",
                "description": "NPM Access Token",
            },
            {
                "name": "twilio_auth_token",
                "regex": r"(?i)(twilio_auth_token|auth_token)\s*[=:]\s*[\"']?([a-f0-9]{32})[\"']?",
                "severity": "CRITICAL",
                "description": "Twilio Auth Token",
            },
            {
                "name": "gitlab_token",
                "regex": r"glpat-[a-zA-Z0-9\-_]{20}",
                "severity": "CRITICAL",
                "description": "GitLab Personal Access Token",
            },
            {
                "name": "digitalocean_token",
                "regex": r"(?i)(do_token|digitalocean_token)\s*[=:]\s*[\"']?([a-f0-9]{64})[\"']?",
                "severity": "CRITICAL",
                "description": "DigitalOcean API Token",
            },
        ]
