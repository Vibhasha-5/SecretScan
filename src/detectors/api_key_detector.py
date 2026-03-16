"""
api_key_detector.py

Detects cloud provider and SaaS API keys:
  AWS, Google, Stripe, SendGrid, Mailgun, OpenAI, Azure, etc.
"""

from typing import List, Dict
from .base_detector import BaseDetector


class APIKeyDetector(BaseDetector):
    """Detects cloud and SaaS API keys."""

    def _load_patterns(self) -> List[Dict]:
        return [
            {
                "name": "aws_access_key_id",
                "regex": r"AKIA[0-9A-Z]{16}",
                "severity": "CRITICAL",
                "description": "AWS Access Key ID",
            },
            {
                "name": "aws_secret_access_key",
                "regex": r"(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
                "severity": "CRITICAL",
                "description": "AWS Secret Access Key",
            },
            {
                "name": "google_api_key",
                "regex": r"AIza[0-9A-Za-z\-_]{35}",
                "severity": "HIGH",
                "description": "Google API Key",
            },
            {
                "name": "google_oauth_client_id",
                "regex": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
                "severity": "HIGH",
                "description": "Google OAuth Client ID",
            },
            {
                "name": "stripe_live_secret_key",
                "regex": r"sk_live_[0-9a-zA-Z]{24,}",
                "severity": "CRITICAL",
                "description": "Stripe Live Secret Key",
            },
            {
                "name": "stripe_test_secret_key",
                "regex": r"sk_test_[0-9a-zA-Z]{24,}",
                "severity": "MEDIUM",
                "description": "Stripe Test Secret Key",
            },
            {
                "name": "stripe_publishable_key",
                "regex": r"pk_(live|test)_[0-9a-zA-Z]{24,}",
                "severity": "LOW",
                "description": "Stripe Publishable Key",
            },
            {
                "name": "sendgrid_api_key",
                "regex": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
                "severity": "HIGH",
                "description": "SendGrid API Key",
            },
            {
                "name": "mailgun_api_key",
                "regex": r"key-[0-9a-zA-Z]{32}",
                "severity": "HIGH",
                "description": "Mailgun API Key",
            },
            {
                "name": "openai_api_key",
                "regex": r"sk-[a-zA-Z0-9]{48}",
                "severity": "CRITICAL",
                "description": "OpenAI API Key",
            },
            {
                "name": "azure_storage_connection",
                "regex": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
                "severity": "CRITICAL",
                "description": "Azure Storage Connection String",
            },
            {
                "name": "heroku_api_key",
                "regex": r"(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
                "severity": "HIGH",
                "description": "Heroku API Key",
            },
            {
                "name": "twilio_account_sid",
                "regex": r"AC[a-zA-Z0-9]{32}",
                "severity": "HIGH",
                "description": "Twilio Account SID",
            },
            {
                "name": "hubspot_api_key",
                "regex": r"(?i)(hubspot_api_key|hapikey)\s*[=:]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?",
                "severity": "HIGH",
                "description": "HubSpot API Key",
            },
            {
                "name": "paypal_braintree_token",
                "regex": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
                "severity": "CRITICAL",
                "description": "PayPal/Braintree Access Token",
            },
            {
                "name": "discord_bot_token",
                "regex": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
                "severity": "HIGH",
                "description": "Discord Bot Token",
            },
        ]
