#!/usr/bin/env python3
"""
insecure_sample.py

⚠️  INTENTIONALLY INSECURE — FOR DEMO PURPOSES ONLY ⚠️

This file contains intentional hardcoded secrets to demonstrate
the Secret & API Key Detector tool. Never put real credentials
in source code like this!
"""

import boto3
import stripe
import openai
import requests

# ─────────────────────────────────────────────
# AWS Credentials (CRITICAL)
# ─────────────────────────────────────────────
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION            = "us-east-1"

client = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION,
)

# ─────────────────────────────────────────────
# GitHub Token (CRITICAL)
# ─────────────────────────────────────────────
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
}

# ─────────────────────────────────────────────
# OpenAI API Key (CRITICAL)
# ─────────────────────────────────────────────
openai.api_key = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghij"

response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)

# ─────────────────────────────────────────────
# Stripe Keys (CRITICAL + LOW)
# ─────────────────────────────────────────────
stripe.api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_PUB_KEY  = "pk_live_TYooMQauvdEDq54NiTphI7jx"

# ─────────────────────────────────────────────
# Database Connection Strings (CRITICAL)
# ─────────────────────────────────────────────
MONGO_URI    = "mongodb://admin:SuperS3cretP@ss@prod.database.host:27017/mydb"
POSTGRES_URL = "postgresql://dbuser:Passw0rd123!@db.prod.example.com:5432/appdb"
MYSQL_URL    = "mysql://root:mysecretpassword@localhost:3306/production"

# ─────────────────────────────────────────────
# Slack Integration (HIGH)
# ─────────────────────────────────────────────
SLACK_BOT_TOKEN  = "xoxb-17653285-885098418-10d7919b2f516a9b7d0e5d4c3a4b"
SLACK_WEBHOOK    = "https://hooks.slack.com/services/T1234ABCD/B5678EFGH/xYzAbCdEfGhIjKlMnOpQrSt"

# ─────────────────────────────────────────────
# SendGrid (HIGH)
# ─────────────────────────────────────────────
SENDGRID_API_KEY = "SG.aBcDeFgHiJkLmNoPqRsTuV.wXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH"

# ─────────────────────────────────────────────
# Hardcoded Password (HIGH)
# ─────────────────────────────────────────────
DB_PASSWORD = "SuperSecretPassword123!"
ADMIN_PASSWORD = "P@ssw0rd#Admin"

# ─────────────────────────────────────────────
# JWT Token (HIGH)
# ─────────────────────────────────────────────
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# ─────────────────────────────────────────────
# Twilio (HIGH)
# ─────────────────────────────────────────────
TWILIO_ACCOUNT_SID = "ACa1b2c3d4e5f6789012345678901234ab"
TWILIO_AUTH_TOKEN  = "auth_token = a1b2c3d4e5f67890a1b2c3d4e5f67890"

# ─────────────────────────────────────────────
# Telegram Bot (HIGH)
# ─────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcde12"

# ─────────────────────────────────────────────
# Google API (HIGH)
# ─────────────────────────────────────────────
GOOGLE_API_KEY = "AIzaSyBnTdS5Lm_8ExAmPle_K3yT0ken123456"


def connect_to_services():
    """Initialize all service connections — BAD PRACTICE: secrets in code!"""
    print("Connecting with hardcoded credentials... (never do this!)")
