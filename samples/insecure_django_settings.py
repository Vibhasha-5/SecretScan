from pathlib import Path
import boto3
import requests

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-5^r8k!q2w#n$x@p1m9v6j3h0g4f7d2s8a'

DEBUG = False

ALLOWED_HOSTS = ['*']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'production_db',
        'USER': 'postgres',
        'PASSWORD': 'Sup3rS3cur3DbP@ss!',
        'HOST': 'prod-db.internal.example.com',
        'PORT': '5432',
    }
}

AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
AWS_STORAGE_BUCKET_NAME = 'my-production-bucket'
AWS_S3_REGION_NAME = 'us-east-1'

STRIPE_SECRET_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc'
STRIPE_PUBLISHABLE_KEY = 'pk_live_TYooMQauvdEDq54NiTphI7jx'

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'noreply@myapp.com'
EMAIL_HOST_PASSWORD = 'GmailAppP@ssword2024'
EMAIL_PORT = 587

SENDGRID_API_KEY = 'SG.aBcDeFgHiJkLmNoPqRsTuV.wXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH'

SLACK_BOT_TOKEN = 'xoxb-17653285-885098418-10d7919b2f516a9b7d0e5d4c3a4b'
SLACK_WEBHOOK = 'https://hooks.slack.com/services/T1234ABCD/B5678EFGH/xYzAbCdEfGhIjKlMnOpQrSt'

REDIS_URL = 'redis://:RedisP@ssword456@cache.prod.example.com:6379/0'

GOOGLE_OAUTH2_CLIENT_ID = '123456789012-abcdefghijklmnopqrstuvwx.apps.googleusercontent.com'
GOOGLE_OAUTH2_CLIENT_SECRET = 'GOCSPX-AbCdEfGhIjKlMnOpQrStUvWx'

TWILIO_ACCOUNT_SID = 'ACa1b2c3d4e5f6789012345678901234ab'
TWILIO_AUTH_TOKEN = 'a1b2c3d4e5f67890a1b2c3d4e5f67890'

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)
