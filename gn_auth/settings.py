"""Default application settings."""
import os

# LOGLEVEL
LOGLEVEL = "WARNING"

# Flask settings
SECRET_KEY = ""
GN_AUTH_SECRETS = None # Set this to path to secrets file

# Session settings
SESSION_EXPIRY_MINUTES = 10

# Database settings
SQL_URI = "mysql://webqtlout:webqtlout@localhost/db_webqtl"
AUTH_DB = f"{os.environ.get('HOME')}/genenetwork/gn3_files/db/auth.db"
AUTH_MIGRATIONS = "migrations/auth"

# Redis settings
REDIS_URI = "redis://localhost:6379/0"
REDIS_JOB_QUEUE = "GN_AUTH::job-queue"

# OAuth2 settings
OAUTH2_SCOPE = (
    "profile", "group", "role", "resource", "user", "masquerade",
    "introspect")

CORS_ORIGINS = "*"
CORS_HEADERS = [
    "Content-Type",
    "Authorization",
    "Access-Control-Allow-Credentials"
]

# JSON Web Keys (JWKs)
JWKS_ROTATION_AGE_DAYS = 7 # Days (from creation) to keep a JWK in use.
JWKS_DELETION_AGE_DAYS = 14 # Days (from creation) to keep a JWK around before deleting it.

## Email
SMTP_HOST = "smtp.genenetwork.org" # does not actually exist right now
SMTP_PORT = 587
SMTP_TIMEOUT = 200 # seconds
SMTP_USER = "no-reply@genenetwork.org"
SMTP_PASSWORD = "asecrettoken"
