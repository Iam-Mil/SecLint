SECRET_PATTERNS = {
    # AWS
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "message": "AWS Access Key ID found",
    },
    "aws_secret_key": {
        "pattern": r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
        "severity": "CRITICAL",
        "message": "AWS Secret Access Key found",
    },

    # GitHub / GitLab / OAuth
    "github_token": {
        "pattern": r"gh[pousr]_[0-9A-Za-z]{36}",
        "severity": "CRITICAL",
        "message": "GitHub Access Token found",
    },
    "gitlab_token": {
        "pattern": r"glpat-[0-9A-Za-z_-]{20,}",
        "severity": "CRITICAL",
        "message": "GitLab Personal Access Token found",
    },
    "oauth_client_secret": {
        "pattern": r"client_secret\s*=\s*['\"][A-Za-z0-9_\-]{12,}['\"]",
        "severity": "HIGH",
        "message": "OAuth client_secret found",
    },

    # Payments
    "stripe_secret": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
        "message": "Stripe Live Secret Key found",
    },
    "stripe_publishable": {
        "pattern": r"pk_live_[0-9a-zA-Z]{24,}",
        "severity": "MEDIUM",
        "message": "Stripe Publishable Key found (not critical)",
    },

    # OpenAI
    "openai_key": {
        "pattern": r"sk-[A-Za-z0-9]{48}",
        "severity": "HIGH",
        "message": "OpenAI API Key found",
    },

    # Telegram / Discord
    "telegram_bot_token": {
        "pattern": r"\d{6,12}:[A-Za-z0-9_-]{30,50}",
        "severity": "CRITICAL",
        "message": "Telegram Bot Token found",
    },
    "discord_bot_token": {
        "pattern": r"[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{20,}",
        "severity": "CRITICAL",
        "message": "Discord Bot Token found",
    },

    # Cloud vendors
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
        "message": "Google API Key found",
    },
    "firebase_key": {
        "pattern": r"AAAA[A-Za-z0-9_-]{7,}",
        "severity": "HIGH",
        "message": "Firebase Server Key found",
    },
    "cloudflare_api_key": {
        "pattern": r"[A-Fa-f0-9]{37}",
        "severity": "HIGH",
        "message": "Cloudflare API Key found",
    },
    "digitalocean_token": {
        "pattern": r"do_[A-Za-z0-9]{60}",
        "severity": "HIGH",
        "message": "DigitalOcean API Token found",
    },

    # Mail providers
    "sendgrid_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",
        "severity": "HIGH",
        "message": "SendGrid API Key found",
    },
    "mailgun_key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "HIGH",
        "message": "Mailgun API Key found",
    },

    # Webhooks
    "slack_webhook": {
        "pattern": r"https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+",
        "severity": "CRITICAL",
        "message": "Slack Webhook URL found",
    },

    # JWT / Secrets
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "HIGH",
        "message": "JWT token found",
    },
    "jwt_secret": {
        "pattern": r"(jwt_secret|secret_key)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        "severity": "HIGH",
        "message": "JWT secret key found",
    },

    # SSH Keys / PEM / Certificates
    "private_key_header": {
        "pattern": r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "message": "Private key found in code",
    },
    "ssh_rsa_key": {
        "pattern": r"ssh-rsa\s+[A-Za-z0-9+/]{100,}={0,3}",
        "severity": "CRITICAL",
        "message": "SSH RSA public key found",
    },

    # Databases
    "database_url": {
        "pattern": r"(postgresql|mysql|mongodb):\/\/[^:]+:[^@]+@",
        "severity": "HIGH",
        "message": "Database URL with credentials",
    },

    # Generic patterns
    "generic_api_key": {
        "pattern": r"(api_key|apikey|api-key)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        "severity": "HIGH",
        "message": "Generic API key found",
    },
    "password_in_code": {
        "pattern": r"(password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]",
        "severity": "HIGH",
        "message": "Hardcoded password found",
    },
    "bearer_token": {
        "pattern": r"Bearer\s+[A-Za-z0-9\._\-]{24,}",
        "severity": "HIGH",
        "message": "Bearer Token found",
    },
}
