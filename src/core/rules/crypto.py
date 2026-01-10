WEAK_CRYPTO_FUNCTIONS = {
    "md5": {
        "severity": "MEDIUM",
        "message": "MD5 is cryptographically broken",
        "recommendation": "Use SHA-256 or SHA-3",
    },
    "sha1": {
        "severity": "MEDIUM",
        "message": "SHA-1 is deprecated",
        "recommendation": "Use SHA-256 or SHA-3",
    },
    "sha0": {
        "severity": "MEDIUM",
        "message": "SHA-0 is cryptographically broken",
        "recommendation": "Use SHA-256 or better",
    },
    "crc32": {
        "severity": "LOW",
        "message": "CRC32 is not a cryptographic hash",
        "recommendation": "Use SHA-256 instead",
    },
    "des": {
        "severity": "HIGH",
        "message": "DES is obsolete",
        "recommendation": "Use AES (256-bit)",
    },
    "des3": {
        "severity": "MEDIUM",
        "message": "3DES is deprecated",
        "recommendation": "Use AES-GCM",
    },
    "rc4": {
        "severity": "HIGH",
        "message": "RC4 cipher is broken",
        "recommendation": "Use AES or ChaCha20",
    },
    "arc2": {
        "severity": "HIGH",
        "message": "ARC2 cipher is obsolete",
        "recommendation": "Use AES",
    },
    "blowfish": {
        "severity": "MEDIUM",
        "message": "Blowfish cipher is outdated and has 64-bit block size issue",
        "recommendation": "Use AES",
    },
    "idea": {
        "severity": "MEDIUM",
        "message": "IDEA cipher is outdated",
        "recommendation": "Use AES",
    },
    "base64_encoding": {
        "severity": "LOW",
        "message": "Base64 is not encryption",
        "recommendation": "Use AES encryption instead of encoding",
    },
    "hmac_md5": {
        "severity": "MEDIUM",
        "message": "HMAC-MD5 is weak for authentication",
        "recommendation": "Use HMAC-SHA256",
    },
    "static_fernet_key": {
        "severity": "HIGH",
        "message": "Hardcoded Fernet key detected",
        "recommendation": "Store keys in environment variables or secret manager",
    },
}

WEAK_CRYPTO_MODES = {
    "ECB": {
        "severity": "HIGH",
        "message": "ECB mode is insecure",
        "recommendation": "Use CBC, GCM or CTR",
    },
    "CBC_no_iv": {
        "severity": "HIGH",
        "message": "CBC mode without IV is insecure",
        "recommendation": "Generate a random IV for each encryption",
    },
    "CTR_no_nonce": {
        "severity": "HIGH",
        "message": "CTR mode without nonce is insecure",
        "recommendation": "Always use a unique nonce",
    },
    "CFB": {
        "severity": "LOW",
        "message": "CFB mode is outdated for new systems",
        "recommendation": "Use GCM or ChaCha20",
    },
    "OFB": {
        "severity": "LOW",
        "message": "OFB mode is outdated",
        "recommendation": "Use GCM or ChaCha20",
    },
}

SSL_TLS_PATTERNS = {
    "requests_verify_false": {
        "pattern": r"requests\.(get|post|put|delete|patch|head|options)\s*\([^)]*verify\s*=\s*False",
        "severity": "HIGH",
        "message": "SSL/TLS verification disabled in requests",
    },
    "urllib_unverified_context": {
        "pattern": r"ssl\._create_unverified_context\s*\(",
        "severity": "HIGH",
        "message": "Unverified SSL context created",
    },
    "ssl_check_hostname_false": {
        "pattern": r"check_hostname\s*=\s*False",
        "severity": "HIGH",
        "message": "SSL hostname verification disabled",
    },
    "ssl_cert_none": {
        "pattern": r"verify_mode\s*=\s*ssl\.CERT_NONE",
        "severity": "HIGH",
        "message": "SSL certificate verification disabled (CERT_NONE)",
    },
    "ssl_cert_optional": {
        "pattern": r"verify_mode\s*=\s*ssl\.CERT_OPTIONAL",
        "severity": "MEDIUM",
        "message": "SSL certificate verification set to optional",
    },
    "httpx_verify_false": {
        "pattern": r"httpx\.(get|post|put|delete|patch|head|options)\s*\([^)]*verify\s*=\s*False",
        "severity": "HIGH",
        "message": "SSL/TLS verification disabled in httpx",
    },
    "urllib3_cert_reqs_none": {
        "pattern": r"cert_reqs\s*=\s*['\"]CERT_NONE['\"]",
        "severity": "HIGH",
        "message": "urllib3 certificate validation disabled",
    },
    "aiohttp_verify_ssl_false": {
        "pattern": r"verify_ssl\s*=\s*False",
        "severity": "HIGH",
        "message": "SSL verification disabled in aiohttp",
    },
}
