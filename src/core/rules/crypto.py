WEAK_CRYPTO_FUNCTIONS = {
    'md5': {
        'severity': 'MEDIUM',
        'message': 'MD5 is cryptographically broken',
        'recommendation': 'Use SHA-256 or SHA-3'
    },

    'sha1': {
        'severity': 'MEDIUM',
        'message': 'SHA-1 is deprecated',
        'recommendation': 'Use SHA-256 or SHA-3'
    },

    'sha0': {
        'severity': 'MEDIUM',
        'message': 'SHA-0 is cryptographically broken',
        'recommendation': 'Use SHA-256 or better'
    },

    'crc32': {
        'severity': 'LOW',
        'message': 'CRC32 is not a cryptographic hash',
        'recommendation': 'Use SHA-256 instead'
    },

    'des': {
        'severity': 'HIGH',
        'message': 'DES is obsolete',
        'recommendation': 'Use AES (256-bit)'
    },

    'des3': {
        'severity': 'MEDIUM',
        'message': '3DES is deprecated',
        'recommendation': 'Use AES-GCM'
    },

    'rc4': {
        'severity': 'HIGH',
        'message': 'RC4 cipher is broken',
        'recommendation': 'Use AES or ChaCha20'
    },

    'arc2': {
        'severity': 'HIGH',
        'message': 'ARC2 cipher is obsolete',
        'recommendation': 'Use AES'
    },

    'blowfish': {
        'severity': 'MEDIUM',
        'message': 'Blowfish cipher is outdated and has 64-bit block size issue',
        'recommendation': 'Use AES'
    },

    'idea': {
        'severity': 'MEDIUM',
        'message': 'IDEA cipher is outdated',
        'recommendation': 'Use AES'
    },

    'base64_encoding': {
        'severity': 'LOW',
        'message': 'Base64 is not encryption',
        'recommendation': 'Use AES encryption instead of encoding'
    },

    'hmac_md5': {
        'severity': 'MEDIUM',
        'message': 'HMAC-MD5 is weak for authentication',
        'recommendation': 'Use HMAC-SHA256'
    },

    'static_fernet_key': {
        'severity': 'HIGH',
        'message': 'Hardcoded Fernet key detected',
        'recommendation': 'Store keys in environment variables or secret manager'
    },
}

WEAK_CRYPTO_MODES = {
    'ECB': {
        'severity': 'HIGH',
        'message': 'ECB mode is insecure',
        'recommendation': 'Use CBC, GCM or CTR'
    },

    'CBC_no_iv': {
        'severity': 'HIGH',
        'message': 'CBC mode without IV is insecure',
        'recommendation': 'Generate a random IV for each encryption'
    },

    'CTR_no_nonce': {
        'severity': 'HIGH',
        'message': 'CTR mode without nonce is insecure',
        'recommendation': 'Always use a unique nonce'
    },

    'CFB': {
        'severity': 'LOW',
        'message': 'CFB mode is outdated for new systems',
        'recommendation': 'Use GCM or ChaCha20'
    },

    'OFB': {
        'severity': 'LOW',
        'message': 'OFB mode is outdated',
        'recommendation': 'Use GCM or ChaCha20'
    },
}
