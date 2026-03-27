"""
crypto_utils.py

This module contains the core cryptographic primitives required for the 
Searchable Symmetric Encryption (SSE) scheme. It provides:
1. Symmetric Encryption (AES-128-CBC with HMAC via Fernet) to encrypt data nodes.
2. A Pseudo-Random Function (PRF) using HMAC-SHA256 to generate deterministic, 
   secure search trapdoors and memory addresses from plaintext keywords.
"""

import json
import hashlib
import hmac
from cryptography.fernet import Fernet

class CryptoUtils:
    @staticmethod
    def generate_key() -> bytes:
        """Generates a 32-byte url-safe base64-encoded key for symmetric encryption."""
        return Fernet.generate_key()

    @staticmethod
    def prf(key: bytes, keyword: str) -> str:
        """Pseudo-Random Function (HMAC-SHA256) used for token generation."""
        return hmac.new(key, keyword.encode('utf-8'), hashlib.sha256).hexdigest()

    @staticmethod
    def encrypt_data(key: bytes, data: dict) -> str:
        """Encrypts a dictionary into a base64 string payload."""
        f = Fernet(key)
        ciphertext_bytes = f.encrypt(json.dumps(data).encode('utf-8'))
        return ciphertext_bytes.decode('utf-8')

    @staticmethod
    def decrypt_data(key: bytes, ciphertext: str) -> dict:
        """Decrypts a base64 string payload back into a dictionary."""
        f = Fernet(key)
        decrypted_bytes = f.decrypt(ciphertext.encode('utf-8'))
        return json.loads(decrypted_bytes.decode('utf-8'))