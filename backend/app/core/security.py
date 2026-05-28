"""Security utilities for encryption, hashing, and token management."""
import os
import base64
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from app.core.config import get_settings

settings = get_settings()

# Password hashing context
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


class TokenManager:
    """Manages JWT token generation and validation."""

    @staticmethod
    def create_access_token(
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a JWT access token.

        Args:
            data: Claims to encode in the token
            expires_delta: Token expiration time delta

        Returns:
            str: Encoded JWT token
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=settings.access_token_expire_minutes
            )

        to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
        encoded_jwt = jwt.encode(
            to_encode,
            settings.secret_key,
            algorithm=settings.algorithm,
        )
        return encoded_jwt

    @staticmethod
    def create_refresh_token(
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a JWT refresh token.

        Args:
            data: Claims to encode in the token
            expires_delta: Token expiration time delta

        Returns:
            str: Encoded JWT refresh token
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=settings.refresh_token_expire_days
            )

        to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "type": "refresh"})
        encoded_jwt = jwt.encode(
            to_encode,
            settings.secret_key,
            algorithm=settings.algorithm,
        )
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        """Verify and decode a JWT token.

        Args:
            token: JWT token to verify

        Returns:
            Dict: Decoded token payload

        Raises:
            JWTError: If token is invalid or expired
        """
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
        )
        return payload


class PasswordManager:
    """Manages password hashing and verification."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a plaintext password.

        Args:
            password: Plaintext password

        Returns:
            str: Hashed password
        """
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a plaintext password against a hash.

        Args:
            plain_password: Plaintext password
            hashed_password: Hashed password to verify against

        Returns:
            bool: True if password matches, False otherwise
        """
        return pwd_context.verify(plain_password, hashed_password)


class EncryptionManager:
    """Manages AES-256 encryption and decryption of sensitive data."""

    def __init__(self):
        """Initialize encryption manager with key from settings."""
        self.key = base64.b64decode(settings.encryption_key)
        if len(self.key) != 32:
            raise ValueError("Encryption key must be 32 bytes (256 bits) when decoded")

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using AES-256-CBC.

        Args:
            plaintext: Text to encrypt

        Returns:
            str: Base64-encoded ciphertext with IV prepended
        """
        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        plaintext_bytes = plaintext.encode()
        padding_length = 16 - (len(plaintext_bytes) % 16)
        padded_plaintext = plaintext_bytes + bytes([padding_length]) * padding_length

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt AES-256-CBC ciphertext.

        Args:
            encrypted_data: Base64-encoded ciphertext with IV prepended

        Returns:
            str: Decrypted plaintext

        Raises:
            ValueError: If decryption fails
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)

            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]

            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()

            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            padding_length = padded_plaintext[-1]
            plaintext = padded_plaintext[:-padding_length]

            return plaintext.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
