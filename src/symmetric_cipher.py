"""AES-256-GCM authenticated encryption operations."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class IntegrityError(ValueError):
    """Raised when AES-GCM authentication fails."""


@dataclass(frozen=True)
class GCMCiphertext:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def generate_session_key() -> bytes:
    """Create a one-use 256-bit AES key from the operating system CSPRNG."""
    return os.urandom(32)


def encrypt(plaintext: bytes, session_key: bytes, associated_data: bytes) -> GCMCiphertext:
    if len(session_key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte session key")
    nonce = os.urandom(12)
    encrypted = AESGCM(session_key).encrypt(nonce, plaintext, associated_data)
    return GCMCiphertext(nonce=nonce, ciphertext=encrypted[:-16], tag=encrypted[-16:])


def decrypt(
    nonce: bytes, ciphertext: bytes, tag: bytes, session_key: bytes, associated_data: bytes
) -> bytes:
    if len(nonce) != 12 or len(tag) != 16:
        raise IntegrityError("invalid AES-GCM nonce or authentication-tag length")
    try:
        return AESGCM(session_key).decrypt(nonce, ciphertext + tag, associated_data)
    except InvalidTag as error:
        raise IntegrityError("AES-GCM authentication failed; bundle may be tampered") from error
