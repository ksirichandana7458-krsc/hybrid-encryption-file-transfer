"""RSA-OAEP session-key wrapping for the hybrid encryption protocol."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


def encrypt_session_key(session_key: bytes, recipient_public_key) -> bytes:
    if len(session_key) != 32:
        raise ValueError("only 256-bit AES session keys may be wrapped")
    return recipient_public_key.encrypt(session_key, _OAEP)


def decrypt_session_key(encrypted_session_key: bytes, recipient_private_key) -> bytes:
    session_key = recipient_private_key.decrypt(encrypted_session_key, _OAEP)
    if len(session_key) != 32:
        raise ValueError("decrypted session key is not a valid AES-256 key")
    return session_key
