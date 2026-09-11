"""RSA key generation, encrypted PEM storage, lifecycle, and revocation checks."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class KeyStatusError(ValueError):
    """Raised when a key cannot be used due to expiry or revocation."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _storage_password(passphrase: str, salt: bytes) -> bytes:
    """Derive a PEM-encryption password with PBKDF2-HMAC-SHA256."""
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000
    ).derive(passphrase.encode("utf-8"))


class KeyManager:
    """Manage RSA-3072 recipient keys and their JSON lifecycle metadata."""

    def __init__(self, key_directory: str | Path, lifetime_days: int = 30):
        self.key_directory = Path(key_directory)
        self.private_key_path = self.key_directory / "private_key.pem"
        self.public_key_path = self.key_directory / "public_key.pem"
        self.metadata_path = self.key_directory / "key_metadata.json"
        self.lifetime_days = lifetime_days

    @staticmethod
    def generate_rsa_keypair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        return private_key, private_key.public_key()

    def generate_and_store(self, passphrase: str) -> dict:
        if not passphrase:
            raise ValueError("a non-empty passphrase is required to encrypt the private key")
        self.key_directory.mkdir(parents=True, exist_ok=True)
        private_key, public_key = self.generate_rsa_keypair()
        salt = os.urandom(16)
        private_bytes = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(_storage_password(passphrase, salt)),
        )
        public_bytes = public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.private_key_path.write_bytes(private_bytes)
        self.public_key_path.write_bytes(public_bytes)
        created_at = _utc_now()
        metadata = {
            "key_id": hashlib.sha256(public_bytes).hexdigest()[:16],
            "algorithm": "RSA-3072-OAEP-SHA256",
            "created_at": created_at.isoformat(),
            "expires_at": (created_at + timedelta(days=self.lifetime_days)).isoformat(),
            "revoked": False,
            "private_key_kdf": {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": 600000,
                "salt": salt.hex(),
            },
        }
        self.metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        return metadata

    def load_private_key(self, passphrase: str):
        self.assert_usable()
        metadata = self.metadata()
        kdf = metadata.get("private_key_kdf", {})
        if kdf.get("algorithm") != "PBKDF2-HMAC-SHA256":
            raise KeyStatusError("private-key KDF metadata is missing or unsupported")
        return serialization.load_pem_private_key(
            self.private_key_path.read_bytes(), password=_storage_password(passphrase, bytes.fromhex(kdf["salt"]))
        )

    def load_public_key(self):
        self.assert_usable()
        return serialization.load_pem_public_key(self.public_key_path.read_bytes())

    def metadata(self) -> dict:
        return json.loads(self.metadata_path.read_text(encoding="utf-8"))

    def assert_usable(self) -> None:
        metadata = self.metadata()
        if metadata.get("revoked"):
            raise KeyStatusError("recipient key is revoked")
        if _utc_now() >= datetime.fromisoformat(metadata["expires_at"]):
            raise KeyStatusError("recipient key has expired and must be rotated")

    def revoke(self) -> None:
        metadata = self.metadata()
        metadata["revoked"] = True
        self.metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    def rotate_if_expired(self, passphrase: str) -> dict | None:
        try:
            self.assert_usable()
        except KeyStatusError as error:
            if "expired" not in str(error):
                raise
            return self.generate_and_store(passphrase)
        return None
