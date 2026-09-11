"""Bundle construction and length-prefixed socket transport for encrypted files."""

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from .asymmetric_cipher import decrypt_session_key, encrypt_session_key
from .hash_integrity import canonical_metadata, compute_header_hmac, verify_header_hmac
from .symmetric_cipher import IntegrityError, decrypt as aes_decrypt, encrypt as aes_encrypt, generate_session_key


class ProtocolError(ValueError):
    """Raised when a received bundle is malformed or has unauthenticated metadata."""


@dataclass(frozen=True)
class EncryptedBundle:
    encrypted_key: bytes
    nonce: bytes
    tag: bytes
    ciphertext: bytes
    metadata: dict
    header_hmac: bytes

    def to_dict(self) -> dict:
        return {
            "encrypted_key": self.encrypted_key.hex(), "iv": self.nonce.hex(), "tag": self.tag.hex(),
            "ciphertext": self.ciphertext.hex(), "metadata": self.metadata, "header_hmac": self.header_hmac.hex(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EncryptedBundle":
        try:
            metadata = value["metadata"]
            if not isinstance(metadata, dict):
                raise TypeError("metadata must be an object")
            return cls(
                encrypted_key=bytes.fromhex(str(value["encrypted_key"])), nonce=bytes.fromhex(str(value["iv"])),
                tag=bytes.fromhex(str(value["tag"])), ciphertext=bytes.fromhex(str(value["ciphertext"])),
                metadata=metadata, header_hmac=bytes.fromhex(str(value["header_hmac"])),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ProtocolError("invalid encrypted bundle") from error


def encrypt_file(
    file_data: bytes, recipient_public_key, filename: str = "payload.bin", sender: str = "sender"
) -> EncryptedBundle:
    metadata = {"filename": filename, "sender": sender, "timestamp": datetime.now(timezone.utc).isoformat(), "version": 1}
    session_key = generate_session_key()
    protected = aes_encrypt(file_data, session_key, canonical_metadata(metadata))
    return EncryptedBundle(
        encrypted_key=encrypt_session_key(session_key, recipient_public_key), nonce=protected.nonce,
        tag=protected.tag, ciphertext=protected.ciphertext, metadata=metadata,
        header_hmac=compute_header_hmac(session_key, metadata),
    )


def decrypt_file(bundle: EncryptedBundle | Mapping[str, object], recipient_private_key) -> bytes:
    if not isinstance(bundle, EncryptedBundle):
        bundle = EncryptedBundle.from_dict(bundle)
    session_key = decrypt_session_key(bundle.encrypted_key, recipient_private_key)
    if not verify_header_hmac(session_key, bundle.metadata, bundle.header_hmac):
        raise IntegrityError("header HMAC verification failed; metadata may be tampered")
    return aes_decrypt(bundle.nonce, bundle.ciphertext, bundle.tag, session_key, canonical_metadata(bundle.metadata))


def encode_bundle(bundle: EncryptedBundle) -> bytes:
    """Encode `[key length|key|IV|tag|metadata length|metadata|HMAC|ciphertext]`."""
    metadata = json.dumps(bundle.metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(bundle.encrypted_key) > 65535 or len(metadata) > 65535:
        raise ProtocolError("bundle component exceeds protocol length field")
    return b"".join((struct.pack("!H", len(bundle.encrypted_key)), bundle.encrypted_key, bundle.nonce,
                     bundle.tag, struct.pack("!H", len(metadata)), metadata, bundle.header_hmac, bundle.ciphertext))


def decode_bundle(payload: bytes) -> EncryptedBundle:
    if len(payload) < 2 + 12 + 16 + 2 + 32:
        raise ProtocolError("bundle is too short")
    key_length = struct.unpack("!H", payload[:2])[0]
    cursor = 2
    minimum = cursor + key_length + 12 + 16 + 2 + 32
    if len(payload) < minimum:
        raise ProtocolError("truncated encrypted key or header")
    encrypted_key = payload[cursor:cursor + key_length]
    cursor += key_length
    nonce, tag = payload[cursor:cursor + 12], payload[cursor + 12:cursor + 28]
    cursor += 28
    metadata_length = struct.unpack("!H", payload[cursor:cursor + 2])[0]
    cursor += 2
    if len(payload) < cursor + metadata_length + 32:
        raise ProtocolError("truncated metadata or header HMAC")
    try:
        metadata = json.loads(payload[cursor:cursor + metadata_length].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("invalid metadata encoding") from error
    cursor += metadata_length
    header_hmac = payload[cursor:cursor + 32]
    cursor += 32
    if not isinstance(metadata, dict):
        raise ProtocolError("metadata must be a JSON object")
    return EncryptedBundle(encrypted_key, nonce, tag, payload[cursor:], metadata, header_hmac)


def send_bundle(connection: socket.socket, bundle: EncryptedBundle) -> None:
    payload = encode_bundle(bundle)
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def receive_bundle(connection: socket.socket, maximum_size: int = 100 * 1024 * 1024) -> EncryptedBundle:
    def receive_exactly(size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = connection.recv(size - len(result))
            if not chunk:
                raise ProtocolError("connection closed before complete bundle was received")
            result.extend(chunk)
        return bytes(result)

    size = struct.unpack("!I", receive_exactly(4))[0]
    if size > maximum_size:
        raise ProtocolError("bundle exceeds configured maximum size")
    return decode_bundle(receive_exactly(size))
