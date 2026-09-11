"""HMAC-SHA256 helpers for authenticated transfer metadata."""

from __future__ import annotations

import hmac
import json
from hashlib import sha256
from typing import Mapping


def canonical_metadata(metadata: Mapping[str, object]) -> bytes:
    """Return a stable, unambiguous representation used as AES-GCM AAD."""
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_header_hmac(session_key: bytes, metadata: Mapping[str, object]) -> bytes:
    """Authenticate metadata with a session-key-bound HMAC-SHA256 value."""
    return hmac.new(session_key, canonical_metadata(metadata), sha256).digest()


def verify_header_hmac(session_key: bytes, metadata: Mapping[str, object], tag: bytes) -> bool:
    return hmac.compare_digest(compute_header_hmac(session_key, metadata), tag)
