import json
from datetime import datetime, timedelta, timezone

import pytest

from src.key_management import KeyManager, KeyStatusError


def test_expired_key_is_rotated(tmp_path):
    manager = KeyManager(tmp_path, lifetime_days=30)
    original = manager.generate_and_store("test-passphrase")
    metadata = manager.metadata()
    metadata["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    manager.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(KeyStatusError, match="expired"):
        manager.load_public_key()
    replacement = manager.rotate_if_expired("test-passphrase")
    assert replacement is not None
    assert replacement["key_id"] != original["key_id"]
    manager.load_public_key()
