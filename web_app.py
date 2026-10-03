"""Local web dashboard for the hybrid encryption file-transfer project."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from src.client_server_protocol import decrypt_file, encrypt_file
from src.key_management import KeyManager, KeyStatusError
from src.symmetric_cipher import IntegrityError

ROOT = Path(__file__).resolve().parent
STORAGE = ROOT / "storage"
KEYS = ROOT / "keys"
AUDIT_LOG = STORAGE / "audit_log.json"
TRANSFER_HISTORY = STORAGE / "transfer_history.json"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


def _read_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _append_entry(path: Path, entry: dict) -> None:
    STORAGE.mkdir(exist_ok=True)
    entries = _read_entries(path)
    entries.insert(0, entry)
    path.write_text(json.dumps(entries[:50], indent=2) + "\n", encoding="utf-8")


def _key_status() -> dict:
    manager = KeyManager(KEYS)
    if not manager.metadata_path.exists():
        return {"state": "No key", "detail": "Generate recipient keys with main.py generate-keys."}
    try:
        metadata = manager.metadata()
        manager.assert_usable()
        return {
            "state": "Active",
            "detail": f"RSA-3072 key {metadata['key_id']}",
            "key_id": metadata["key_id"],
            "expires_at": metadata["expires_at"],
        }
    except KeyStatusError as error:
        return {"state": "Unavailable", "detail": str(error)}


def _event(case: str, outcome: str, title: str, detail: str, warning: bool, steps: list[str], filename: str) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = {
        "case": case,
        "outcome": outcome,
        "title": title,
        "detail": detail,
        "warning": warning,
        "steps": steps,
        "timestamp": timestamp,
        "filename": filename,
    }
    _append_entry(AUDIT_LOG, entry)
    _append_entry(TRANSFER_HISTORY, {**entry, "sender": "dashboard"})
    return entry


def _run_case(case: str, payload: bytes, filename: str) -> dict:
    private_key, public_key = KeyManager.generate_rsa_keypair()
    bundle = encrypt_file(payload, public_key, filename, "dashboard")

    if case == "success":
        plaintext = decrypt_file(bundle, private_key)
        assert plaintext == payload
        output_directory = STORAGE / "output_files"
        output_directory.mkdir(parents=True, exist_ok=True)
        output_path = output_directory / f"received_{filename}"
        output_path.write_bytes(plaintext)
        return _event(case, "Verified", "Bundle authenticated and decrypted",
                      f"The selected file was authenticated and saved as {output_path.name}.", False,
                      ["Session key encrypted with recipient RSA public key", "Header HMAC-SHA256 verified", "Payload decrypted after AES-GCM tag validation"], filename)

    tampered = bundle.to_dict()
    if case == "ciphertext":
        modified = bytearray(bytes.fromhex(tampered["ciphertext"]))
        modified[0] ^= 1
        tampered["ciphertext"] = modified.hex()
        expected_error = "AES-GCM authentication failed"
        title = "Ciphertext modification was blocked"
        detail = "The AES-GCM authentication tag rejected the altered payload. No plaintext was returned."
        steps = ["Session key recovered with recipient RSA private key", "Header HMAC-SHA256 verified", "AES-GCM tag failed; plaintext withheld"]
    elif case == "metadata":
        tampered["metadata"]["filename"] = "renamed_paper.txt"
        expected_error = "header HMAC verification failed"
        title = "Metadata modification was blocked"
        detail = "The HMAC-SHA256 header check rejected the altered file name before payload decryption."
        steps = ["Session key recovered with recipient RSA private key", "Header HMAC-SHA256 failed", "Payload decryption skipped; output withheld"]
    elif case == "expired":
        with tempfile.TemporaryDirectory() as temporary_directory:
            manager = KeyManager(temporary_directory)
            manager.generate_and_store("dashboard-passphrase")
            metadata = manager.metadata()
            metadata["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            manager.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            try:
                manager.assert_usable()
            except KeyStatusError:
                return _event(case, "Stopped", "Transfer requires key rotation",
                              "The lifecycle check rejected the expired recipient key before a session key could be wrapped.", True,
                              ["Recipient key lifetime checked", "Key expiration detected", "Session-key wrapping prevented; rotate key"], filename)
        raise RuntimeError("expired-key case did not trigger")
    else:
        raise ValueError("unsupported case")

    try:
        decrypt_file(tampered, private_key)
    except IntegrityError as error:
        if expected_error not in str(error):
            raise
        return _event(case, "Rejected", title, detail, True, steps, filename)
    raise RuntimeError("tampered bundle unexpectedly decrypted")


@app.get("/")
def dashboard():
    return send_from_directory(ROOT, "dashboard.html")


@app.get("/api/dashboard")
def dashboard_data():
    return jsonify({"key": _key_status(), "audit": _read_entries(AUDIT_LOG), "transfers": _read_entries(TRANSFER_HISTORY)})


@app.post("/api/cases")
def run_case():
    payload = request.get_json(silent=True) or {}
    uploaded_file = request.files.get("file")
    case = request.form.get("case") or payload.get("case")
    if case not in {"success", "ciphertext", "metadata", "expired"}:
        return jsonify({"error": "choose a supported transfer case"}), 400
    try:
        file_data = uploaded_file.read() if uploaded_file and uploaded_file.filename else b"Dashboard transfer payload: hybrid encryption verification."
        filename = Path(uploaded_file.filename).name if uploaded_file and uploaded_file.filename else "exam_paper.txt"
        return jsonify(_run_case(case, file_data, filename))
    except Exception:
        app.logger.exception("dashboard case failed")
        return jsonify({"error": "protocol case could not be completed"}), 500


if __name__ == "__main__":
    app.run(debug=True)
