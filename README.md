# Hybrid Encryption File Transfer Protocol

An INS project implementation of hybrid file encryption using AES-256-GCM and RSA-3072-OAEP with SHA-256.

## Security design

1. The sender generates a fresh 256-bit AES session key and a unique 96-bit GCM nonce for each file.
2. AES-GCM encrypts the file and authenticates its canonical metadata as associated data.
3. RSA-OAEP-SHA256 encrypts the AES session key for the recipient.
4. An HMAC-SHA256 over metadata is also included to satisfy the separate integrity module requirement.
5. The receiver verifies the header HMAC and the AES-GCM tag before returning any plaintext.

The binary transport payload is length-prefixed and contains the encrypted key, 12-byte IV, 16-byte GCM tag, JSON metadata, 32-byte header HMAC, and ciphertext. `send_bundle` and `receive_bundle` implement socket framing with a maximum receive size.

## Run

Install Python 3.10+ and dependencies, then use:

```powershell
python -m pip install -r requirements.txt
python main.py run
python main.py generate-keys
python main.py encrypt storage/input_files/example.txt encrypted_bundle.json --sender alice
python main.py decrypt encrypted_bundle.json storage/output_files/example.txt
python -m pytest
```

For the live dashboard, start the local server and open `http://127.0.0.1:5000`:

```powershell
python -m flask --app web_app run
```

Opening [dashboard.html](dashboard.html) directly still works as a static preview, but it cannot load live key metadata or record audit events.

Private keys are stored as passphrase-encrypted PKCS#8 PEM files. A unique salt and PBKDF2-HMAC-SHA256 (600,000 iterations) derive the PEM encryption password; the salt and KDF parameters are held in non-secret metadata. Metadata also tracks creation, expiration, and revocation; an expired key can be rotated through `KeyManager.rotate_if_expired`.

## Security note

This RSA key-wrapping design gives each transfer a separate AES session key, but it does **not** provide forward secrecy: a recipient private-key compromise can decrypt previously captured bundles. For forward secrecy, replace RSA-OAEP wrapping with an authenticated ephemeral X25519 key agreement and an HKDF-derived AES key, while retaining AES-GCM for the payload.
