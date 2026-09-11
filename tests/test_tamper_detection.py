import pytest

from src.client_server_protocol import decode_bundle, decrypt_file, encode_bundle, encrypt_file
from src.key_management import KeyManager
from src.symmetric_cipher import IntegrityError


@pytest.fixture
def keys():
    return KeyManager.generate_rsa_keypair()


def test_ciphertext_tampering_is_rejected(keys):
    private_key, public_key = keys
    bundle = encrypt_file(b"classified", public_key)
    tampered = bundle.to_dict()
    ciphertext = bytearray(bytes.fromhex(tampered["ciphertext"]))
    ciphertext[0] ^= 1
    tampered["ciphertext"] = ciphertext.hex()
    with pytest.raises(IntegrityError, match="AES-GCM"):
        decrypt_file(tampered, private_key)


def test_metadata_tampering_is_rejected(keys):
    private_key, public_key = keys
    tampered = encrypt_file(b"classified", public_key).to_dict()
    tampered["metadata"]["filename"] = "substituted.txt"
    with pytest.raises(IntegrityError, match="header HMAC"):
        decrypt_file(tampered, private_key)


def test_binary_transport_round_trip(keys):
    private_key, public_key = keys
    bundle = encrypt_file(b"framed payload", public_key, "report.txt", "alice")
    received = decode_bundle(encode_bundle(bundle))
    assert decrypt_file(received, private_key) == b"framed payload"
    assert received.metadata["filename"] == "report.txt"
