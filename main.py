"""Command-line entry point for the hybrid encryption file-transfer demo."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from src.client_server_protocol import EncryptedBundle, decrypt_file, encrypt_file
from src.key_management import KeyManager
from src.symmetric_cipher import IntegrityError

ROOT = Path(__file__).resolve().parent
KEYS = ROOT / "keys"
INPUT = ROOT / "storage" / "input_files"
OUTPUT = ROOT / "storage" / "output_files"


def passphrase(prompt: str) -> str:
    return getpass.getpass(prompt)


def cmd_generate_keys(_: argparse.Namespace) -> None:
    metadata = KeyManager(KEYS).generate_and_store(passphrase("Private-key passphrase: "))
    print(f"Generated {metadata['algorithm']} key {metadata['key_id']}; expires {metadata['expires_at']}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    manager = KeyManager(KEYS)
    bundle = encrypt_file(args.input.read_bytes(), manager.load_public_key(), args.input.name, args.sender)
    args.bundle.write_text(__import__("json").dumps(bundle.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(f"Encrypted {args.input.name} to {args.bundle}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    manager = KeyManager(KEYS)
    bundle = EncryptedBundle.from_dict(__import__("json").loads(args.bundle.read_text(encoding="utf-8")))
    args.output.write_bytes(decrypt_file(bundle, manager.load_private_key(passphrase("Private-key passphrase: "))))
    print(f"Authenticated and decrypted file written to {args.output}")


def cmd_demo(_: argparse.Namespace) -> None:
    private_key, public_key = KeyManager.generate_rsa_keypair()
    payload = b"CONFIDENTIAL: INS Lab End-Semester Exam Paper & Solution Key."
    bundle = encrypt_file(payload, public_key, "exam_paper.txt", "INS-demo")
    print("=== INS HYBRID CRYPTOSYSTEM DEMO ===")
    print(f"Original data: {payload.decode()}")
    print(f"AES-GCM ciphertext: {bundle.ciphertext.hex()[:30]}...")
    print(f"RSA-encrypted session key: {bundle.encrypted_key.hex()[:30]}...")
    print(f"Decrypted output: {decrypt_file(bundle, private_key).decode()}")
    tampered = bundle.to_dict()
    altered = bytearray(bytes.fromhex(tampered["ciphertext"]))
    altered[0] ^= 1
    tampered["ciphertext"] = altered.hex()
    try:
        decrypt_file(tampered, private_key)
    except IntegrityError as error:
        print(f"Security alert triggered: {error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AES-256-GCM + RSA-3072 hybrid file encryption")
    commands = parser.add_subparsers(required=True)
    generate = commands.add_parser("generate-keys")
    generate.set_defaults(handler=cmd_generate_keys)
    encrypt = commands.add_parser("encrypt")
    encrypt.add_argument("input", type=Path)
    encrypt.add_argument("bundle", type=Path)
    encrypt.add_argument("--sender", default="sender")
    encrypt.set_defaults(handler=cmd_encrypt)
    decrypt = commands.add_parser("decrypt")
    decrypt.add_argument("bundle", type=Path)
    decrypt.add_argument("output", type=Path)
    decrypt.set_defaults(handler=cmd_decrypt)
    demo = commands.add_parser("demo")
    demo.set_defaults(handler=cmd_demo)
    return parser


if __name__ == "__main__":
    INPUT.mkdir(parents=True, exist_ok=True)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    arguments = build_parser().parse_args()
    arguments.handler(arguments)
