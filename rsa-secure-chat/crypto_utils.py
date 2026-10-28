"""Hybrid encryption helpers: RSA-OAEP (key wrap) + AES-256-GCM (message)."""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 2048


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generate_keypair():
    """Return (private_pem, public_pem) as strings."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def encrypt_message(public_pem: str, plaintext: str) -> dict:
    """Encrypt with a fresh AES key, then wrap that key with the receiver's RSA key."""
    public_key = serialization.load_pem_public_key(public_pem.encode())
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    wrapped_key = public_key.encrypt(aes_key, _oaep())
    b64 = lambda b: base64.b64encode(b).decode()
    return {"enc_key": b64(wrapped_key), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}


def decrypt_message(private_pem: str, enc_key: str, nonce: str, ciphertext: str) -> str:
    """Raises ValueError on any failure (wrong key, tampering, bad key format)."""
    try:
        private_key = serialization.load_pem_private_key(private_pem.strip().encode(), password=None)
        aes_key = private_key.decrypt(base64.b64decode(enc_key), _oaep())
        plain = AESGCM(aes_key).decrypt(base64.b64decode(nonce), base64.b64decode(ciphertext), None)
        return plain.decode("utf-8")
    except (ValueError, InvalidTag, TypeError) as exc:
        raise ValueError("Decryption failed") from exc
