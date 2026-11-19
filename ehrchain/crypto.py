"""Cryptographic helpers.

SHA-256        : integrity fingerprints (hashlib)
Ed25519        : digital signatures for identities, transactions and consensus votes
X25519 + HKDF  : wrapping a file key for one recipient
AES-256-GCM    : authenticated encryption of medical files (stored off-chain)
"""
import hashlib
import json
import os
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(chunk), b""):
            h.update(part)
    return h.hexdigest()


def canon(obj) -> bytes:
    """Canonical JSON bytes (stable key order) - what we hash and sign."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class SigningKey:
    """Ed25519 identity key."""

    def __init__(self):
        self._priv = Ed25519PrivateKey.generate()
        self.public_hex = self._priv.public_key().public_bytes(**_RAW).hex()

    def sign(self, data: bytes) -> str:
        return self._priv.sign(data).hex()

    def private_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization as _s
        return self._priv.private_bytes(_s.Encoding.Raw, _s.PrivateFormat.Raw, _s.NoEncryption()).hex()

    @classmethod
    def from_private_hex(cls, h):
        obj = cls.__new__(cls)
        obj._priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(h))
        obj.public_hex = obj._priv.public_key().public_bytes(**_RAW).hex()
        return obj


@lru_cache(maxsize=8192)
def _pub(pub_hex):
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))


def verify(pub_hex: str, data: bytes, sig_hex: str) -> bool:
    try:
        _pub(pub_hex).verify(bytes.fromhex(sig_hex), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class BoxKey:
    """X25519 key used to receive wrapped file keys."""

    def __init__(self):
        self._priv = X25519PrivateKey.generate()
        self.public_hex = self._priv.public_key().public_bytes(**_RAW).hex()

    def exchange(self, peer_pub_hex: str) -> bytes:
        return self._priv.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex)))


def _kek(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ehrchain-keywrap").derive(shared)


def wrap_key(file_key: bytes, recipient_box_pub_hex: str) -> dict:
    eph = BoxKey()
    nonce = os.urandom(12)
    ct = AESGCM(_kek(eph.exchange(recipient_box_pub_hex))).encrypt(nonce, file_key, None)
    return {"eph": eph.public_hex, "nonce": nonce.hex(), "ct": ct.hex()}


def unwrap_key(box: BoxKey, wrapped: dict) -> bytes:
    kek = _kek(box.exchange(wrapped["eph"]))
    return AESGCM(kek).decrypt(bytes.fromhex(wrapped["nonce"]), bytes.fromhex(wrapped["ct"]), None)


def encrypt(plaintext: bytes):
    """AES-256-GCM. Returns (key, blob) where blob = nonce(12) + ciphertext+tag."""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return key, nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt(key: bytes, blob: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if the blob was modified."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)
