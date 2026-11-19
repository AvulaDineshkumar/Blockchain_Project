"""Participants of the network (patients, hospitals, doctors, insurers, auditor, admin)."""
from .crypto import BoxKey, SigningKey, decrypt, unwrap_key, sha256_hex
from .ledger import make_tx
from cryptography.exceptions import InvalidTag


class Actor:
    def __init__(self, aid, role, name=""):
        self.id, self.role, self.name = aid, role, name
        self.sk = SigningKey()
        self.bk = BoxKey()
        self._nonce = 0

    def tx(self, ttype, payload, ts):
        self._nonce += 1
        return make_tx(self.sk, self.id, ttype, payload, ts, self._nonce)

    def register_payload(self):
        # patients are pseudonymous on the ledger (ID only); organisations and clinicians keep public names
        return {"id": self.id, "role": self.role, "name": "" if self.role == "patient" else self.name,
                "sign_pub": self.sk.public_hex, "box_pub": self.bk.public_hex}

    def open_response(self, response):
        """Decrypt a file served by the off-chain store and compare its SHA-256 with the
        hash the blockchain holds. Returns (status, plaintext_or_None)."""
        try:
            key = unwrap_key(self.bk, response["wrapped_key"])
            plain = decrypt(key, response["ciphertext"])
        except InvalidTag:
            return "TAMPERED_CIPHERTEXT", None
        except (KeyError, ValueError):
            return "BAD_RESPONSE", None
        if sha256_hex(plain) != response["expected_hash"]:
            return "HASH_MISMATCH", plain
        return "OK", plain
