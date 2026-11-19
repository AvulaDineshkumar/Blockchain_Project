"""Off-chain encrypted file store plus the access gateway.

The store only ever holds AES-256-GCM ciphertext and file keys wrapped to the custodian
hospital. A file key is re-wrapped for a requester ONLY if the ledger holds a committed
REQUEST_ACCESS transaction from that requester for that record whose contract result is
GRANTED:*. So the blockchain, not the store operator, decides who may read.
"""
import os
import tempfile

from .crypto import encrypt, sha256_hex, unwrap_key, wrap_key


class OffChainStore:
    def __init__(self, root=None, in_memory=False):
        self.in_memory = in_memory
        self.root = root or (None if in_memory else tempfile.mkdtemp(prefix="ehr_store_"))
        self._mem = {}
        self.meta = {}     # record_id -> {custodian, wrapped_key, hash, size}

    # -- hospital side -------------------------------------------------------------------
    def put(self, record_id, plaintext, custodian):
        """Encrypt `plaintext` for storage. Returns the SHA-256 of the PLAINTEXT, which is
        what goes on-chain."""
        h = sha256_hex(plaintext)
        key, blob = encrypt(plaintext)
        self.meta[record_id] = {"custodian": custodian.id, "hash": h, "size": len(plaintext),
                                "wrapped_key": wrap_key(key, custodian.bk.public_hex)}
        if self.in_memory:
            self._mem[record_id] = blob
        else:
            with open(os.path.join(self.root, record_id + ".enc"), "wb") as f:
                f.write(blob)
        return h

    def _blob(self, record_id):
        if self.in_memory:
            return self._mem[record_id]
        with open(os.path.join(self.root, record_id + ".enc"), "rb") as f:
            return f.read()

    # -- gateway -------------------------------------------------------------------------
    def serve(self, tx_id, requester_id, requester_box_pub, ledger, actors):
        """Return the encrypted file to a requester IF the ledger authorised it."""
        found = ledger.lookup(tx_id)
        if found is None:
            return {"error": "NOT_ON_LEDGER"}
        _, tx, result = found
        if tx["type"] != "REQUEST_ACCESS" or tx["sender"] != requester_id:
            return {"error": "TX_DOES_NOT_MATCH_REQUESTER"}
        if not result.startswith("GRANTED"):
            return {"error": result}
        rid = tx["payload"]["record_id"]
        m = self.meta.get(rid)
        if m is None:
            return {"error": "NO_FILE"}
        custodian = actors[m["custodian"]]
        file_key = unwrap_key(custodian.bk, m["wrapped_key"])
        return {"ciphertext": self._blob(rid), "wrapped_key": wrap_key(file_key, requester_box_pub),
                "expected_hash": ledger.state.records[rid]["file_hash"], "grant": result}

    # -- attack hooks used by the experiments ------------------------------------------
    def tamper_ciphertext(self, record_id, offset=100):
        blob = bytearray(self._blob(record_id))
        blob[min(offset, len(blob) - 1)] ^= 0x01
        if self.in_memory:
            self._mem[record_id] = bytes(blob)
        else:
            with open(os.path.join(self.root, record_id + ".enc"), "wb") as f:
                f.write(bytes(blob))

    def replace_file_consistently(self, record_id, new_plaintext, custodian):
        """Insider attack: swap the stored file for a different, properly encrypted one.
        The ciphertext is valid and decrypts fine; only the on-chain hash can reveal it."""
        key, blob = encrypt(new_plaintext)
        self.meta[record_id]["wrapped_key"] = wrap_key(key, custodian.bk.public_hex)
        if self.in_memory:
            self._mem[record_id] = blob
        else:
            with open(os.path.join(self.root, record_id + ".enc"), "wb") as f:
                f.write(blob)

    def disk_bytes(self):
        if self.in_memory:
            return sum(len(b) for b in self._mem.values())
        return sum(os.path.getsize(os.path.join(self.root, f)) for f in os.listdir(self.root))
