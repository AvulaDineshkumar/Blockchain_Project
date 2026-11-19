"""Smart contract: identity registry, record registry, consent and access policy.

Every validator runs exactly this code on exactly the same inputs, so every honest node
computes the same result string for every transaction. Denied requests are NOT dropped:
they are written to the ledger with a DENIED:<reason> result, i.e. they become auditable
security events.
"""
_MISSING = object()
ROLES = ("patient", "hospital", "doctor", "insurer", "auditor")
INSURER_KIND = "FHIR_INS"   # the only data kind an insurer may ever receive (billing/coverage view)


class State:
    def __init__(self, admin_pub: str):
        self.admin_pub = admin_pub
        self.identities = {}   # id -> {role, name, sign_pub, box_pub}
        self.records = {}      # record_id -> {patient, hospital, kind, file_hash, size, added}
        self.consents = {}     # (patient, grantee) -> tuple of consent dicts
        self.nodes = {}        # validator id -> {operator (hospital id), node_pub}
        self.seen = {}         # tx_id -> True (replay protection)
        self._journal = None

    # ---- journaling so a proposed block can be executed and rolled back --------------
    def begin(self):
        self._journal = []

    def commit(self):
        self._journal = None

    def rollback(self):
        if self._journal is None:
            return
        for d, k, old in reversed(self._journal):
            if old is _MISSING:
                d.pop(k, None)
            else:
                d[k] = old
        self._journal = None

    def _set(self, d, k, v):
        if self._journal is not None:
            self._journal.append((d, k, d.get(k, _MISSING)))
        d[k] = v

    # ---- execution -------------------------------------------------------------------
    def execute(self, tx: dict, now: float) -> str:
        tid = tx["tx_id"]
        if tid in self.seen:
            return "DENIED:REPLAY"
        self._set(self.seen, tid, True)
        fn = {
            "REGISTER": self._register,
            "ASSIGN_NODE": self._assign_node,
            "ADD_RECORD": self._add_record,
            "GRANT_CONSENT": self._grant,
            "REVOKE_CONSENT": self._revoke,
            "REQUEST_ACCESS": self._request_access,
        }.get(tx["type"])
        if fn is None:
            return "DENIED:UNKNOWN_TYPE"
        try:
            return fn(tx, tx["payload"], now)
        except (KeyError, TypeError, ValueError):
            return "DENIED:MALFORMED"

    def _who(self, tx):
        ident = self.identities.get(tx["sender"])
        if ident is None or ident["sign_pub"] != tx["sender_pub"]:
            return None
        return ident

    def _register(self, tx, p, now):
        if tx["sender"] != "admin" or tx["sender_pub"] != self.admin_pub:
            return "DENIED:NOT_ADMIN"
        if p["role"] not in ROLES:
            return "DENIED:BAD_ROLE"
        if not p["id"] or p["id"] in self.identities:
            return "DENIED:DUPLICATE_ID"
        self._set(self.identities, p["id"], {"role": p["role"], "name": p.get("name", ""),
                                             "sign_pub": p["sign_pub"], "box_pub": p["box_pub"]})
        return "OK"

    def _assign_node(self, tx, p, now):
        """Admin records which registered hospital operates which validator node."""
        if tx["sender"] != "admin" or tx["sender_pub"] != self.admin_pub:
            return "DENIED:NOT_ADMIN"
        op = self.identities.get(p["operator"])
        if op is None or op["role"] != "hospital":
            return "DENIED:OPERATOR_NOT_HOSPITAL"
        if p["node"] in self.nodes:
            return "DENIED:NODE_ALREADY_ASSIGNED"
        self._set(self.nodes, p["node"], {"operator": p["operator"], "node_pub": p["node_pub"]})
        return "OK"

    def _add_record(self, tx, p, now):
        me = self._who(tx)
        if me is None:
            return "DENIED:UNREGISTERED"
        if me["role"] != "hospital":
            return "DENIED:NOT_HOSPITAL"
        patient = self.identities.get(p["patient_id"])
        if patient is None or patient["role"] != "patient":
            return "DENIED:NO_SUCH_PATIENT"
        if p["record_id"] in self.records:
            return "DENIED:DUPLICATE_RECORD"
        self._set(self.records, p["record_id"], {
            "patient": p["patient_id"], "hospital": tx["sender"], "kind": p["kind"],
            "file_hash": p["file_hash"], "size": p.get("size", 0), "added": now})
        return "OK"

    def _grant(self, tx, p, now):
        me = self._who(tx)
        if me is None:
            return "DENIED:UNREGISTERED"
        if me["role"] != "patient":
            return "DENIED:NOT_PATIENT"
        if p["grantee"] not in self.identities:
            return "DENIED:UNKNOWN_GRANTEE"
        if self.identities[p["grantee"]]["role"] == "insurer" and any(k != INSURER_KIND for k in p["kinds"]):
            return "DENIED:INSURER_POLICY"
        rid = p["record_id"]
        if rid != "*" and self.records.get(rid, {}).get("patient") != tx["sender"]:
            return "DENIED:NOT_YOUR_RECORD"
        key = (tx["sender"], p["grantee"])
        entry = {"record_id": rid, "kinds": tuple(p["kinds"]),
                 "expires_at": float(p["expires_at"]), "revoked": False}
        self._set(self.consents, key, self.consents.get(key, ()) + (entry,))
        return "OK"

    def _revoke(self, tx, p, now):
        me = self._who(tx)
        if me is None or me["role"] != "patient":
            return "DENIED:NOT_PATIENT"
        key = (tx["sender"], p["grantee"])
        cur = self.consents.get(key, ())
        new = tuple(dict(c, revoked=True) if c["record_id"] in ("*", p["record_id"]) or p["record_id"] == "*"
                    else c for c in cur)
        self._set(self.consents, key, new)
        return "OK"

    def _request_access(self, tx, p, now):
        me = self._who(tx)
        if me is None:
            return "DENIED:UNREGISTERED"
        rec = self.records.get(p["record_id"])
        if rec is None:
            return "DENIED:NO_SUCH_RECORD"
        if me["role"] == "auditor":
            return "DENIED:AUDITOR_NO_CONTENT"
        sender = tx["sender"]
        if sender == rec["patient"]:
            return "GRANTED:OWNER"
        if sender == rec["hospital"]:
            return "GRANTED:CUSTODIAN"
        if me["role"] == "insurer" and rec["kind"] != INSURER_KIND:
            return "DENIED:INSURER_POLICY"
        match = [c for c in self.consents.get((rec["patient"], sender), ())
                 if not c["revoked"] and c["record_id"] in ("*", p["record_id"]) and rec["kind"] in c["kinds"]]
        if not match:
            return "DENIED:NO_CONSENT"
        if any(now <= c["expires_at"] for c in match):
            return "GRANTED:CONSENT"
        return "DENIED:EXPIRED"
