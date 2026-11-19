"""Pre-signed transaction workload used by the benchmarks (signing is done before timing)."""
import random

from .toy import toy_world


def make_workload(n_tx, n_nodes, seed=0, batch_size=200, hop_ms=5.0, pats=30, docs=30, hosp=5):
    rng = random.Random(seed)
    w, H, D, P, I, A, recs = toy_world(n_nodes=n_nodes, hosp=hosp, docs=docs, pats=pats,
                                       file_size=1024, batch_size=batch_size, hop_ms=hop_ms, seed=seed)
    # half of the doctor/patient pairs have consent, so the mix has GRANTED and DENIED results
    for i, rid in enumerate(recs):
        for j, d in enumerate(D):
            if (i + j) % 2 == 0:
                w.grant(P[i], d.id, rid, ("MRI",), days=30)
    w.commit()
    txs = []
    for _ in range(n_tx):
        r = rng.random()
        if r < 0.85:
            a = rng.choice(D + P + [I, A])
            txs.append(a.tx("REQUEST_ACCESS", {"record_id": rng.choice(recs)}, w.clock.now()))
        else:
            p = rng.choice(P)
            txs.append(p.tx("GRANT_CONSENT", {"grantee": rng.choice(D).id, "record_id": "*",
                                              "kinds": ["MRI"], "expires_at": w.clock.now() + 86400 * 5}, w.clock.now()))
    return w, txs
