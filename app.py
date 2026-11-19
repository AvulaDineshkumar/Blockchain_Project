"""MedChain: dashboard for the privacy-preserving medical data sharing blockchain.
Run:  streamlit run app.py"""
import copy
import inspect
import io
import json
import os
import time
from collections import Counter

import pandas as pd
import streamlit as st

from ehrchain.ledger import verify_chain
from ehrchain.network import BYZ_PRIMARY, BYZ_VOTER, HONEST, OFFLINE
from ehrchain.world import World, access_history

ROOT = os.path.dirname(os.path.abspath(__file__))


def _stretch(fn):
    """Full-width argument that works on old and new Streamlit versions."""
    p = inspect.signature(fn).parameters.get("width")
    return {"width": "stretch"} if p is not None and "Width" in str(p.annotation) else {"use_container_width": True}


SDF, SIMG, SBTN = _stretch(st.dataframe), _stretch(st.image), _stretch(st.button)
st.set_page_config(page_title="MedChain | Medical data sharing on a blockchain", page_icon=None, layout="wide")

# ------------------------------------------------------------------ look and feel -------
st.markdown("""
<style>
.block-container {padding-top: 1.2rem; max-width: 1250px;}
.hero {background: #134E4A; color:#fff; padding: 18px 26px;
       border-radius: 8px; margin-bottom: 18px; }
.hero h1 {color:#fff; font-size: 1.9rem; margin:0 0 4px 0;}
.hero p {color:#E0F2FE; margin: 0 0 12px 0; font-size: 1.0rem;}
.chip {display:inline-block; background: rgba(255,255,255,.18); border:1px solid rgba(255,255,255,.35); color:#fff;
       padding: 3px 11px; border-radius: 999px; font-size: .78rem; margin: 2px 6px 2px 0;}
.card {background:#fff; border:1px solid #DCE6EC; border-radius:14px; padding: 14px 16px; box-shadow: 0 1px 3px rgba(15,23,42,.06); height:100%;}
.card h4 {margin: 0 0 4px 0; font-size: 1.0rem; color:#0F172A;}
.card p {margin: 0; color:#475569; font-size: .88rem;}
.step {background:#fff; border:1px solid #DCE6EC; border-top: 5px solid #0F766E; border-radius: 12px; padding: 12px; min-height: 142px;}
.step .n {display:inline-block; background:#0F766E; color:#fff; width: 24px; height:24px; text-align:center; border-radius:50%; font-weight:700; font-size:.85rem; line-height:24px;}
.step b {display:block; margin: 6px 0 3px 0;}
.step span {color:#475569; font-size:.84rem;}
.kpi {background:#fff; border:1px solid #DCE6EC; border-radius:14px; padding: 12px 14px; text-align:center;}
.kpi .v {font-size: 1.7rem; font-weight: 800; color:#0F766E; line-height:1.1;}
.kpi .l {font-size: .78rem; color:#64748B; text-transform: uppercase; letter-spacing: .04em;}
.badge {display:inline-block; padding: 4px 12px; border-radius: 999px; font-weight:700; font-size:.85rem; margin: 2px 6px 2px 0;}
.b-ok {background:#DCFCE7; color:#166534; border:1px solid #86EFAC;}
.b-no {background:#FEE2E2; color:#991B1B; border:1px solid #FCA5A5;}
.b-warn {background:#FEF3C7; color:#92400E; border:1px solid #FCD34D;}
.b-info {background:#E0F2FE; color:#075985; border:1px solid #7DD3FC;}
.result {border-radius: 14px; padding: 14px 18px; margin: 8px 0; border-left: 8px solid;}
.r-ok {background:#F0FDF4; border-color:#22C55E;}
.r-no {background:#FEF2F2; border-color:#EF4444;}
.r-warn {background:#FFFBEB; border-color:#F59E0B;}
.result .t {font-size: 1.05rem; font-weight: 800; margin-bottom: 2px;}
.result .d {color:#334155; font-size:.92rem;}
.node {border-radius: 14px; padding: 12px 14px; border:2px solid; background:#fff; margin-bottom: 8px;}
.n-on {border-color:#22C55E;} .n-off {border-color:#EF4444; background:#FEF2F2;} .n-byz {border-color:#F59E0B; background:#FFFBEB;}
.node .id {font-weight: 800; font-size:1.05rem;}
.node .sm {color:#64748B; font-size:.8rem;}
.idcard {background: linear-gradient(120deg,#ECFEFF,#EFF6FF); border:1px solid #BAE6FD; border-radius: 14px; padding: 12px 16px;}
.idcard .nm {font-size:1.15rem; font-weight:800;} .idcard code {font-size:.78rem;}
.how {background:#fff; border:1px dashed #94A3B8; border-radius:12px; padding: 10px 14px; color:#334155; font-size:.92rem; margin-bottom: 10px;}
div[data-testid="stSidebar"] {border-right: 1px solid #DCE6EC;}
</style>
""", unsafe_allow_html=True)


# result code -> (icon, short title, plain-English explanation, style)
EXPLAIN = {
    "GRANTED:OWNER": ("", "Granted: the owner", "This is the patient's own record, so access is always allowed.", "ok"),
    "GRANTED:CUSTODIAN": ("", "Granted: the hospital that holds it", "The hospital that created the record can read it.", "ok"),
    "GRANTED:CONSENT": ("", "Granted: the patient consented", "A valid, unexpired consent from the patient covers this record.", "ok"),
    "DENIED:NO_CONSENT": ("", "Denied: no consent", "The patient never allowed this person to see this kind of data (or revoked it). The attempt is still written to the ledger.", "no"),
    "DENIED:EXPIRED": ("", "Denied: consent expired", "The patient's consent existed but its time window has ended. Checked against the block time, so every node agrees.", "warn"),
    "DENIED:UNREGISTERED": ("", "Denied: unknown identity", "The signer is not a registered participant of this permissioned network (or used somebody else's name with the wrong key).", "no"),
    "DENIED:INSURER_POLICY": ("", "Denied: insurer policy", "Insurers may only receive the billing view (name, gender, birth date, claim totals), never clinical records or MRI.", "no"),
    "DENIED:AUDITOR_NO_CONTENT": ("", "Denied: auditors never see content", "Auditors verify the audit trail but can never open medical files.", "no"),
    "DENIED:NO_SUCH_RECORD": ("", "Denied: unknown record", "No record with this ID exists on the ledger.", "no"),
    "DENIED:REPLAY": ("", "Denied: replayed request", "The same signed request was already processed once.", "no"),
    "OK": ("", "File intact", "The decrypted file's SHA-256 matches the hash stored on the blockchain.", "ok"),
    "TAMPERED_CIPHERTEXT": ("", "File was modified", "The encrypted file changed after it was stored: the AES-GCM authentication check failed. Tampering detected.", "warn"),
    "HASH_MISMATCH": ("", "File was replaced", "The file decrypts fine but its SHA-256 differs from the hash on the blockchain. Tampering detected.", "warn"),
}


def show_result(res, extra=""):
    """Render a ledger result like 'GRANTED:CONSENT|OK' as coloured cards with plain explanations."""
    if res is None:
        st.markdown('<div class="result r-warn"><div class="t">Not committed yet</div><div class="d">Consensus is stalled: more than f validators are faulty. '
                    'The signed request waits in the mempool and is committed once enough validators are honest again.</div></div>', unsafe_allow_html=True)
        return
    for code in res.split("|"):
        icon, title, text, style = EXPLAIN.get(code, ("", code, "Recorded on the ledger.", "ok"))
        st.markdown(f'<div class="result r-{style}"><div class="t">{title}</div><div class="d">{text}</div></div>', unsafe_allow_html=True)
    if extra:
        st.caption(extra)


def label_of(res):
    code = res.split("|")[0] if "|" not in res else res.split("|")[0]
    icon, title, _, _ = EXPLAIN.get(code, ("", code, "", "ok"))
    return title


def kpi(col, value, label):
    col.markdown(f'<div class="kpi"><div class="v">{value}</div><div class="l">{label}</div></div>', unsafe_allow_html=True)


def card(col, title, text):
    col.markdown(f'<div class="card"><h4>{title}</h4><p>{text}</p></div>', unsafe_allow_html=True)


def how(text):
    st.markdown(f'<div class="how"><b>About this page.</b> {text}</div>', unsafe_allow_html=True)


# ------------------------------------------------------------------ world ---------------
@st.cache_resource(show_spinner="Loading Synthea Coherent patients, encrypting their files and building the chain ...")
def get_world(n_nodes, patients):
    w = World(n_nodes=n_nodes)
    w.load_dataset(os.path.join(ROOT, "data", "subset"), limit=patients)
    return w


with st.sidebar:
    st.markdown("## MedChain")
    st.caption("Privacy-preserving medical data sharing with tamper-resistant access auditing")
    st.markdown("**Settings**")
    n_nodes = st.selectbox("Number of validators", [4, 7, 10, 13], index=0, help="n = 3f+1: 4, 7, 10 and 13 nodes tolerate f = 1, 2, 3 and 4 faulty nodes.")
    n_pat = st.slider("Number of patients", 3, 5, 3, help="Patients are taken from the Synthea Coherent data set, each with a FHIR record and an MRI file.")
    w = get_world(n_nodes, n_pat)
    st.markdown("**Open the page for**")
    role = st.radio("view", ["Overview", "Guided demo", "Patient", "Hospital", "Doctor", "Insurer", "Auditor", "Network & results"],
                    label_visibility="collapsed")
    st.markdown("**Clock (to test consent expiry)**")
    days = st.number_input("Move the clock forward (days)", 0, 365, 0)
    if st.button("Move clock forward") and days:
        w.clock.advance(days * 86400)
        st.toast(f"Clock moved forward {days} day(s)", icon=None)
    st.divider()
    ok_cons = w.net.chain_consistent()
    st.markdown(f"**Ledger height:** {w.net.height} blocks  \n**All honest nodes agree:** {'yes' if ok_cons else 'no'}")

pids = list(w.patients)
label = {pid: f"{w.patients[pid].name}" for pid in pids}
led = w.net.reference().ledger
total_tx = sum(len(b["txs"]) for b in led.blocks)
denied_total = sum(r.startswith("DENIED") for b in led.blocks for r in b["results"])

st.markdown(f"""
<div class="hero">
  <h1>MedChain: medical record sharing on a permissioned blockchain</h1>
  <p>Files stay encrypted off-chain. The ledger keeps each file's hash, the patient's consent and every access, granted or denied.</p>
</div>
""", unsafe_allow_html=True)


def history_df(pid):
    h = access_history(w, pid)
    df = pd.DataFrame(h)
    if df.empty:
        return df
    df["who"] = df.requester.map(lambda x: w.actors[x].name if x in w.actors else f"{x}")
    df["outcome"] = df.result.map(lambda r: label_of(r) if not r.startswith(("GRANT_CONSENT", "REVOKE_CONSENT")) else ("" + r.split(":")[0].replace("_", " ").title()))
    return df[["block", "record", "who", "outcome"]]


def identity_card(a):
    st.markdown(f'<div class="idcard"><div class="nm">{a.name}</div>'
                f'<span class="badge b-info">{a.role}</span> Digital identity (Ed25519 public key): <code>{a.sk.public_hex[:24]}…</code></div>', unsafe_allow_html=True)


def request_ui(me, order, key):
    rid = st.selectbox("Which record?", order, key=key,
                       format_func=lambda r: f"{ {'MRI': 'MRI scan', 'FHIR': 'Clinical record', 'FHIR_INS': 'Billing view'}.get(w.records[r]['kind'], w.records[r]['kind']) } · {w.patients[w.records[r]['patient']].name if w.records[r]['patient'] in w.patients else w.records[r]['patient']}")
    st.caption("MRI scan = head MRI file. Clinical record = full FHIR record. Billing view = the limited record insurers may receive.")
    if st.button("Send signed request", type="primary", key=key + "_go"):
        with st.spinner("Signing the request and running consensus among the validators ..."):
            res, plain, tx = w.request_and_fetch(me, rid)
        show_result(res, f"Transaction {tx['tx_id'][:20]}… signed with Ed25519 by {me.id} and agreed by the validators.")
        if plain is not None:
            kind = w.records[rid]["kind"]
            if kind in ("FHIR", "FHIR_INS"):
                b = json.loads(plain)
                cnt = Counter(e["resource"]["resourceType"] for e in b["entry"])
                st.markdown(f"**{'Billing view' if kind == 'FHIR_INS' else 'Clinical record'}** decrypted: {len(b['entry'])} resources")
                st.bar_chart(pd.Series(cnt).sort_values(ascending=False).head(10))
            else:
                try:
                    import numpy as np
                    import pydicom
                    ds = pydicom.dcmread(io.BytesIO(plain))
                    a = ds.pixel_array.astype(float)
                    c1, c2, c3 = st.columns(3)
                    for col, (nm, sl) in zip((c1, c2, c3), (("axial", a[a.shape[0] // 2]), ("coronal", a[:, a.shape[1] // 2]), ("sagittal", a[:, :, a.shape[2] // 2]))):
                        sl = (sl - sl.min()) / (np.ptp(sl) + 1e-9)
                        col.image(sl, caption=f"{nm} slice (decrypted, hash verified)", **SIMG)
                except Exception as e:
                    st.write(f"MRI decrypted and verified ({len(plain)/2**20:.1f} MB). Preview unavailable: {e}")


# ================================================================== OVERVIEW =============
if role.endswith("Overview"):
    how("This is a working prototype of a permissioned blockchain for hospitals. Use the left menu to act as a patient, hospital, doctor, insurer or auditor, "
        "or open <b>Guided demo</b> to see every scenario in the project brief in one click.")
    c = st.columns(6)
    kpi(c[0], len(w.patients), "Patients"); kpi(c[1], len(w.records), "Records"); kpi(c[2], w.net.n, "Validators")
    kpi(c[3], len(led.blocks), "Blocks"); kpi(c[4], total_tx, "Transactions"); kpi(c[5], denied_total, "Denied attempts logged")
    st.markdown("### How a record is shared")
    steps = [("Encrypt and fingerprint", "The hospital encrypts the MRI (AES-256-GCM) and keeps it off-chain. Its SHA-256 hash goes on the blockchain."),
             ("Patient consents", "The patient signs a consent: who, which data, for how long. A smart contract stores it."),
             ("Doctor asks", "The doctor signs a request with their private key. Nobody can forge or alter it."),
             ("Validators vote", "Validator nodes re-check the request and vote (PBFT). A block needs 2f+1 signatures."),
             ("Decision on the ledger", "Granted or denied, the result is written to the ledger. Denials become security events."),
             ("File released", "Only if granted, the file key is wrapped for the doctor. The hash proves the file is untouched.")]
    cols = st.columns(6)
    for i, (col, (t, d)) in enumerate(zip(cols, steps), 1):
        col.markdown(f'<div class="step"><span class="n">{i}</span><b>{t}</b><span>{d}</span></div>', unsafe_allow_html=True)
    st.markdown("### Who can do what")
    c = st.columns(5)
    card(c[0], "Patient", "Owns the record, grants and revokes consent, sees the complete access history.")
    card(c[1], "Hospital", "Creates records, keeps the encrypted file, and runs a validator node.")
    card(c[2], "Doctor", "Requests records. Gets them only with the patient's valid consent.")
    card(c[3], "Insurer", "Receives only the billing view. Clinical data and MRI are always denied.")
    card(c[4], "Auditor", "Verifies the chain and reads security events, but never sees medical content.")
    st.markdown("### Security features you can try")
    c = st.columns(4)
    card(c[0], "Tamper detection", "Change a stored file by one bit and the next reader is told.")
    card(c[1], "Expiring consent", "Access stops automatically when the consent window ends.")
    card(c[2], "Byzantine tolerance", "Up to f lying or offline validators cannot change the ledger.")
    card(c[3], "Immutable audit trail", "Editing history breaks hashes, signatures and quorum certificates.")
    st.markdown("### Latest blocks on the ledger")
    rows = []
    for b in led.blocks[-8:][::-1]:
        for t, r in list(zip(b["txs"], b["results"]))[:3]:
            rows.append({"block": b["header"]["index"], "proposer": b["header"]["proposer"], "type": t["type"].replace("_", " ").title(),
                         "by": t["sender"][:26], "result": label_of(r) if r != "OK" else "OK"})
    st.dataframe(pd.DataFrame(rows), hide_index=True, **SDF)
    st.caption("Dataset: Synthea Coherent Data Set (synthetic patients): FHIR clinical records and DICOM MRI volumes. No real patient data is involved.")

# ================================================================== GUIDED DEMO ==========
elif role.endswith("Guided demo"):
    how("One button per scenario from the project brief. Each runs on the real patient data and shows what the blockchain decided and why. "
        "Run them in order for the smoothest story; each has an explanation of what to look for.")
    pid = pids[0]
    p, pat = w.patients[pid], w.actors[pid]
    doc = w.actors[w.doctor_of[pid][0]]
    strangers = [a for a in w.actors.values() if a.role == "doctor" and a.id not in w.doctor_of[pid]]
    stranger = strangers[0]
    ins = w.actors[w.insurer_of[pid]]
    mri, fhir, insr = f"MRI-{p.pid[:8]}", f"FHIR-{p.pid[:8]}", f"INS-{p.pid[:8]}"
    c = st.columns(3)
    c[0].markdown(f"**Patient**<br>{pat.name}", unsafe_allow_html=True)
    c[1].markdown(f"**Treating doctor**<br>{doc.name}", unsafe_allow_html=True)
    c[2].markdown(f"**Unrelated doctor**<br>{stranger.name}", unsafe_allow_html=True)
    st.divider()

    def scenario(title, desc, button, key, fn):
        st.markdown(f"#### {title}")
        st.caption(desc)
        if st.button(button, key=key, type="primary"):
            with st.spinner("Running on the blockchain ..."):
                fn()
        st.divider()

    def s1():
        show_result(w.request_and_fetch(stranger, mri)[0])
    scenario("1. Unauthorized doctor asks for the MRI", "Expected: denied, and the attempt appears as a security event in the Auditor view.", "Try it", "d1", s1)

    def s2():
        w.grant(pat, doc.id, "*", ("FHIR", "MRI"), days=7); w.commit()
        st.info("Patient signed a consent for 7 days.")
        res = w.request_and_fetch(doc, mri)
        show_result(res[0])
    scenario("2. Authorized doctor gets the record", "The patient consents, then the treating doctor asks. Expected: granted, file decrypts and the hash matches.", "Grant consent and request", "d2", s2)

    def s3():
        w.submit(pat, "REVOKE_CONSENT", {"grantee": doc.id, "record_id": "*"}); w.commit()  # drop earlier consents so only the 1-day one counts
        w.grant(pat, doc.id, "*", ("FHIR", "MRI"), days=1); w.commit()
        st.info("Consent valid for 1 day. Moving the clock forward 2 days ...")
        w.clock.advance(2 * 86400)
        show_result(w.request_and_fetch(doc, mri)[0])
    scenario("3. Consent has expired", "Expected: denied automatically. (This moves the demo clock forward 2 days.)", "Expire it", "d3", s3)

    def s4():
        w.grant(pat, doc.id, "*", ("FHIR", "MRI"), days=30); w.commit()
        w.store.tamper_ciphertext(fhir)
        st.warning("An attacker flipped one bit of the stored encrypted clinical record.")
        show_result(w.request_and_fetch(doc, fhir)[0])
        pdata = w.patients[pid]
        w.store.put(fhir, open(pdata.fhir_path, "rb").read(), w.actors[w.records[fhir]["hospital"]])
        st.caption("Original file restored afterwards.")
    scenario("4. A stored medical file is modified", "Expected: tampering is detected by the authentication tag / hash check. The file is restored afterwards.", "Tamper with the file", "d4", s4)

    def s5():
        w.grant(pat, ins.id, "*", ("FHIR_INS",), days=30); w.commit()
        st.markdown("**Insurer asks for the billing view:**"); show_result(w.request_and_fetch(ins, insr)[0])
        st.markdown("**Insurer asks for the MRI:**"); show_result(w.request_and_fetch(ins, mri)[0])
    scenario("5. The insurer gets only what is permitted", "Expected: billing view granted, MRI denied by policy.", "Run insurer test", "d5", s5)

    def s6():
        w.net.set_behavior("V1", OFFLINE)
        st.warning("Validator V1 is now offline.")
        show_result(w.request_and_fetch(doc, mri)[0])
        st.success(f"The remaining validators kept committing blocks (height {w.net.height}).")
        w.net.recover("V1")
        st.caption("V1 was brought back and re-synced from its peers.")
    scenario("6. A blockchain node fails", "Expected: the network keeps working because 3 of 4 validators are enough (f = 1).", "Take V1 offline", "d6", s6)

    def s7():
        nxt = w.net.order[w.net.reference().ledger.next_index % w.net.n]
        w.net.set_behavior(nxt, BYZ_PRIMARY, "forge_result")
        st.warning(f"{nxt} is the next block proposer and it is now malicious: it tries to forge a result.")
        tx = w.submit(stranger, "REQUEST_ACCESS", {"record_id": mri}); w.commit()
        show_result(w.result(tx))
        st.success("Honest validators rejected the forged block, moved to the next proposer, and the true result was recorded.")
        w.net.set_behavior(nxt, HONEST)
    scenario("7. A malicious node tries to cheat", "Expected: the forged block is rejected, a view change happens and the correct (denied) result is on the ledger.", "Make the proposer malicious", "d7", s7)

# ================================================================== PATIENT ==============
elif role.endswith("Patient"):
    how("You are the owner of your medical data. Choose who may see what and for how long, and review every access to your records, including the ones that were denied.")
    pid = st.selectbox("Patient", pids, format_func=label.get)
    p, pat = w.patients[pid], w.actors[pid]
    identity_card(pat)
    st.markdown("#### My records (encrypted off-chain, fingerprints on the blockchain)")
    st.dataframe(pd.DataFrame([{"record": r, "type": {"MRI": "MRI scan", "FHIR": "Clinical record", "FHIR_INS": "Billing view"}.get(v["kind"], v["kind"]),
                                "hospital": w.actors[v["hospital"]].name, "SHA-256 fingerprint": v["hash"][:24] + "…", "size MB": round(v["size"] / 2**20, 2)}
                               for r, v in w.records.items() if v["patient"] == pid]), hide_index=True, **SDF)
    t1, t2, t3 = st.tabs(["Give consent", "Revoke consent", "Access history"])
    grantees = {a.id: f"{a.name} ({a.role})" for a in sorted((a for a in w.actors.values() if a.role in ("doctor", "insurer", "hospital")), key=lambda a: ("doctor", "insurer", "hospital").index(a.role))}
    with t1:
        g = st.selectbox("Allow this person", list(grantees), format_func=grantees.get)
        if w.actors[g].role == "insurer":
            kinds = st.multiselect("To see (insurers can only receive the billing view)", ["FHIR_INS"], default=["FHIR_INS"])
        else:
            kinds = st.multiselect("To see", ["FHIR", "MRI"], default=["FHIR"], help="FHIR = full clinical record, MRI = brain scan")
        d = st.number_input("For how many days?", 1, 365, 7)
        if st.button("Sign and record consent", type="primary") and kinds:
            tx = w.grant(pat, g, "*", tuple(kinds), days=d); w.commit()
            st.success(f"Consent recorded on the ledger ({w.result(tx)}). It expires automatically after {d} day(s).")
    with t2:
        g2 = st.selectbox("Stop allowing", list(grantees), format_func=grantees.get, key="rv")
        if st.button("Revoke now"):
            tx = w.submit(pat, "REVOKE_CONSENT", {"grantee": g2, "record_id": "*"}); w.commit()
            st.success(f"Consent revoked ({w.result(tx)}). Further requests will be denied.")
    with t3:
        st.caption("Everything that happened to your records, read directly from the ledger. Nobody can quietly remove a line.")
        h = history_df(pid)
        st.dataframe(h, hide_index=True, **SDF)
        if not h.empty:
            c = st.columns(3)
            kpi(c[0], len(h), "Events"); kpi(c[1], int(h.outcome.str.contains("Denied|expired|unknown|policy|never|replayed", case=False).sum()), "Blocked attempts")
            kpi(c[2], int(h.outcome.str.contains("Granted").sum()), "Granted accesses")

# ================================================================== HOSPITAL =============
elif role.endswith("Hospital"):
    how("Hospitals create records. The file is encrypted and stored off-chain; only its fingerprint goes on the blockchain. Hospitals also run the validator nodes.")
    hs = {a.id: a.name for a in w.actors.values() if a.role == "hospital"}
    most = max(hs, key=lambda h: sum(v["hospital"] == h for v in w.records.values()))
    hid = st.selectbox("Hospital", list(hs), index=list(hs).index(most), format_func=hs.get)
    hosp = w.actors[hid]
    identity_card(hosp)
    nodes_run = [n for n, v in led.state.nodes.items() if v["operator"] == hid]
    if nodes_run:
        st.success(f"This hospital operates validator node(s): {', '.join(nodes_run)}")
    st.markdown("#### Records created here")
    st.dataframe(pd.DataFrame([{"record": r, "patient": w.patients[v["patient"]].name if v["patient"] in w.patients else v["patient"],
                                "type": {"MRI": "MRI", "FHIR": "Clinical", "FHIR_INS": "Billing"}.get(v["kind"], v["kind"]),
                                "SHA-256": v["hash"][:24] + "…", "MB": round(v["size"] / 2**20, 2)} for r, v in w.records.items() if v["hospital"] == hid]),
                 hide_index=True, **SDF)
    st.markdown("#### Request a record from another hospital")
    st.caption("A hospital can ask for a patient's record like anyone else: it needs that patient's consent, and the request is signed and recorded.")
    request_ui(hosp, [r for r, v in w.records.items() if v["hospital"] != hid and v["kind"] != "FHIR_INS"], "req_hosp")
    st.markdown("#### Add a new record")
    tgt = st.selectbox("For patient", pids, format_func=label.get, key="newrec_p")
    up = st.file_uploader("Choose any file (it will be encrypted)")
    if up is not None and st.button("Encrypt, store and register", type="primary"):
        raw = up.getvalue()
        rid = f"UP-{len(w.records) + 1}-{tgt[2:10]}"
        h = w.store.put(rid, raw, hosp)
        w.records[rid] = {"patient": tgt, "hospital": hid, "kind": "FHIR", "hash": h, "size": len(raw)}
        tx = w.submit(hosp, "ADD_RECORD", {"record_id": rid, "patient_id": tgt, "kind": "FHIR", "file_hash": h, "size": len(raw)})
        w.commit()
        st.success(f"Registered as {rid} (ledger result {w.result(tx)}).")
        st.code(f"SHA-256: {h}", language="text")

# ================================================================== DOCTOR / INSURER =====
elif role.endswith("Doctor") or role.endswith("Insurer"):
    who_role = "doctor" if role.endswith("Doctor") else "insurer"
    how(f"Act as a {who_role} and ask for a record. Your request is signed with your private key, checked by the smart contract and recorded on the ledger whether it is granted or denied.")
    who = {a.id: a.name for a in w.actors.values() if a.role == who_role}
    me = w.actors[st.selectbox("Acting as", list(who), format_func=who.get)]
    identity_card(me)
    if who_role == "insurer":
        st.info("Policy: an insurer can only ever receive the billing view (name, gender, birth date, claim totals). Requests for clinical records or MRI are denied by the contract, even with patient consent.")
        order = sorted(w.records, key=lambda r: (w.records[r]["kind"] != "FHIR_INS", r))
    else:
        order = list(w.records)
    request_ui(me, order, "req_" + who_role)

# ================================================================== AUDITOR ==============
elif role.endswith("Auditor"):
    how("Auditors verify that the history is intact and investigate suspicious access. They can read the audit trail but can never open medical content.")
    c = st.columns(4)
    kpi(c[0], len(led.blocks), "Blocks"); kpi(c[1], total_tx, "Transactions"); kpi(c[2], denied_total, "Security events"); kpi(c[3], f"{w.net.quorum}/{w.net.n}", "Votes needed per block")
    b1, b2 = st.columns(2)
    if b1.button("Verify the whole chain from the first block", type="primary", **SBTN):
        ok, reason, at = verify_chain(led.blocks)
        if ok:
            st.markdown('<div class="result r-ok"><div class="t">Chain is valid</div><div class="d">Every hash, signature, contract result and validator quorum certificate checks out.</div></div>', unsafe_allow_html=True)
        else:
            st.error(f"Invalid at block {at}: {reason}")
    if b2.button("Simulate an attacker editing a denied event", **SBTN):
        blocks = copy.deepcopy(led.blocks)
        for b in blocks[1:]:
            idx = next((i for i, r in enumerate(b["results"]) if r.startswith("DENIED")), None)
            if idx is not None:
                b["results"][idx] = "GRANTED:CONSENT"
                break
        ok, reason, at = verify_chain(blocks)
        st.markdown(f'<div class="result r-warn"><div class="t">Tampering detected</div><div class="d">The edited copy fails verification: <b>{reason}</b> at block <b>{at}</b>. '
                    'Recomputing the hashes would not help the attacker either, because the validators\' signatures would no longer match.</div></div>', unsafe_allow_html=True)
    rows = []
    for b in led.blocks[1:]:
        for t, r in zip(b["txs"], b["results"]):
            if r.startswith("DENIED"):
                who = led.state.identities.get(t["sender"], {})
                rows.append({"block": b["header"]["index"], "who": (who.get('name') or t['sender']),
                             "attempted": t["type"].replace("_", " ").title(), "outcome": label_of(r),
                             "record": t["payload"].get("record_id") if isinstance(t["payload"], dict) else ""})
    st.markdown("#### Security events (denied attempts are recorded, not dropped)")
    if rows:
        df = pd.DataFrame(rows)
        c1, c2 = st.columns([2, 1])
        c1.dataframe(df, hide_index=True, **SDF)
        c2.markdown("**Why denied**")
        c2.bar_chart(df.outcome.value_counts())
    else:
        st.info("No denied attempts yet. Try the Guided demo, then come back.")

# ================================================================== NETWORK ==============
else:
    how("The validator nodes agree on every block by voting. Take nodes offline or make one dishonest and watch the network react. More than f faulty nodes stop the network, but never corrupt it.")
    ledger = w.net.reference().ledger
    nxt = w.net.order[ledger.next_index % w.net.n]
    cc = st.columns(4)
    kpi(cc[0], w.net.n, "Validators (n)"); kpi(cc[1], w.net.f, "Faults tolerated (f)"); kpi(cc[2], w.net.quorum, "Quorum (2f+1)"); kpi(cc[3], nxt, "Next block proposer")
    st.markdown("#### Validator nodes")
    cols = st.columns(min(4, w.net.n))
    for i, n in enumerate(w.net.nodes.values()):
        beh = n.behavior
        cls = {"honest": "n-on", "offline": "n-off"}.get(beh, "n-byz")
        dot = {"honest": "online & honest", "offline": "offline", "byz_voter": "dishonest voter", "byz_primary": "dishonest proposer"}.get(beh, beh)
        op = ledger.state.nodes.get(n.id, {}).get("operator")
        opn = w.actors[op].name if op in w.actors else "-"
        cols[i % len(cols)].markdown(f'<div class="node {cls}"><div class="id">{n.id}</div><div>{dot}</div>'
                                     f'<div class="sm">{opn}</div><div class="sm">height {n.ledger.next_index - 1} · head {n.ledger.head_hash[:10]}…</div></div>', unsafe_allow_html=True)
    st.markdown("#### Inject a fault")
    c1, c2, c3 = st.columns([1, 1, 1])
    nid = c1.selectbox("Node", w.net.order)
    beh = c2.selectbox("Behaviour", [HONEST, OFFLINE, BYZ_VOTER, BYZ_PRIMARY], format_func=lambda b: {"honest": "honest", "offline": "offline", "byz_voter": "dishonest voter", "byz_primary": "dishonest proposer"}[b])
    if c3.button("Apply", **SBTN):
        if beh == HONEST and w.net.nodes[nid].behavior == OFFLINE:
            w.net.recover(nid)
        else:
            w.net.set_behavior(nid, beh)
        st.rerun()
    st.caption(f"With n = {w.net.n}, up to f = {w.net.f} faulty nodes are tolerated. Take f+1 offline, then send a request from the Doctor view: nothing is committed, and nothing is corrupted.")
    st.markdown("#### Attack on storage")
    tr = st.selectbox("Record to tamper with", list(w.records), key="tamper_rec")
    t1, t2 = st.columns(2)
    if t1.button("Flip one bit of the encrypted file", **SBTN):
        w.store.tamper_ciphertext(tr)
        st.warning("File modified. Request it as a doctor who has consent and the tampering will be flagged.")
    if t2.button("Restore the original file", **SBTN):
        rec = w.records[tr]
        p = w.patients.get(rec["patient"])
        if p is not None and tr.split("-")[0] in ("FHIR", "MRI", "INS"):
            from ehrchain.data import insurance_view
            raw = open(p.dicom_path if rec["kind"] == "MRI" else p.fhir_path, "rb").read()
            if rec["kind"] == "FHIR_INS":
                raw = insurance_view(raw)
            w.store.put(tr, raw, w.actors[rec["hospital"]]); st.success("Restored")
    fig = os.path.join(ROOT, "results", "figures")
    if os.path.isdir(fig):
        st.markdown("#### Benchmark results")
        caps = {"fig1": "Latency vs load (lower is better)", "fig2": "Throughput vs load (higher is better)", "fig3": "Block confirmation time vs nodes",
                "fig4": "Consensus messages and traffic vs nodes", "fig5": "Proof-of-Work difficulty vs block time", "fig6": "Hashing and encryption cost vs file size",
                "fig7": "Behaviour with offline nodes", "fig8": "Storage: on-chain vs off-chain", "fig9": "Effect of network delay", "fig10": "Simulation vs real TCP validators"}
        files = sorted([f for f in os.listdir(fig) if f.endswith(".png") and not f.startswith("fig0")], key=lambda f: int(f.split("_")[0][3:]))
        cols = st.columns(2)
        for i, f in enumerate(files):
            cols[i % 2].image(os.path.join(fig, f), caption=caps.get(f.split("_")[0], f), **SIMG)
