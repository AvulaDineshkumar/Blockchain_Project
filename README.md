# MedChain: privacy-preserving medical data sharing on a permissioned blockchain

Course project for 24DS743 Blockchain Technology, M.Tech Data Science, Amrita School of Computing, Bengaluru.

Authors: Avula Dinesh Kumar (BL.SC.P2DSC25006) and Paunesh Varadharajan (BL.SC.P2DSC25022).
Guide: Ms. Shalini Tiwari, Assistant Professor.

## What the project does

Hospitals keep patient records in separate central databases, so the database owner decides who reads a record and also keeps the access log. This project builds a permissioned blockchain in Python that shares medical records among patients, hospitals, doctors, insurers and an auditor.

- Medical files stay encrypted off-chain with AES-256-GCM.
- The ledger holds only the SHA-256 hash of each file, the patient's consent with an expiry date, and every access request, granted or denied.
- A smart contract (the Python class `State` in `ehrchain/contract.py`) decides each request from the requester's identity, role and the patient's consent.
- Validators agree on each block with PBFT-style voting (n >= 3f + 1, quorum 2f + 1), with view change and node recovery.
- The data are 20 patients of the Synthea Coherent Data Set, each with a FHIR record and an MRI volume (DICOM).
- The system is compared with a Proof of Work chain and a centralized SQLite database on one workload.

## Run the demo

```
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501. The first start takes a few seconds because the app reads the patient files and encrypts the MRI files. Use the Guided demo page for the seven scenarios (unauthorised request, consent, expiry, tampered file, insurer, failed node, malicious node).

This repository holds 5 of the 20 patients, so the demo starts quickly and fits free hosting. To get all 20, install the AWS CLI and run `./fetch_subset.sh 20`.

## Other commands

```
pytest -q tests                 # 23 unit and attack tests
python p2p_demo.py              # four real validator processes over TCP
python -m ehrchain.experiments  # attack and failure experiments -> results/experiments.json
./run_bench.sh                  # benchmarks (resumable) -> results/bench_*.csv
python -m ehrchain.charts       # figures and tables -> results/figures, results/summary_table.md
```

## Folder map

| Path | What it is |
|---|---|
| `app.py` | Streamlit demo: Overview, Guided demo, Patient, Hospital, Doctor, Insurer, Auditor, Network and results |
| `ehrchain/crypto.py` | SHA-256, Ed25519, X25519 with HKDF, AES-256-GCM |
| `ehrchain/contract.py` | Smart contract: roles, consent with expiry, access decisions |
| `ehrchain/ledger.py` | Transactions, blocks, Merkle trees, commit certificates, chain verification |
| `ehrchain/network.py` | Validators and PBFT-style consensus in one process |
| `ehrchain/p2p.py` | The same validators as separate TCP processes |
| `ehrchain/storage.py` | Encrypted off-chain store and the gateway that checks the ledger first |
| `ehrchain/data.py`, `actors.py`, `world.py` | Dataset loader, people and keys, glue object used by the app |
| `ehrchain/baselines.py`, `workload.py`, `benchmark.py`, `experiments.py`, `charts.py` | PoW and SQLite baselines, workload, timing runs, attack experiments, figures |
| `tests/test_core.py` | Unit and attack tests |
| `data/subset/` | FHIR and DICOM files of the demo patients |
| `results/` | Saved experiment outputs |

## Main results

On the 20 patients, all 80 permitted requests were granted and hash-verified, and every unauthorised access, file edit, ledger edit and forged validator result in the experiments was caught. At 10,000 transactions, PBFT with 4 validators takes 893.5 ms (5,641 tx/s) and with 13 validators 1,012.2 ms (4,954 tx/s), against 1,394.8 ms for the PoW baseline and 154.0 ms for the centralized database. The ledger is 0.057% of the size of the data it protects.

## Notes

The data are synthetic, so no real patient is involved. This is a teaching prototype: PBFT has no checkpointing or persistence, and keys are held in memory.
