"""Dataset profile (light EDA) of the 20-patient Synthea Coherent subset.
Run: python -m ehrchain.profile_data   -> results/dataset_profile.csv/.md + 2 simple charts"""
import json
import os
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from .data import dicom_summary, load_subset

ROOT = os.path.join(os.path.dirname(__file__), "..")
RES = os.path.join(ROOT, "results")
os.makedirs(os.path.join(RES, "figures"), exist_ok=True)
data = load_subset(os.path.join(ROOT, "data", "subset"))
types, rows, dcm_info = Counter(), [], Counter()
for p in data:
    b = json.load(open(p.fhir_path))
    rt = Counter(e["resource"]["resourceType"] for e in b["entry"])
    types.update(rt)
    d = dicom_summary(p.dicom_path)
    dcm_info[(d["modality"], d["rows"], d["cols"], d["frames"], d["bits"])] += 1
    rows.append({"patient": p.name, "gender": next(e["resource"].get("gender") for e in b["entry"] if e["resource"]["resourceType"] == "Patient"),
                 "fhir_resources": p.n_resources, "encounters": rt["Encounter"], "imaging_studies": rt["ImagingStudy"],
                 "hospitals": len(p.hospitals), "doctors": len(p.doctors), "insurer": p.insurer,
                 "fhir_MB": round(p.fhir_bytes / 2**20, 2), "dicom_MB": round(p.dicom_bytes / 2**20, 2)})
df = pd.DataFrame(rows)
df.to_csv(os.path.join(RES, "dataset_profile.csv"), index=False)
summary = [
    f"patients with both FHIR and DICOM: {len(df)} (unpaired files: 0 by construction)",
    f"FHIR resources per patient: min {df.fhir_resources.min()}, median {int(df.fhir_resources.median())}, max {df.fhir_resources.max()}",
    f"FHIR size: total {df.fhir_MB.sum():.1f} MB (mean {df.fhir_MB.mean():.1f}, max {df.fhir_MB.max():.1f})",
    f"DICOM size: total {df.dicom_MB.sum():.0f} MB, per file {df.dicom_MB.min():.1f}-{df.dicom_MB.max():.1f} MB",
    f"DICOM headers (modality, rows, cols, frames, bits): {dict(dcm_info)}",
    f"patients with an ImagingStudy resource: {(df.imaging_studies > 0).sum()}/{len(df)}",
    f"distinct hospitals {len({h for p in data for h in p.hospitals})}, doctors {len({d for p in data for d, _ in p.doctors})}, insurers {df.insurer.nunique()}",
    f"gender: {df.gender.value_counts().to_dict()}",
    "top resource types: " + ", ".join(f"{k} {v}" for k, v in types.most_common(8)),
]
open(os.path.join(RES, "dataset_profile.md"), "w").write("# Dataset profile (20 patients)\n\n" + "\n".join("- " + s for s in summary) + "\n\n" + df.to_markdown(index=False) + "\n")
print("\n".join(summary))
top = types.most_common(8)
plt.figure(figsize=(6.4, 4)); plt.barh([k for k, _ in top][::-1], [v for _, v in top][::-1], color="tab:blue")
plt.xlabel("Count (20 patients)"); plt.title("FHIR resource types in the subset"); plt.grid(True, axis="x", alpha=0.3)
plt.tight_layout(); plt.savefig(os.path.join(RES, "figures", "fig0a_fhir_resource_types.png"), dpi=130); plt.close()
x = range(len(df)); plt.figure(figsize=(7, 4))
plt.bar(x, df.dicom_MB, label="DICOM MRI", color="tab:gray"); plt.bar(x, df.fhir_MB, bottom=df.dicom_MB, label="FHIR record", color="tab:blue")
plt.xlabel("Patient (1-20)"); plt.ylabel("File size (MB)"); plt.title("File size per patient"); plt.legend(); plt.grid(True, axis="y", alpha=0.3)
plt.tight_layout(); plt.savefig(os.path.join(RES, "figures", "fig0b_file_sizes.png"), dpi=130); plt.close()
