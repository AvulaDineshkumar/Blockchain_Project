"""Load the Synthea Coherent subset (FHIR bundle + DICOM volume per patient)."""
import glob
import json
import os
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class PatientData:
    stem: str
    pid: str
    name: str
    fhir_path: str
    dicom_path: str
    imaging_hospital: str
    hospitals: list = field(default_factory=list)
    doctors: list = field(default_factory=list)   # (doctor display name, hospital)
    insurer: str = ""
    n_resources: int = 0
    fhir_bytes: int = 0
    dicom_bytes: int = 0


def _name(p):
    n = p["name"][0]
    return f"{' '.join(n.get('given', []))} {n.get('family', '')}".strip()


def load_subset(root):
    fhir_dir, dicom_dir = os.path.join(root, "fhir"), os.path.join(root, "dicom")
    out = []
    for fp in sorted(glob.glob(os.path.join(fhir_dir, "*.json"))):
        stem = os.path.basename(fp)[:-5]
        dcm = glob.glob(os.path.join(dicom_dir, stem + "*.dcm"))
        if not dcm:
            continue
        with open(fp) as f:
            bundle = json.load(f)
        res = [e["resource"] for e in bundle["entry"]]
        pat = next(r for r in res if r["resourceType"] == "Patient")
        enc = [r for r in res if r["resourceType"] == "Encounter"]
        hosp = Counter(e["serviceProvider"]["display"] for e in enc if "serviceProvider" in e)
        docs = set()
        for e in enc:
            hn = e.get("serviceProvider", {}).get("display")
            for part in e.get("participant", []):
                d = part.get("individual", {}).get("display")
                if d and hn:
                    docs.add((d, hn))
        # hospital that did the MRI: the encounter referenced by the ImagingStudy
        by_url = {e["fullUrl"]: e["resource"] for e in bundle["entry"]}
        img_h = None
        for r in res:
            if r["resourceType"] == "ImagingStudy":
                ref = r.get("encounter", {}).get("reference")
                if ref in by_url:
                    img_h = by_url[ref].get("serviceProvider", {}).get("display")
        ins = Counter(r["insurer"]["display"] for r in res
                      if r["resourceType"] == "ExplanationOfBenefit" and "insurer" in r)
        out.append(PatientData(
            stem=stem, pid=pat["id"], name=_name(pat), fhir_path=fp, dicom_path=dcm[0],
            imaging_hospital=img_h or hosp.most_common(1)[0][0], hospitals=sorted(hosp),
            doctors=sorted(docs), insurer=ins.most_common(1)[0][0] if ins else "Unknown Insurer",
            n_resources=len(res), fhir_bytes=os.path.getsize(fp), dicom_bytes=os.path.getsize(dcm[0])))
    return out


def dicom_summary(path):
    import pydicom
    ds = pydicom.dcmread(path, stop_before_pixels=True)
    return {"modality": str(getattr(ds, "Modality", "")), "rows": int(getattr(ds, "Rows", 0)),
            "cols": int(getattr(ds, "Columns", 0)), "frames": int(getattr(ds, "NumberOfFrames", 0) or 0),
            "bits": int(getattr(ds, "BitsAllocated", 0))}


INS_KEEP = {"Claim": ("resourceType", "id", "status", "type", "billablePeriod", "created", "total"),
            "ExplanationOfBenefit": ("resourceType", "id", "status", "type", "billablePeriod", "created", "total", "insurer"),
            "Coverage": ("resourceType", "id", "status", "type", "period", "payor")}


def insurance_view(bundle_bytes: bytes) -> bytes:
    """Minimum-necessary view for insurers: demographics (name, gender, birth date) and the
    billing totals of Claim / ExplanationOfBenefit / Coverage. No diagnoses, observations,
    medications, procedures, notes or imaging."""
    b = json.loads(bundle_bytes)
    out = []
    for e in b["entry"]:
        r = e["resource"]
        t = r["resourceType"]
        if t == "Patient":
            out.append({k: r[k] for k in ("resourceType", "id", "name", "gender", "birthDate") if k in r})
        elif t in INS_KEEP:
            out.append({k: r[k] for k in INS_KEEP[t] if k in r})
    return json.dumps({"resourceType": "Bundle", "type": "collection", "entry": [{"resource": r} for r in out]},
                      separators=(",", ":")).encode()
