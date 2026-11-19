#!/usr/bin/env bash
# Usage: ./fetch_subset.sh [N]   (default N=20)
# Picks N patients that HAVE a DICOM image and downloads, for each, the DICOM file (~32 MiB)
# and the matching FHIR JSON (~1-12 MiB) into ./data/subset/{dicom,fhir}
set -u
export PATH="$HOME/.local/bin:$PATH"
N="${1:-20}"
B="s3://synthea-open-data/coherent/unzipped"
cd "$(dirname "$0")"
mkdir -p data/subset/dicom data/subset/fhir
aws s3 ls --no-sign-request "$B/dicom/" 2>/dev/null | awk '{print $4}' | grep '\.dcm$' > data/dicom_list.txt
echo "DICOM files in bucket: $(wc -l < data/dicom_list.txt)"
head -n "$N" data/dicom_list.txt | while read -r dcm; do
  stem=$(echo "$dcm" | sed -E 's/^(.+_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})1\.2\.840.*$/\1/')
  echo "== $stem"
  aws s3 cp --no-sign-request --only-show-errors "$B/dicom/$dcm" "data/subset/dicom/$dcm"
  aws s3 cp --no-sign-request --only-show-errors "$B/fhir/$stem.json" "data/subset/fhir/$stem.json" \
    || echo "   (no FHIR file found for $stem)"
done
echo "Done."; du -sh data/subset; ls data/subset/fhir | wc -l; ls data/subset/dicom | wc -l
