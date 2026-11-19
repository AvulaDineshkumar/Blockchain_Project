#!/usr/bin/env bash
# Synthea Coherent Data Set (public bucket, no AWS account needed) -> ./data
# Usage:
#   ./download_data.sh list                  -> top level of the bucket
#   ./download_data.sh ls <subfolder>/       -> browse a subfolder (e.g. unzipped/)
#   ./download_data.sh get <path>            -> download ONE file into ./data (path relative to coherent/)
#   ./download_data.sh sync <subfolder>/ "<pattern>" [N] -> download files matching pattern from a subfolder
set -e
export PATH="$HOME/.local/bin:$PATH"
BUCKET="s3://synthea-open-data/coherent/"
cd "$(dirname "$0")"
mkdir -p data
command -v aws >/dev/null 2>&1 || python3 -m pip install --user awscli
case "$1" in
  list) aws s3 ls --no-sign-request --human-readable --summarize "$BUCKET" ;;
  ls)   aws s3 ls --no-sign-request --human-readable "${BUCKET}$2" | head -${3:-60} ;;
  get)  [ -n "$2" ] || { echo "give a path"; exit 1; }
        mkdir -p "data/$(dirname "$2")"
        aws s3 cp --no-sign-request "${BUCKET}$2" "./data/$2" ;;
  sync) [ -n "$2" ] && [ -n "$3" ] || { echo "give subfolder and pattern"; exit 1; }
        aws s3 sync --no-sign-request "${BUCKET}$2" "./data/$2" --exclude "*" --include "$3" ;;
  *)    sed -n '2,8p' "$0" ;;
esac
