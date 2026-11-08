#!/usr/bin/env bash
# Writes the release tag and each script's SHA-256 into every GitLab template.
# Run it in the release commit, before tagging: scripts/pin-release.sh v1.2.0
set -euo pipefail

tag="${1:-}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Usage: scripts/pin-release.sh vX.Y.Z' >&2; exit 1; }

root="$(cd "$(dirname "$0")/.." && pwd)"
sha256() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

for template in "$root"/*/gitlab.yml; do
  dir="$(dirname "$template")"
  # Each template runs the scan.sh beside it.
  sum="$(sha256 "$dir/scan.sh")"
  sed -i.bak \
    -e "s/^\(    SENTINEL_ACTIONS_REF:\).*/\1 $tag/" \
    -e "s/^\(    SENTINEL_SCRIPT_SHA256:\).*/\1 $sum/" \
    "$template"
  rm -f "$template.bak"
  echo "$(basename "$dir")/gitlab.yml now runs scan.sh $tag ($sum)."
done
