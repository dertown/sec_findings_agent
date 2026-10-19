#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist"
APP="$ROOT/es_finding_evidence"
mkdir -p "$OUT"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/es_finding_evidence"
# Package the app directory only (exclude tests and local caches).
tar -C "$APP" -cf - \
  --exclude='*.pyc' \
  --exclude='__pycache__' \
  --exclude='.DS_Store' \
  . | tar -C "$STAGE/es_finding_evidence" -xf -
# Splunk .spl is a gzip tarball whose top-level folder is the app id.
tar -C "$STAGE" -czf "$OUT/es_finding_evidence-1.2.0.spl" es_finding_evidence
echo "Wrote $OUT/es_finding_evidence-1.2.0.spl"
tar -tzf "$OUT/es_finding_evidence-1.2.0.spl" | head -n 20 || true
