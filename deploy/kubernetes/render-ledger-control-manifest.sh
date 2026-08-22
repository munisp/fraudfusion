#!/usr/bin/env bash
set -euo pipefail

: "${LEDGER_IMAGE_REFERENCE:?LEDGER_IMAGE_REFERENCE must be an immutable registry image digest}"
: "${LEDGER_INGRESS_CLASS:?LEDGER_INGRESS_CLASS is required}"
: "${LEDGER_HOSTNAME:?LEDGER_HOSTNAME is required}"
: "${LEDGER_TLS_SECRET_NAME:?LEDGER_TLS_SECRET_NAME is required}"

if [[ ! "$LEDGER_IMAGE_REFERENCE" =~ ^[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]]; then
  echo "LEDGER_IMAGE_REFERENCE must match registry/path@sha256:<64 lowercase hex characters>" >&2
  exit 2
fi
if [[ ! "$LEDGER_HOSTNAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]; then
  echo "LEDGER_HOSTNAME must be a DNS hostname" >&2
  exit 2
fi
if [[ ! "$LEDGER_INGRESS_CLASS" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ || ! "$LEDGER_TLS_SECRET_NAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
  echo "LEDGER_INGRESS_CLASS and LEDGER_TLS_SECRET_NAME must be Kubernetes DNS labels" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
escaped_image="$(printf '%s' "$LEDGER_IMAGE_REFERENCE" | sed 's/[&|]/\\&/g')"
escaped_class="$(printf '%s' "$LEDGER_INGRESS_CLASS" | sed 's/[&|]/\\&/g')"
escaped_host="$(printf '%s' "$LEDGER_HOSTNAME" | sed 's/[&|]/\\&/g')"
escaped_tls="$(printf '%s' "$LEDGER_TLS_SECRET_NAME" | sed 's/[&|]/\\&/g')"

sed \
  -e "s|__LEDGER_IMAGE_REFERENCE__|$escaped_image|g" \
  -e "s|__LEDGER_INGRESS_CLASS__|$escaped_class|g" \
  -e "s|__LEDGER_HOSTNAME__|$escaped_host|g" \
  -e "s|__LEDGER_TLS_SECRET_NAME__|$escaped_tls|g" \
  "$ROOT/ledger-control-service.yaml"
