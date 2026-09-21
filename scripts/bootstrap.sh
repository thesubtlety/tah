#!/usr/bin/env bash
# tah macOS first-run setup. Idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Go"
command -v go >/dev/null || { echo "install Go 1.27+ (https://go.dev/dl) then re-run"; exit 1; }
go build -o bin/tah ./cmd/tah
echo "    built bin/tah"

echo "==> Presidio (content classifier for the scan worker)"
if command -v python3 >/dev/null; then
  python3 -m pip install --user -q -r presidio/requirements.txt || \
    echo "    pip failed; run: python3 -m pip install presidio-analyzer"
  # NER entities (PERSON/LOCATION/medical) need a spaCy model; regex/checksum
  # entities (SSN, credit card, IBAN...) work without one. Grab lg if you want NER.
  python3 -m spacy download en_core_web_lg || \
    echo "    NER model not installed — regex/checksum PII still works; PERSON/LOCATION won't"
else
  echo "    python3 not found — 'tah scan' will be a no-op until Presidio is installed"
fi

cat <<'NOTE'

==> Grant access (once), then run:
    Endpoint Security via eslogger needs root + Full Disk Access.
    Grant Full Disk Access to your terminal (or the tah binary) in
    System Settings > Privacy & Security > Full Disk Access.

    sudo ./bin/tah snapshot --db tah.db      # seed pre-existing state (cold start)
    sudo ./bin/tah collect  --db tah.db      # eslogger + net/DNS pollers
    ./bin/tah watch   --db tah.db            # live odd-activity view
    ./bin/tah scan    --db tah.db            # run Presidio over queued files

    For cleartext DNS names, install an mDNSResponder profile with
    Privacy-Enable-Level = Sensitive (private_data:on alone is NOT enough).
NOTE
