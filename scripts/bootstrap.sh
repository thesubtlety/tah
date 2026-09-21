#!/usr/bin/env bash
# tah setup. Idempotent. Presidio is optional — the tool runs without it.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v go >/dev/null || { echo "Need Go 1.27+   (brew install go)"; exit 1; }
go build -o bin/tah ./cmd/tah
echo "built ./bin/tah"

# Optional: PII content classification. Without it, sensitive files just queue.
if command -v python3 >/dev/null && python3 -m pip --version >/dev/null 2>&1; then
  python3 -m pip install --user -q -r presidio/requirements.txt && echo "Presidio installed"
  python3 -m spacy download en_core_web_lg >/dev/null 2>&1 \
    && echo "spaCy NER model installed" \
    || echo "NER model skipped — regex/checksum PII (SSN, cards, IBAN) still works"
else
  echo "Presidio skipped (optional; needs python3 + pip). PII files queue until installed."
fi

cat <<'NOTE'

Run it — ONE daemon does collection + net/DNS + PII scan:
  sudo ./bin/tah snapshot      # once: seed pre-existing state
  sudo ./bin/tah collect       # the daemon; leave it running
  ./bin/tah status             # confirm it is capturing

Look at it — read-only, any time, no sudo, no extra daemon:
  ./bin/tah report
  ./bin/tah watch              # live view
  ./bin/tah rank  

Full Disk Access (eslogger needs it) is a GUI/MDM grant — there is no pure-CLI
way to turn it on. On a headless/remote Mac:
  * screen-share once and add ./bin/tah in
    System Settings > Privacy & Security > Full Disk Access, or
  * push a PPPC profile via MDM granting SystemPolicyAllFiles to the binary.
NOTE
