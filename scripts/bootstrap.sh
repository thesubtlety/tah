#!/usr/bin/env bash
# tah setup. Builds the binary. Presidio (PII) is optional and OFF by default —
# credentials are recognized without it. Enable with:  scripts/bootstrap.sh --presidio
set -euo pipefail
cd "$(dirname "$0")/.."

command -v go >/dev/null || { echo "Need Go 1.27+   (brew install go)"; exit 1; }
go build -o bin/tah ./cmd/tah
echo "built ./bin/tah"

if [[ "${1:-}" == "--presidio" ]]; then
  command -v python3 >/dev/null || { echo "python3 required for --presidio"; exit 1; }
  # A venv avoids the 'externally-managed-environment' pip error on macOS/Homebrew
  # Python (PEP 668). tah auto-detects presidio/.venv.
  python3 -m venv presidio/.venv
  presidio/.venv/bin/python -m pip install -q --upgrade pip
  presidio/.venv/bin/python -m pip install -q -r presidio/requirements.txt
  presidio/.venv/bin/python -m spacy download en_core_web_lg >/dev/null 2>&1 \
    && echo "Presidio + NER model installed in presidio/.venv" \
    || echo "Presidio installed in presidio/.venv (NER model skipped; regex/checksum PII still works)"
else
  echo "Presidio: OFF (optional). Credentials still recognized without it."
  echo "  enable PII later:  scripts/bootstrap.sh --presidio"
fi

cat <<'NOTE'

Run it — ONE daemon (eslogger + net/DNS + content recognition):
  sudo ./bin/tah snapshot      # once: seed pre-existing state
  sudo ./bin/tah collect       # the daemon; leave it running
  ./bin/tah status             # confirm it is capturing (no sudo)
  ./bin/tah report             # findings (no sudo)

The db lives at ~/.tah/tah.db and is shared between the sudo daemon and your
non-root queries. Full Disk Access (eslogger) is a GUI/MDM grant — no pure-CLI way.
NOTE
