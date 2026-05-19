#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
RUNTIME_DIR="${TMPDIR:-/tmp}/ids-runtime-${USER:-user}"
MPL_DIR="$RUNTIME_DIR/matplotlib"
LOG_DIR="$RUNTIME_DIR/logs"

if [[ "${1:-}" == "--help" ]]; then
  echo "Usage:"
  echo "  ./run_macos.sh          Start the IDS GUI with sudo packet-capture permission"
  echo "  ./run_macos.sh --check  Verify Python imports and model loading"
  exit 0
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python virtual environment not found at: $PYTHON_BIN"
  echo "Create it with:"
  echo "  /opt/homebrew/bin/python3.13 -m venv .venv"
  echo "  .venv/bin/python -m pip install -r requirements.txt"
  exit 1
fi

mkdir -p "$MPL_DIR" "$LOG_DIR"

if [[ "${1:-}" == "--check" ]]; then
  PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR="$MPL_DIR" IDS_LOG_DIR="$LOG_DIR" "$PYTHON_BIN" -B - <<'PY'
import sys
sys.path.insert(0, "Tool")
sys.path.insert(0, "scripts")

from packet_sniffer import get_network_interfaces
from hybrid_model import MemoryEfficientHybridDLMLModel

model = MemoryEfficientHybridDLMLModel.load("models/hybrid_dl_ml_model.pkl")
print("Imports: OK")
print("Interfaces:", ", ".join(get_network_interfaces()[:5]))
print("Model classes:", ", ".join(str(c) for c in model.label_encoder.classes_))
PY
  exit 0
fi

cd "$ROOT_DIR/Tool"

# macOS packet capture uses /dev/bpf devices, which require root privileges.
exec sudo env PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR="$MPL_DIR" IDS_LOG_DIR="$LOG_DIR" "$PYTHON_BIN" -B optimized_sniffer_gui.py
