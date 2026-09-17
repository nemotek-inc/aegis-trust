#!/usr/bin/env bash
# Local + CI wrapper to invoke the time_to_first_call verifier against the
# current node SDK source. Packs the SDK, materialises a clean CJS workdir,
# exports the env-var contract the release gate expects, then runs the
# verifier.
#
# Usage:
#   bash node/tests/timing/run_timing_gate.sh
#
# Exit 0 = PASS, non-zero = FAIL.

set -euo pipefail

SDK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd )"
# OPS_ROOT must point at the maintainer's local quality-gate root (not committed
# to this repo). No internal default is hardcoded here.
OPS_ROOT="${OPS_ROOT:?set OPS_ROOT to the local quality-gate root containing verifiers/}"
VERIFIER="${OPS_ROOT}/verifiers/time_to_first_call.py"

if [ ! -f "$VERIFIER" ]; then
  echo "time_to_first_call verifier not found at $VERIFIER" >&2
  exit 2
fi

cd "$SDK_DIR"
# Cross-review round 1 P1-G2: drop any older tgz before pack so `ls -t`
# can never pick up a stale tarball (CI artifact pollution).
rm -f aegis_trust-sdk-*.tgz
npm pack >/dev/null
TGZ="$(ls -t aegis_trust-sdk-*.tgz | head -1)"
TGZ_ABS="$SDK_DIR/$TGZ"
echo "[timing-gate] packed: $TGZ_ABS"

WORKDIR="$(mktemp -d /tmp/aegis-timing-XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

cat > "$WORKDIR/package.json" <<EOF
{ "name": "aegis-timing-harness", "private": true, "version": "0.0.0", "type": "commonjs" }
EOF

export PRODUCTIZATION_TIMING_INSTALL_CMD="npm install $TGZ_ABS"
export PRODUCTIZATION_TIMING_FIRST_CALL_SCRIPT="$SDK_DIR/tests/timing/first_call_script.js"

echo "[timing-gate] PRODUCTIZATION_TIMING_INSTALL_CMD=$PRODUCTIZATION_TIMING_INSTALL_CMD"
echo "[timing-gate] PRODUCTIZATION_TIMING_FIRST_CALL_SCRIPT=$PRODUCTIZATION_TIMING_FIRST_CALL_SCRIPT"

python3 "$VERIFIER" \
  --package "aegis-trust" \
  --install-cmd "$PRODUCTIZATION_TIMING_INSTALL_CMD" \
  --first-call-script "$PRODUCTIZATION_TIMING_FIRST_CALL_SCRIPT" \
  --workdir "$WORKDIR" \
  --threshold 60 \
  --json
