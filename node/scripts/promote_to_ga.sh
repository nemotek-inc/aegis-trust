#!/usr/bin/env bash
# promote_to_ga.sh — aegis-trust v0.9.0-rc* → v0.9.0 GA promotion
#
# Prerequisites (sprint_002 hard gate, NOT automatically verified by this script —
# operator must literal confirm before running):
#   1. 5 external oracle survey: top_1_pct_readability + dx_friction_audit verifier PASS
#      with 4/5 acceptance (productization_doctrine_complete label)
#   2. The 5 architectural P0 hardening items verified (sprint_002 hardening sprint close)
#   3. ≥ 30 day monitoring window since latest rc publish (memory feedback_distribution_*.md)
#   4. ≥ 3 external dev usage signals (npm DL trend / GitHub issue / community feedback)
#   5. Release-readiness v3 15-checklist 15/15 PASS literal
#
# What this script does (idempotent, dry-run by default):
#   1. Verify the latest rc tag (rc5 as of 2026-05-21) still latest on npm (catch accidental re-publish)
#   2. dist-tag promotion: latest=0.9.0 (replacing 0.8.1)
#   3. dist-tag retire: rc (no longer needed for production users)
#   4. Tag v0.9.0 in git + push → release.yml GA fire
#   5. README + AGENTS.md + CHANGELOG: STABILITY_LEVEL "preview" → "stable" + GA note
#
# Usage:
#   bash scripts/promote_to_ga.sh --dry-run         # preview, no changes (default)
#   bash scripts/promote_to_ga.sh --confirm-prereqs # actually promote (operator confirms 1-5)
#
# Operator override (if a later rc has been published since this script was last updated):
#   AEGIS_RC_TAG=0.9.0-rc6 bash scripts/promote_to_ga.sh --dry-run
#
# AO-check: Gate-1~6 considerations
# - AO-001/002: dist-tag change is npm registry-side, not Aegis trust boundary
# - AO-003: tag promotion event must be recorded in decision_log (D-XXX)
# - AO-006: no secrets, OTP via authenticator app required for npm dist-tag promote

set -euo pipefail

# T-S179 reconciliation (2026-05-21): canonical package name is `aegis-trust`
# (not `@aegis_trust/sdk`). Current latest rc is rc5; parametrise via
# AEGIS_RC_TAG so future rc bumps don't silently regress this script.
AEGIS_PKG="${AEGIS_PKG:-aegis-trust}"
AEGIS_RC_TAG="${AEGIS_RC_TAG:-0.9.0-rc5}"

MODE="${1:-}"
[ "$MODE" != "--dry-run" ] && [ "$MODE" != "--confirm-prereqs" ] && {
    echo "Usage: $0 [--dry-run | --confirm-prereqs]"
    echo ""
    sed -n '2,30p' "$0"
    exit 2
}

DRY_RUN=1
[ "$MODE" = "--confirm-prereqs" ] && DRY_RUN=0

cd "$(dirname "$0")/.."  # cwd = node/ (canonical monorepo layout per T-006c)

echo "=== Step 1: verify ${AEGIS_RC_TAG} status (package: ${AEGIS_PKG}) ==="
npm view "${AEGIS_PKG}@${AEGIS_RC_TAG}" version 2>&1 | head -2 || { echo "ERROR: ${AEGIS_PKG}@${AEGIS_RC_TAG} not published" >&2; exit 2; }
echo ""

echo "=== Step 2: dist-tag promotion preview ==="
echo "  current dist-tags:"
npm dist-tag ls "${AEGIS_PKG}" 2>&1 | sed 's/^/    /'
echo "  planned after promotion:"
echo "    latest: 0.9.0"
echo "    (rc tag retired)"
echo ""

if [ "$DRY_RUN" = "1" ]; then
    echo "=== DRY RUN — no changes made ==="
    echo "Operator: confirm 5 prereqs (see top of script comments), then re-run with --confirm-prereqs"
    exit 0
fi

echo "=== CONFIRM-PREREQS mode — operator has attested 1-5 hard gate ==="
echo "Press Ctrl-C within 10 seconds to abort..."
sleep 10
echo ""

echo "=== Step 3: bump source v${AEGIS_RC_TAG} → v0.9.0 ==="
sed -i.bak "s/\"version\": \"${AEGIS_RC_TAG}\"/\"version\": \"0.9.0\"/" package.json
echo "0.9.0" > VERSION
sed -i.bak 's/STABILITY_LEVEL: "preview" | "stable" | "deprecated" = "preview"/STABILITY_LEVEL: "preview" | "stable" | "deprecated" = "stable"/' src/index.ts
echo "  package.json, VERSION, src/index.ts updated"
echo ""

echo "=== Step 4: build + test ==="
npm run build
npm test
echo ""

echo "=== Step 5: git commit + tag + push ==="
cd ..
git add node/{package.json,VERSION,src/index.ts}
git commit -m "[GA] ${AEGIS_PKG} v0.9.0 GA promotion — 5 oracle PASS + P0 hardening + 30d monitoring complete"
git tag -a "v0.9.0" -m "${AEGIS_PKG} v0.9.0 GA — internal-ops sprint_002 close + 30d monitoring"
git push origin "$(git branch --show-current)"
git push origin v0.9.0
echo ""

echo "=== Step 6: npm publish v0.9.0 + dist-tag promote ==="
echo "  Requires OTP from authenticator app (recovery codes for breakglass only)"
echo "  Run manually after Giri authorization:"
echo "    cd node && npm publish --tag latest --access public --otp=<TOTP>"
echo "    npm dist-tag rm ${AEGIS_PKG} rc"
echo ""

echo "=== Step 7: post-promotion verify ==="
echo "  npm view ${AEGIS_PKG} version  # expect 0.9.0"
echo "  npm dist-tag ls ${AEGIS_PKG}    # expect latest=0.9.0 only"
echo ""

echo "[GA promotion completed in script — manual npm publish + dist-tag step pending operator]"
