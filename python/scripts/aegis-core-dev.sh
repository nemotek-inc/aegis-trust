#!/usr/bin/env bash
# aegis-core dev runner for Tier β integration tests (S024 rewrite).
#
# T-158: SHA-tagged image cache — skip the 15-30 min Rust rebuild when
#        the aegis-core source tree hasn't changed. Docker images are
#        tagged with the short git SHA; `up` retags :latest to the
#        current SHA when the image already exists, otherwise builds.
# T-175: AEGIS_CORE_DIR remote URL allowlist (STRIDE Spoof mitigation) —
#        verify the referenced checkout points at the canonical
#        aegis-core remote before we trust its Dockerfile.
# T-159: compose file carries no build block — build logic lives only
#        here so cache behaviour is a single source of truth.
#
# Subcommands:
#   up      — start aegis-core, building only on cache miss
#   down    — stop + remove container (image cache preserved)
#   status  — ps + health probe
#   logs    — tail container logs
#   sha     — print the current AEGIS_CORE_DIR SHA (for attestation)
#   image   — print the full image digest for attestation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/aegis-core.compose.yml"
IMAGE_NAME="aegis-core-dev"
# AO-001 spoof prevention: only trust remotes pointing at the canonical
# aegis-core repo. The canonical owner is deliberately NOT hardcoded here —
# this repo is public and aegis-core is not — so the allowlist is supplied out
# of band, by whichever of these is set first:
#
#   1. AEGIS_CORE_REMOTE_ALLOWLIST      — comma-separated anchored regexes
#   2. AEGIS_CORE_REMOTE_ALLOWLIST_FILE — one anchored regex per line
#      (default: $XDG_CONFIG_HOME/aegis-trust/core-remote-allowlist, falling
#      back to $HOME/.config/...; blank lines and #-comment lines ignored)
#
# With neither configured the check FAILS CLOSED: an unconfigured runner
# refuses every AEGIS_CORE_DIR rather than silently trusting all of them.
#
# Anchored patterns only, and this is ENFORCED, not merely requested: every
# pattern must start with "^" and end with "$". An unanchored pattern such as
# "." matches every remote and would silently turn the allowlist off, so a
# pattern that is not anchored is refused instead of trusted. Anchoring is what
# stops strings like https://evil.example/github.com/... from sneaking past.
ALLOWLIST_FILE="${AEGIS_CORE_REMOTE_ALLOWLIST_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/aegis-trust/core-remote-allowlist}"

load_allowlist() {
  local raw=() line pattern
  if [[ -n "${AEGIS_CORE_REMOTE_ALLOWLIST:-}" ]]; then
    IFS=',' read -ra raw <<<"$AEGIS_CORE_REMOTE_ALLOWLIST"
  elif [[ -r "$ALLOWLIST_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      raw+=("$line")
    done <"$ALLOWLIST_FILE"
  fi

  ALLOWLIST_PATTERNS=()
  if [[ ${#raw[@]} -gt 0 ]]; then
    for pattern in "${raw[@]}"; do
      # Trim surrounding whitespace; drop blank entries and comment lines.
      pattern="${pattern#"${pattern%%[![:space:]]*}"}"
      pattern="${pattern%"${pattern##*[![:space:]]}"}"
      [[ -z "$pattern" || "$pattern" == \#* ]] && continue
      if [[ "$pattern" != \^* || "$pattern" != *\$ ]]; then
        cat >&2 <<EOF
error: aegis-core remote allowlist pattern is not anchored:

  $pattern

Every pattern must start with "^" and end with "\$". An unanchored pattern
matches remotes it was never meant to (". " matches all of them), which would
turn this trust check off without saying so. Refusing rather than trusting.
EOF
        exit 2
      fi
      ALLOWLIST_PATTERNS+=("$pattern")
    done
  fi

  if [[ ${#ALLOWLIST_PATTERNS[@]} -eq 0 ]]; then
    cat >&2 <<EOF
error: no aegis-core remote allowlist is configured, so no AEGIS_CORE_DIR can
be trusted (fail-closed).

Configure the canonical remote once, either as an environment variable:

    export AEGIS_CORE_REMOTE_ALLOWLIST='^(https://|git@)github\\.com[:/]OWNER/aegis[_-]core(\\.git)?$'

or in a file (one anchored regex per line):

    $ALLOWLIST_FILE

Anchor every pattern with ^...$ so a lookalike remote cannot match.
EOF
    exit 2
  fi
}

require_env() {
  if [[ -z "${AEGIS_CORE_DIR:-}" ]]; then
    cat >&2 <<'EOF'
error: AEGIS_CORE_DIR is not set.

Point it at your aegis-core checkout so the build context is
reproducible across dev machines. Example:

    export AEGIS_CORE_DIR="$HOME/projects/aegis-core"

See scripts/aegis-core.compose.yml for the expected Dockerfile layout.
EOF
    exit 2
  fi
  if [[ ! -f "$AEGIS_CORE_DIR/Dockerfile" ]]; then
    echo "error: $AEGIS_CORE_DIR/Dockerfile not found." >&2
    exit 2
  fi
  if [[ ! -d "$AEGIS_CORE_DIR/.git" ]]; then
    echo "error: $AEGIS_CORE_DIR is not a git checkout; refusing to trust an arbitrary tree." >&2
    exit 2
  fi
  local remote
  remote="$(git -C "$AEGIS_CORE_DIR" remote get-url origin 2>/dev/null || true)"
  if [[ -z "$remote" ]]; then
    echo "error: $AEGIS_CORE_DIR has no origin remote; refusing to trust it." >&2
    exit 2
  fi
  local pattern ok=0
  load_allowlist
  for pattern in "${ALLOWLIST_PATTERNS[@]}"; do
    if [[ "$remote" =~ $pattern ]]; then
      ok=1
      break
    fi
  done
  if [[ $ok -ne 1 ]]; then
    cat >&2 <<EOF
error: $AEGIS_CORE_DIR origin is "$remote" which does not match the
aegis-core remote allowlist:

${ALLOWLIST_PATTERNS[*]}

This protects the β runner from a spoofed AEGIS_CORE_DIR (AO-001
trust boundary). Set AEGIS_CORE_REMOTE_ALLOWLIST (or add a line to
$ALLOWLIST_FILE) to approve an additional fork.
EOF
    exit 2
  fi
}

core_sha() {
  git -C "$AEGIS_CORE_DIR" rev-parse --short=12 HEAD
}

image_tag_for_sha() {
  echo "${IMAGE_NAME}:${1}"
}

image_digest() {
  local tag="${1:-${IMAGE_NAME}:latest}"
  docker image inspect --format='{{.Id}}' "$tag" 2>/dev/null || echo ""
}

ensure_image() {
  local sha tag
  sha="$(core_sha)"
  tag="$(image_tag_for_sha "$sha")"
  if docker image inspect "$tag" >/dev/null 2>&1; then
    echo "[aegis-core-dev] cache hit: $tag (source SHA $sha)"
  else
    echo "[aegis-core-dev] cache miss: building $tag (may take 15-30 min)"
    docker build -t "$tag" "$AEGIS_CORE_DIR"
  fi
  # Always retag :latest so compose picks up this SHA.
  docker tag "$tag" "${IMAGE_NAME}:latest"
  echo "[aegis-core-dev] :latest -> $tag"
}

cmd="${1:-up}"
case "$cmd" in
  up)
    require_env
    ensure_image
    docker compose -f "$COMPOSE_FILE" up -d
    ;;
  down)
    docker compose -f "$COMPOSE_FILE" down
    ;;
  status)
    docker compose -f "$COMPOSE_FILE" ps
    if curl -skf https://localhost:8443/api/v1/health >/dev/null; then
      echo "aegis-core: OK"
    else
      echo "aegis-core: NOT reachable"
      exit 1
    fi
    ;;
  logs)
    docker compose -f "$COMPOSE_FILE" logs --tail=200 -f
    ;;
  sha)
    require_env
    core_sha
    ;;
  image)
    image_digest "${IMAGE_NAME}:latest"
    ;;
  *)
    echo "usage: $0 {up|down|status|logs|sha|image}" >&2
    exit 64
    ;;
esac
