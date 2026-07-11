#!/usr/bin/env bash
# TEMPEST algebraic-ground-truth oracles — runner
# Applies the field/order oracle patch to a pinned rs-soroban-env checkout and runs it.
# The field oracles call pub(crate) host fns, so they MUST live inside the crate (hence a patch).
set -euo pipefail

SHA="c212b91"                                   # pinned host revision the oracles were verified against
ENV_DIR="${1:-$HOME/sorohunter/hunt/rs-soroban-env}"
PATCH="$(cd "$(dirname "$0")" && pwd)/tempest_soroban_env_${SHA}.patch"
export PATH="$HOME/.cargo/bin:$PATH"

if [ ! -d "$ENV_DIR/.git" ]; then
  echo "rs-soroban-env checkout not found at: $ENV_DIR"
  echo "clone it and check out $SHA, then re-run:  $0 <path-to-rs-soroban-env>"
  echo "  git clone https://github.com/stellar/rs-soroban-env && cd rs-soroban-env && git checkout $SHA"
  exit 1
fi

cd "$ENV_DIR"
HAVE="$(git rev-parse --short HEAD)"
[ "$HAVE" = "$SHA" ] || echo "WARN: checkout is $HAVE, oracles verified against $SHA — line offsets may drift"

# apply patch if not already applied (idempotent)
if git apply --check --reverse "$PATCH" >/dev/null 2>&1; then
  echo "oracles already applied."
elif git apply --check "$PATCH" >/dev/null 2>&1; then
  git apply "$PATCH" && echo "oracles applied."
else
  echo "ERROR: patch does not apply cleanly to $HAVE (expected $SHA)."; exit 1
fi

echo "=== running 5 TEMPEST oracles ==="
cargo test -p soroban-env-host --lib tempest -- --nocapture 2>&1 \
  | grep -vE "Compiling|Finished|warning:|^\s*$" | tail -45
