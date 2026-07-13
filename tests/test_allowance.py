"""Ground-truth test for the unrestricted-`transfer_from` prover (harness
--allowance).

This is the gap-filler against the static Soroban linters (CoinFabrik Scout's
`unrestricted-transfer-from`, which flags the pattern but cannot confirm
exploitability; OpenZeppelin's SDK has no equivalent). sorohunter's economic
detectors (`drain`/`greed`) watch the contract's and attacker's balances; the
allowance-drain class moves a *victim's* approved balance, which none of them
watch. This prover sets up the victim allowance state and PROVES the drain by
execution:

  unauth_pull -> allowance-drain (victim's 1000 tokens moved under empty auth)
  auth_pull   -> held           (from.require_auth() reverts the empty-auth call)

`auth_pull` is the load-bearing FP control: it runs the identical transfer_from on
the same victim allowance and differs by one line (`from.require_auth()`), so an
`allowance-drain` verdict reads the missing check specifically, not a parse or
setup failure. If `auth_pull` ever drains, the prover is broken.

Skips (does not fail) if the harness binary or fixture wasms are not built. Build:
  (cd harness && cargo build --release)
  (cd bench && cargo build --release --target wasm32v1-none -p unauth_pull -p auth_pull)
  cp bench/target/wasm32v1-none/release/{unauth,auth}_pull.wasm soro/assets/
"""
import json
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "harness", "target", "release", "harness")
ASSETS = os.path.join(ROOT, "soro", "assets")


def _run(wasm_name, tmp_path):
    wasm = os.path.join(ASSETS, wasm_name)
    if not os.path.exists(BIN):
        pytest.skip(f"harness binary not built at {BIN}")
    if not os.path.exists(wasm):
        pytest.skip(f"fixture wasm missing: {wasm}")
    out = os.path.join(tmp_path, wasm_name + ".json")
    subprocess.run([BIN, "--allowance", wasm, out, "pull:address,i128"], check=True, cwd=ROOT)
    return json.load(open(out))


def test_unauth_pull_drains_victim(tmp_path):
    """The bug: transfer_from on a victim's allowance with no from.require_auth()."""
    d = _run("unauth_pull.wasm", tmp_path)
    assert d["verdict"] == "allowance-drain"
    assert d["bypasses"] == 1
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["empty-auth-pull"]["bypass"] is True
    assert "moved 1000" in probes["empty-auth-pull"]["detail"]


def test_auth_pull_zero_false_positive(tmp_path):
    """The FP control: same transfer_from, plus from.require_auth(). Must hold."""
    d = _run("auth_pull.wasm", tmp_path)
    assert d["verdict"] == "held"
    assert d["bypasses"] == 0
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["empty-auth-pull"]["bypass"] is False
