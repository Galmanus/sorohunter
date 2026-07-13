"""Ground-truth test for the auth-bypass prover (harness --checkauth).

The prover drives a smart account's real `__check_auth` via
`try_invoke_contract_check_auth` (no mock_all_auths) and reports a bypass when
the account approves a forged/absent signature. Its whole value is one property:
zero false positives on a correct account. These assertions codify that:

  good_account       -> held        (0 bypass)  <- the FP gate; if this breaks, the prover is worthless
  blind_account      -> auth-bypass (all probes) <- "returns Ok" bug, caught everywhere
  void_guard_account -> auth-bypass (void rejected, non-void bypass) <- subtle bug read precisely

Skips (does not fail) if the harness binary or the fixture wasms are not built,
so the suite stays green on a machine without the Rust toolchain. Build with:
  (cd harness && cargo build --release)
  (cd bench && cargo build --release --target wasm32v1-none \\
       -p good_account -p blind_account -p void_guard_account)
  cp bench/target/wasm32v1-none/release/{good,blind,void_guard}_account.wasm soro/assets/
"""
import json
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "harness", "target", "release", "harness")
ASSETS = os.path.join(ROOT, "soro", "assets")


def _run(wasm_name, ctor_csv, tmp_path):
    wasm = os.path.join(ASSETS, wasm_name)
    if not os.path.exists(BIN):
        pytest.skip(f"harness binary not built at {BIN}")
    if not os.path.exists(wasm):
        pytest.skip(f"fixture wasm missing: {wasm}")
    out = os.path.join(tmp_path, wasm_name + ".json")
    subprocess.run([BIN, "--checkauth", wasm, out, ctor_csv], check=True, cwd=ROOT)
    return json.load(open(out))


def test_good_account_zero_false_positive(tmp_path):
    """The load-bearing gate: a correct ed25519 account must show ZERO bypass."""
    d = _run("good_account.wasm", "bytes_n:32", tmp_path)
    assert d["verdict"] == "held"
    assert d["bypasses"] == 0
    assert all(p["bypass"] is False for p in d["probes"])


def test_blind_account_fully_caught(tmp_path):
    """`__check_auth` that returns Ok without checking: every probe is a bypass."""
    d = _run("blind_account.wasm", "", tmp_path)
    assert d["verdict"] == "auth-bypass"
    assert d["bypasses"] == len(d["probes"]) == 10


def test_void_guard_precise(tmp_path):
    """Only rejects a void signature; the prover must bypass on every non-void
    hypothesis and reject exactly the void ones."""
    d = _run("void_guard_account.wasm", "", tmp_path)
    assert d["verdict"] == "auth-bypass"
    for p in d["probes"]:
        if p["hypothesis"] == "void":
            assert p["bypass"] is False, "void must be rejected"
        else:
            assert p["bypass"] is True, f"{p['hypothesis']} should bypass a void-only guard"
