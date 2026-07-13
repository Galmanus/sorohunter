"""Ground-truth test for the auth-arg scope-mismatch prover (harness --scope),
the TA-04 class.

A payment fn that authorizes the payer with `require_auth_for_args` scoped too
narrowly (omitting the recipient/amount) lets one authorization be replayed to any
recipient. The prover mocks an authorization for the payer scoped to ONLY the
payer address, then calls `pay(payer, attacker, amount)`:

  scoped_vuln -> scope-mismatch (500 moved to the attacker under the [payer] auth)
  scoped_safe -> held           (require_auth binds full args -> the mock fails)

scoped_safe is the load-bearing FP control: identical `pay`, differs by
`require_auth()` (binds from,to,amount) vs `require_auth_for_args([from])`. The
verdict is confirmed by real value movement, not just call success.
"""
import json
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "harness", "target", "release", "harness")
ASSETS = os.path.join(ROOT, "soro", "assets")


def _run(name, tmp_path):
    wasm = os.path.join(ASSETS, name)
    if not os.path.exists(BIN):
        pytest.skip(f"harness binary not built at {BIN}")
    if not os.path.exists(wasm):
        pytest.skip(f"fixture wasm missing: {wasm}")
    out = os.path.join(tmp_path, name + ".json")
    subprocess.run([BIN, "--scope", wasm, out], check=True, cwd=ROOT)
    return json.load(open(out))


def test_scoped_vuln_redirects(tmp_path):
    d = _run("scoped_vuln.wasm", tmp_path)
    assert d["verdict"] == "scope-mismatch"
    assert d["bypasses"] == 1
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["redirect-under-scope"]["bypass"] is True
    assert "500 moved" in probes["redirect-under-scope"]["detail"]


def test_scoped_safe_zero_false_positive(tmp_path):
    d = _run("scoped_safe.wasm", tmp_path)
    assert d["verdict"] == "held"
    assert d["bypasses"] == 0
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["redirect-under-scope"]["bypass"] is False
