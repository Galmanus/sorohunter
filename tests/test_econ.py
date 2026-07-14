"""Ground-truth test for the P2/P3 economic multi-call fuzzer (harness --econ).

The economic fuzzer sets up a real token + a funded target + an attacker, fuzzes
SEQUENCES of the target's economic functions with the attacker as the (legitimately
authorized) actor, and reports any sequence that leaves the attacker in net token
profit — value drained from the protocol. This finds bugs that auth-scan misses
(every call is authorized) and single-shot misses (the drain needs a sequence).
It tests composition-level solvency, which per-contract formal verification does
not model.

  econ_vuln: withdraw checks credit but forgets to decrement it -> the sequence
             deposit -> withdraw -> withdraw drains the reserve (attacker +100).
  econ_safe: withdraw decrements credit -> no sequence yields profit.

Deterministic (fixed seed).
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
        pytest.skip("harness binary not built")
    if not os.path.exists(wasm):
        pytest.skip(f"fixture missing: {name}")
    out = os.path.join(tmp_path, name + ".json")
    subprocess.run([BIN, "--econ", wasm, out, "deposit,withdraw"], check=True, cwd=ROOT)
    return json.load(open(out))


def test_econ_vuln_drains_via_sequence(tmp_path):
    d = _run("econ_vuln.wasm", tmp_path)
    assert d["verdict"] == "econ-drain"
    assert d["bypasses"] == 1
    detail = d["probes"][0]["detail"]
    assert "deposit -> withdraw -> withdraw" in detail
    assert "+100" in detail


def test_econ_safe_solvency_holds(tmp_path):
    d = _run("econ_safe.wasm", tmp_path)
    assert d["verdict"] == "held"
    assert d["bypasses"] == 0
