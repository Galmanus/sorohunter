"""Ground-truth test for the P1 stateful coverage-guided fuzzer (soro `fuzz`).

The fuzzer explores sequences of calls to find bugs that only trigger after a
setup sequence — which single-shot probing structurally cannot reach.

  seq_vuln: fire() breaches ONLY after arm().  single-shot probe misses it;
            the fuzzer finds the sequence [arm -> fire].
  seq_safe: fire() is auth-gated regardless -> no sequence bypasses -> clean.

Deterministic (fixed seed) so the result is reproducible.
"""
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SORO = os.path.join(ROOT, "soro", "target", "release", "sorohunter")
ASSETS = os.path.join(ROOT, "soro", "assets")


def _need(name):
    if not os.path.exists(SORO):
        pytest.skip("soro binary not built")
    if not os.path.exists(os.path.join(ASSETS, name)):
        pytest.skip(f"fixture missing: {name}")


def _run(cmd):
    return subprocess.run([SORO] + cmd, capture_output=True, text=True, cwd=ROOT, timeout=120).stdout


def test_single_shot_misses_sequence_bug():
    _need("seq_vuln.wasm")
    out = _run(["probe", os.path.join(ASSETS, "seq_vuln.wasm")])
    assert "0 finding(s)" in out, "single-shot probe should miss the sequence-dependent bug"


def test_fuzzer_finds_sequence_breach():
    _need("seq_vuln.wasm")
    out = _run(["fuzz", os.path.join(ASSETS, "seq_vuln.wasm"), "--rounds", "300"])
    assert "1 stateful finding(s)" in out
    assert "BREACH" in out
    assert "arm -> fire" in out


def test_fuzzer_clean_on_safe():
    _need("seq_safe.wasm")
    out = _run(["fuzz", os.path.join(ASSETS, "seq_safe.wasm"), "--rounds", "300"])
    assert "0 stateful finding(s)" in out
