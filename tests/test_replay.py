"""Ground-truth test for the signature-binding prover (harness --replay).

This is the passkey class. Unlike --checkauth (which throws forgeries at an
account that ignores its signature), --replay holds the signer key, produces ONE
genuinely valid signature, and asks a question a forgery battery cannot: is that
valid signature BOUND to the payload it authorizes? A wallet that verifies the
assertion but not the challenge (cf. swig-wallet #143) lets a valid pair for
payload A authorize payload B.

  bound_account   -> held         (0 bypass)  <- FP gate: parses the SAME blob as unbound, still refuses cross-payload replay
  unbound_account -> replay-bypass (1 bypass)  <- verifies the sig but not the binding -> cross-payload replay
  good_account    -> inconclusive (0 bypass)  <- different (raw BytesN<64>) ABI: prover must NOT invent a verdict

The bound/unbound pair is the load-bearing control: both verify a real ed25519
signature (forgery-control probe rejects garbage on both), both accept the valid
pair for its own payload (positive-path probe), and they differ ONLY on the one
line that binds msg == signature_payload. So a bypass here reads the binding bug
specifically, not a parse failure or a missing verify.

Build with:
  (cd harness && cargo build --release)
  (cd bench && cargo build --release --target wasm32v1-none \\
       -p unbound_account -p bound_account -p good_account)
  cp bench/target/wasm32v1-none/release/{unbound,bound,good}_account.wasm soro/assets/
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
    out = os.path.join(tmp_path, "replay_" + wasm_name + ".json")
    subprocess.run([BIN, "--replay", wasm, out, ctor_csv], check=True, cwd=ROOT)
    return json.load(open(out))


def _probe(d, name):
    return next(p for p in d["probes"] if p["probe"] == name)


def test_bound_account_zero_false_positive(tmp_path):
    """The FP gate: a correct account that binds sig->payload shows ZERO bypass,
    while still accepting the valid pair for its own payload."""
    d = _run("bound_account.wasm", "bytes_n:32", tmp_path)
    assert d["verdict"] == "held"
    assert d["bypasses"] == 0
    assert _probe(d, "positive-path")["bypass"] is False
    assert _probe(d, "cross-payload-replay")["bypass"] is False


def test_unbound_account_replay_caught(tmp_path):
    """The bug: verifies the signature but not the binding. The valid pair for A
    must authorize B (cross-payload replay), and only that probe is a bypass."""
    d = _run("unbound_account.wasm", "bytes_n:32", tmp_path)
    assert d["verdict"] == "replay-bypass"
    assert d["bypasses"] == 1
    # Baseline holds: a valid sig IS accepted, and a forgery IS rejected. Without
    # both, a cross-payload Ok would be meaningless.
    assert "REJECTED" not in _probe(d, "positive-path")["detail"]
    assert _probe(d, "forgery-control")["bypass"] is False
    assert _probe(d, "cross-payload-replay")["bypass"] is True


def test_good_account_wrong_abi_is_inconclusive(tmp_path):
    """good_account takes a raw BytesN<64>, not the 96-byte blob ABI. The prover
    must report `inconclusive` (no valid baseline), never a bypass or a false
    `held`."""
    d = _run("good_account.wasm", "bytes_n:32", tmp_path)
    assert d["verdict"] == "inconclusive"
    assert d["bypasses"] == 0
