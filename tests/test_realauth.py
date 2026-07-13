"""Ground-truth test for the real-target auth provers (harness --realauth,
--realauth-p256).

Unlike --checkauth/--replay, which drive synthetic fixtures, these provers
deploy a contract via its real passkey-kit `Signer` constructor and drive the
genuine `__check_auth` with a real signature wrapped in the target's own
`Signatures(Map<SignerKey, Signature>)` type. Two branches:

  --realauth       ed25519 branch. A correct ed25519_verify binds the signature
                   to the payload by construction, so this branch mostly proves
                   the machinery lands and cannot be forged.
  --realauth-p256  secp256r1 / WebAuthn branch. This is where the binding bug
                   (swig-wallet #143) lives: verify the ECDSA assertion but never
                   check clientDataJSON.challenge == payload. The load-bearing
                   pair:
                     bound_passkey   -> held           (0 bypass)  <- FP gate
                     unbound_passkey -> replay-bypass   (1 bypass)  <- teeth

The real mainnet passkey wallet (ecd990...) is asserted to be REACHED
(positive-path accepted) and `held` — a grounded result on real code, and the
proof the WebAuthn encoder matches the real wasm byte-for-byte. If positive-path
ever regresses the verdict becomes `inconclusive` and this test fails loudly.

Skips (does not fail) if the harness binary or wasms are not built.
Build:
  (cd harness && cargo build --release)
  (cd bench && cargo build --release --target wasm32v1-none \\
       -p bound_passkey -p unbound_passkey)
  cp bench/target/wasm32v1-none/release/{bound,unbound}_passkey.wasm soro/assets/
"""
import glob
import json
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "harness", "target", "release", "harness")
ASSETS = os.path.join(ROOT, "soro", "assets")


def _run(mode, wasm_path, tmp_path):
    if not os.path.exists(BIN):
        pytest.skip(f"harness binary not built at {BIN}")
    if not os.path.exists(wasm_path):
        pytest.skip(f"wasm missing: {wasm_path}")
    out = os.path.join(tmp_path, os.path.basename(wasm_path) + f".{mode}.json")
    subprocess.run([BIN, f"--{mode}", wasm_path, out], check=True, cwd=ROOT)
    return json.load(open(out))


def _real_passkey_wasm():
    hits = glob.glob(os.path.join(ROOT, "recon", "out", "wasm", "ecd990*.wasm"))
    return hits[0] if hits else os.path.join(ROOT, "recon", "out", "wasm", "missing.wasm")


# --- secp256r1 / WebAuthn: the load-bearing pair ---------------------------

def test_bound_passkey_zero_false_positive(tmp_path):
    """A correct passkey account (binds the challenge) must show ZERO bypass."""
    d = _run("realauth-p256", os.path.join(ASSETS, "bound_passkey.wasm"), tmp_path)
    assert d["verdict"] == "held"
    assert d["bypasses"] == 0
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["positive-path"]["detail"].startswith("genuine")
    assert probes["cross-payload-replay"]["bypass"] is False


def test_unbound_passkey_binding_bug_caught(tmp_path):
    """The swig-#143 class: verifies the assertion but ignores the challenge.
    Both positive-path and forgery-control must confirm a real verify runs, so the
    replay-bypass reads the binding bug specifically, not a parse/verify failure."""
    d = _run("realauth-p256", os.path.join(ASSETS, "unbound_passkey.wasm"), tmp_path)
    assert d["verdict"] == "replay-bypass"
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["positive-path"]["detail"].startswith("genuine")  # baseline reached
    assert probes["forgery-control"]["bypass"] is False  # it DOES verify
    assert probes["cross-payload-replay"]["bypass"] is True  # ...but ignores binding


def test_real_passkey_wallet_reached_and_held_p256(tmp_path):
    """The real mainnet passkey wallet: the WebAuthn encoder must REACH its real
    __check_auth (positive-path accepted) and the wallet must hold. A regression to
    `inconclusive` (positive-path rejected) means the encoder no longer matches the
    real ABI/digest and must be fixed before any field verdict is trusted."""
    d = _run("realauth-p256", _real_passkey_wasm(), tmp_path)
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["positive-path"]["detail"].startswith("genuine"), (
        "encoder no longer reaches the real __check_auth: " + probes["positive-path"]["detail"]
    )
    assert d["verdict"] == "held"
    assert d["bypasses"] == 0


# --- ed25519 branch: machinery lands on the real wasm ----------------------

def test_real_passkey_wallet_reached_and_held_ed25519(tmp_path):
    d = _run("realauth", _real_passkey_wasm(), tmp_path)
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["positive-path"]["detail"].startswith("genuine")
    assert d["verdict"] == "held"
