"""Ground-truth test for the fee-on-transfer accounting prover (harness
--feetoken).

New detector class, grounded in a real Soroban mainnet bridge audit (Coinspect
Tricorn Bridge, TRI-005): a vault that credits the deposit `amount` argument
instead of its measured token balance delta over-credits against a deflationary /
fee-on-transfer token, becoming insolvent. Static linters (CoinFabrik Scout,
OpenZeppelin) do not catch this — it is a dynamic accounting invariant. The prover
deploys a real 10%-fee token and the target vault, deposits through it, and
compares internal credit to tokens actually held.

  fee_vault_vuln -> fee-overcredit (credited 1000, holds 900)
  fee_vault_safe -> held           (credits the measured delta, 900 == 900)

fee_vault_safe is the load-bearing FP control: identical deposit path, differs by
crediting the balance delta instead of the argument.
"""
import json
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "harness", "target", "release", "harness")
ASSETS = os.path.join(ROOT, "soro", "assets")


def _run(vault_name, tmp_path):
    vault = os.path.join(ASSETS, vault_name)
    ft = os.path.join(ASSETS, "fee_token.wasm")
    if not os.path.exists(BIN):
        pytest.skip(f"harness binary not built at {BIN}")
    if not os.path.exists(vault) or not os.path.exists(ft):
        pytest.skip("fixture wasm missing")
    out = os.path.join(tmp_path, vault_name + ".json")
    subprocess.run([BIN, "--feetoken", vault, out, ft], check=True, cwd=ROOT)
    return json.load(open(out))


def test_fee_vault_vuln_overcredits(tmp_path):
    d = _run("fee_vault_vuln.wasm", tmp_path)
    assert d["verdict"] == "fee-overcredit"
    assert d["bypasses"] == 1
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["over-credit"]["bypass"] is True
    assert "over-credited by 100" in probes["over-credit"]["detail"]


def test_fee_vault_safe_zero_false_positive(tmp_path):
    d = _run("fee_vault_safe.wasm", tmp_path)
    assert d["verdict"] == "held"
    assert d["bypasses"] == 0
    probes = {p["probe"]: p for p in d["probes"]}
    assert probes["over-credit"]["bypass"] is False
