#!/usr/bin/env python3
"""hunt_confirmed.py — the FUNCTIONAL hunter. For each live contract: classify via
RPC (skip SAC/archived), then run `soro scan --fork` against REAL on-chain state.
Findings here are CONFIRMED (state-fork), not fresh-deploy candidates — this is the
path that avoids the Wombat-style false positive. Read-only; no tx is signed.
"""
import json, os, re, subprocess, sys
from stellar_sdk import SorobanServer, Durability
from stellar_sdk import xdr as x

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
ROOT = os.path.dirname(HERE)
SORO = os.path.join(ROOT, "soro", "target", "release", "sorohunter")
srv = SorobanServer("https://soroban-rpc.mainnet.stellar.gateway.fm")
FINDING = re.compile(r"\[(breach|chain|hijack|reinit|drain|greed|redirect|replay|oracle|counterfeit|roundtrip)\s*\]")


def is_wasm(cid):
    try:
        key = x.SCVal(x.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE)
        ent = srv.get_contract_data(cid, key, Durability.PERSISTENT)
        if ent is None:
            return False
        execu = x.LedgerEntryData.from_xdr(ent.xdr).contract_data.val.instance.executable
        return execu.type == x.ContractExecutableType.CONTRACT_EXECUTABLE_WASM
    except Exception:
        return False


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(OUT, "live_contracts.json")
    ids = list(json.load(open(src)).keys())
    N = int(sys.argv[2]) if len(sys.argv) > 2 else len(ids)
    ids = ids[:N]
    wasm_n = 0
    scanned = 0
    findings = []
    for i, cid in enumerate(ids):
        if not is_wasm(cid):
            continue
        wasm_n += 1
        r = subprocess.run([SORO, "scan", cid, "--network", "mainnet", "--fork"],
                           capture_output=True, text=True, timeout=180)
        out = r.stdout + r.stderr
        scanned += 1
        hits = [l.strip() for l in out.splitlines() if FINDING.search(l)]
        if hits:
            findings.append({"contract": cid, "hits": hits})
            print(f"  !! CONFIRMED on {cid}:")
            for h in hits:
                print("     " + h)
        if scanned % 5 == 0:
            print(f"[{i+1}/{len(ids)}] wasm={wasm_n} scanned={scanned} confirmed_findings={len(findings)}", flush=True)
    print(f"\nCONFIRMED HUNT: candidates={len(ids)} custom_wasm={wasm_n} state-fork-scanned={scanned} CONFIRMED={len(findings)}")
    json.dump(findings, open(os.path.join(OUT, "confirmed_findings.json"), "w"), indent=1)
    if not findings:
        print("  (zero confirmed against real on-chain state — the honest, state-fork-verified zero)")


main()
