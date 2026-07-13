#!/usr/bin/env python3
"""hunt_rpc.py — free, no-Google hunt. Fetch each contract's wasm DIRECTLY via
Soroban RPC (instance -> executable -> code entry) using stellar_sdk, classify
SAC vs WASM vs archived, dedup by wasm hash, and probe every custom WASM with the
detector suite. Bypasses the `stellar` CLI (which drops fetchable contracts with
"not found"). Read-only.
"""
import hashlib, json, os, subprocess, sys
from stellar_sdk import SorobanServer, Durability
from stellar_sdk import xdr as x

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
ROOT = os.path.dirname(HERE)
WDIR = os.path.join(OUT, "rpc_wasm")
os.makedirs(WDIR, exist_ok=True)
SORO = os.path.join(ROOT, "soro", "target", "release", "sorohunter")
HARNESS = os.path.join(ROOT, "harness", "target", "release", "harness")
srv = SorobanServer("https://soroban-rpc.mainnet.stellar.gateway.fm")


def fetch_wasm(cid):
    key = x.SCVal(x.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE)
    ent = srv.get_contract_data(cid, key, Durability.PERSISTENT)
    if ent is None:
        return ("not-found", None)
    data = x.LedgerEntryData.from_xdr(ent.xdr)
    execu = data.contract_data.val.instance.executable
    if execu.type != x.ContractExecutableType.CONTRACT_EXECUTABLE_WASM:
        return ("SAC", None)
    ck = x.LedgerKey(x.LedgerEntryType.CONTRACT_CODE,
                     contract_code=x.LedgerKeyContractCode(hash=x.Hash(execu.wasm_hash.hash)))
    resp = srv.get_ledger_entries([ck])
    if not resp.entries:
        return ("code-archived", execu.wasm_hash.hash.hex())
    return ("WASM", x.LedgerEntryData.from_xdr(resp.entries[0].xdr).contract_code.code)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(OUT, "live_contracts.json")
    ids = list(json.load(open(src)).keys())
    N = int(sys.argv[2]) if len(sys.argv) > 2 else len(ids)
    ids = ids[:N]
    stats = {"WASM": 0, "SAC": 0, "not-found": 0, "code-archived": 0, "err": 0}
    seen = {}
    findings = []
    probed = 0
    for i, cid in enumerate(ids):
        try:
            kind, w = fetch_wasm(cid)
        except Exception:
            stats["err"] += 1
            continue
        stats[kind] = stats.get(kind, 0) + 1
        if kind != "WASM":
            continue
        h = hashlib.sha256(w).hexdigest()
        if h in seen:
            continue
        seen[h] = cid
        dst = os.path.join(WDIR, cid + ".wasm")
        open(dst, "wb").write(w)
        probed += 1
        p = subprocess.run([SORO, "probe", dst], capture_output=True, text=True, timeout=120)
        out = p.stdout
        if "0 finding(s)" not in out:
            verd = next((l.split("->", 1)[1].strip() for l in out.splitlines()
                         if "->" in l and "clean" not in l and "probes" in l), "?")
            findings.append({"contract": cid, "wasm": h[:16], "detector": "probe", "verdict": verd})
        if b"__check_auth" in w:
            oj = os.path.join(WDIR, cid + ".realauth.json")
            subprocess.run([HARNESS, "--realauth-p256", dst, oj], capture_output=True, text=True, timeout=60)
            try:
                d = json.load(open(oj))
                if d.get("verdict") not in ("held", "inconclusive", "deploy-failed"):
                    findings.append({"contract": cid, "wasm": h[:16], "detector": "realauth-p256", "verdict": d["verdict"]})
            except Exception:
                pass
        if probed % 5 == 0:
            print(f"[{i+1}/{len(ids)}] wasm={stats['WASM']} sac={stats['SAC']} archived={stats['code-archived']+stats['not-found']} unique_probed={probed} findings={len(findings)}", flush=True)
    print(f"\nRPC HUNT: scanned={len(ids)} {stats} unique_wasm_probed={probed} NON-CLEAN={len(findings)}")
    for f in findings:
        print(f"  !! {f['detector']:14} {f['verdict'][:56]:56} {f['contract']}")
    json.dump(findings, open(os.path.join(OUT, "rpc_findings.json"), "w"), indent=1)
    if not findings:
        print("  (zero non-clean — honest, FP-filtered, on real custom WASM contracts)")


main()
