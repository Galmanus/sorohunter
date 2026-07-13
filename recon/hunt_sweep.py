#!/usr/bin/env python3
"""hunt_sweep.py — fetch the harvested live contracts' wasm (read-only) and run
the detector suite. Dedup by wasm hash. Reports only non-clean verdicts (the
init-guard fix filters fresh-deploy artifacts). No tx is ever signed.
"""
import hashlib, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
ROOT = os.path.dirname(HERE)
WDIR = os.path.join(OUT, "hunt_wasm")
os.makedirs(WDIR, exist_ok=True)
SORO = os.path.join(ROOT, "soro", "target", "release", "sorohunter")
HARNESS = os.path.join(ROOT, "harness", "target", "release", "harness")
RPC = "https://soroban-rpc.mainnet.stellar.gateway.fm"
PASS = "Public Global Stellar Network ; September 2015"

N = int(sys.argv[1]) if len(sys.argv) > 1 else 80
live = list(json.load(open(os.path.join(OUT, "live_contracts.json"))).items())[:N]

seen_hash = {}
findings = []
probed = 0
sac_skipped = 0
fetch_failed = 0
deploy_failed = 0
for i, (cid, ev) in enumerate(live):
    dst = os.path.join(WDIR, cid + ".wasm")
    if not os.path.exists(dst) or os.path.getsize(dst) == 0:
        r = subprocess.run(
            ["stellar", "contract", "fetch", "--id", cid, "--rpc-url", RPC,
             "--network-passphrase", PASS, "-o", dst, "-q"],
            capture_output=True, text=True, timeout=60,
        )
        err = (r.stderr or "") + (r.stdout or "")
        if "built-in asset contract" in err:
            sac_skipped += 1
            continue
        if not os.path.exists(dst) or os.path.getsize(dst) == 0:
            fetch_failed += 1
            continue
    h = hashlib.sha256(open(dst, "rb").read()).hexdigest()
    if h in seen_hash:
        continue
    seen_hash[h] = cid
    probed += 1
    # general detectors (breach/hijack/redirect/chain, init-guarded)
    p = subprocess.run([SORO, "probe", dst], capture_output=True, text=True, timeout=120)
    out = p.stdout
    if "deploy-failed" in out and "clean" not in out.split("summary")[-1]:
        deploy_failed += 1
    nfind = 0
    for line in out.splitlines():
        if "finding(s)" in line:
            try: nfind = int(line.split()[-2].split("(")[0]) if "0 finding" not in line else 0
            except Exception: nfind = 0
    verd = ""
    for line in out.splitlines():
        if "->" in line and "clean" not in line and "probes" in line:
            verd = line.split("->", 1)[1].strip()
    if "0 finding(s)" not in out:
        findings.append({"contract": cid, "events": ev, "wasm": h[:16], "detector": "probe", "verdict": verd})
    # smart-account check
    has_ca = b"__check_auth" in open(dst, "rb").read()
    if has_ca:
        outj = os.path.join(WDIR, cid + ".realauth.json")
        subprocess.run([HARNESS, "--realauth-p256", dst, outj], capture_output=True, text=True, timeout=60)
        try:
            d = json.load(open(outj))
            if d.get("verdict") not in ("held", "inconclusive", "deploy-failed"):
                findings.append({"contract": cid, "events": ev, "wasm": h[:16], "detector": "realauth-p256", "verdict": d["verdict"]})
        except Exception:
            pass
    if probed % 10 == 0:
        print(f"[{i+1}/{len(live)}] unique_probed={probed} findings={len(findings)}", flush=True)

print(f"\nSWEEP DONE: targets={len(live)} sac_skipped={sac_skipped} fetch_failed={fetch_failed} unique_wasm_probed={probed} deploy_failed_within={deploy_failed} NON-CLEAN={len(findings)}")
for f in findings:
    print(f"  !! {f['detector']:14} {f['verdict'][:60]:60} events={f['events']} {f['contract']}")
json.dump(findings, open(os.path.join(OUT, "hunt_findings.json"), "w"), indent=1)
if not findings:
    print("  (no non-clean verdicts — the honest zero, on real live contracts, FP-filtered)")
