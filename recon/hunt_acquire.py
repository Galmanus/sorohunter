#!/usr/bin/env python3
"""hunt_acquire.py — pull a real mainnet contract set, dedup by wasm, rank by
activity. Read-only: only reads the stellar.expert public index. No tx.

Output: recon/out/hunt_targets.json  = [{wasm, contract, invocations, events, n}]
one representative (most-active) contract per UNIQUE wasm implementation.
"""
import json, os, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)
API = "https://api.stellar.expert/explorer/public/contract"
UA = {"User-Agent": "sorohunter-hunt/1.0"}
MAX_PAGES = int(sys.argv[1]) if len(sys.argv) > 1 else 20  # 200/page


def _get(url):
    req = urllib.request.Request(url, headers=UA)
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def act(r):
    return (r.get("invocations") or 0) + (r.get("events") or 0) + (r.get("subinvocation") or 0)


by_wasm = {}  # wasm -> best record
total = 0
cursor = None
for page in range(MAX_PAGES):
    url = f"{API}?sort=created&order=desc&limit=200"
    if cursor:
        url += f"&cursor={cursor}"
    try:
        d = _get(url)
    except Exception as e:
        print(f"[p{page}] err {repr(e)[:80]}, retry", flush=True)
        time.sleep(2); continue
    recs = d.get("_embedded", {}).get("records", [])
    if not recs:
        print("[end of index]", flush=True); break
    for r in recs:
        c, w = r.get("contract"), r.get("wasm")
        if not c or not w:
            continue
        total += 1
        cur = by_wasm.get(w)
        if cur is None or act(r) > act(cur):
            by_wasm[w] = r
    cursor = recs[-1].get("paging_token")
    if (page + 1) % 5 == 0:
        live = sum(1 for r in by_wasm.values() if act(r) > 0)
        print(f"[p{page+1}] scanned={total} unique_wasm={len(by_wasm)} live_wasm={live}", flush=True)

targets = []
for w, r in by_wasm.items():
    targets.append({
        "wasm": w, "contract": r["contract"],
        "invocations": r.get("invocations"), "events": r.get("events"),
        "subinvocation": r.get("subinvocation"), "activity": act(r),
    })
targets.sort(key=lambda t: t["activity"], reverse=True)
json.dump(targets, open(os.path.join(OUT, "hunt_targets.json"), "w"), indent=1)
live = [t for t in targets if t["activity"] > 0]
print(f"\nTOTAL scanned={total}  unique_wasm={len(targets)}  live_wasm={len(live)}")
print("top 10 by activity:")
for t in targets[:10]:
    print(f"  act={t['activity']:>6}  {t['contract']}  wasm={t['wasm'][:16]}")
