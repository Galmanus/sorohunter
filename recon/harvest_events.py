#!/usr/bin/env python3
"""harvest_events.py — enumerate LIVE mainnet contracts by paginating Soroban RPC
getEvents. Every contract event carries a contractId; grinding pages harvests the
set of contracts actually being used. Read-only. No tx.

Output: recon/out/live_contracts.json = {contractId: event_count}
"""
import json, os, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)
RPC = "https://soroban-rpc.mainnet.stellar.gateway.fm"
TARGET_UNIQUE = int(sys.argv[1]) if len(sys.argv) > 1 else 400
MAX_PAGES = int(sys.argv[2]) if len(sys.argv) > 2 else 400


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=40).read())


latest = rpc("getLatestLedger", {})["result"]["sequence"]
start = latest - 16000  # ~1 day window (retention-bound)
counts = {}
cursor = None
params = {"startLedger": start, "filters": [{"type": "contract"}], "pagination": {"limit": 200}}
pages = 0
while pages < MAX_PAGES and len(counts) < TARGET_UNIQUE:
    if cursor:
        params = {"filters": [{"type": "contract"}], "pagination": {"cursor": cursor, "limit": 200}}
    try:
        r = rpc("getEvents", params)
    except Exception as e:
        print(f"[p{pages}] err {repr(e)[:80]}", flush=True); time.sleep(2); continue
    res = r.get("result", {})
    evs = res.get("events", [])
    if not evs:
        print("[no more events]", flush=True); break
    for e in evs:
        c = e.get("contractId")
        if c:
            counts[c] = counts.get(c, 0) + 1
    cursor = res.get("cursor")
    pages += 1
    if pages % 20 == 0:
        print(f"[p{pages}] unique_contracts={len(counts)}", flush=True)
    if not cursor:
        break

ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
json.dump(dict(ranked), open(os.path.join(OUT, "live_contracts.json"), "w"), indent=1)
print(f"\nHARVEST: pages={pages} unique_live_contracts={len(counts)}")
print("top 10 by event volume:")
for c, n in ranked[:10]:
    print(f"  events={n:>5}  {c}")
