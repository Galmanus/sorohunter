#!/usr/bin/env python3
"""
checkauth_census.py — measure the smart-account target supply on Stellar mainnet.

The gating number for the auth-bypass PoV pivot: how many DEPLOYED contracts
export `__check_auth` (i.e. are custom accounts / smart accounts), how many
distinct implementations (wasm hashes) they run, and how much on-chain activity
they carry (invocations/events as a liveness proxy).

Read-only. No transaction is ever submitted. It only:
  - reads the stellar.expert public contract index (metadata + wasm hash),
  - fetches contract wasm via the local `stellar` CLI (read-only),
  - inspects the wasm export section for the `__check_auth` symbol.

Two phases, both resumable via on-disk checkpoints:
  phase 1  enumerate contracts -> wasm-hash -> [contract ids] + activity
  phase 2  fetch each UNIQUE wasm once, detect `__check_auth` export
Output: recon/out/census.json + a printed summary.
"""
import json, os, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)
IDX = os.path.join(OUT, "contract_index.json")     # phase 1 checkpoint
WASM_CACHE = os.path.join(OUT, "wasm")             # fetched wasm blobs
DETECT = os.path.join(OUT, "wasm_detect.json")     # phase 2 checkpoint
CENSUS = os.path.join(OUT, "census.json")          # final
os.makedirs(WASM_CACHE, exist_ok=True)

API = "https://api.stellar.expert/explorer/public/contract"
UA = {"User-Agent": "sorohunter-census/1.0"}


def _get(url):
    req = urllib.request.Request(url, headers=UA)
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def phase1(max_pages=None):
    """Sweep the contract index by cursor. Resumable: reloads and continues."""
    state = {"records": {}, "cursor": None, "pages": 0}
    if os.path.exists(IDX):
        state = json.load(open(IDX))
    records = state["records"]
    url = f"{API}?limit=200&order=desc"
    if state["cursor"]:
        url = f"{API}?limit=200&order=desc&cursor={state['cursor']}"
    while True:
        try:
            d = _get(url)
        except Exception as e:
            print(f"[p1] fetch error, retry in 3s: {repr(e)[:120]}", flush=True)
            time.sleep(3)
            continue
        recs = d.get("_embedded", {}).get("records", [])
        if not recs:
            print("[p1] end of index", flush=True)
            break
        for r in recs:
            c = r.get("contract")
            if not c:
                continue
            records[c] = {
                "wasm": r.get("wasm"),
                "created": r.get("created"),
                "invocations": r.get("invocations"),
                "subinvocation": r.get("subinvocation"),
                "events": r.get("events"),
            }
        state["cursor"] = recs[-1].get("paging_token")
        state["pages"] += 1
        nxt = d.get("_links", {}).get("next", {}).get("href")
        if state["pages"] % 10 == 0:
            uw = len({v["wasm"] for v in records.values() if v["wasm"]})
            print(f"[p1] pages={state['pages']} contracts={len(records)} unique_wasm={uw}", flush=True)
            json.dump(state, open(IDX, "w"))
        if not nxt:
            print("[p1] no next link, done", flush=True)
            break
        url = "https://api.stellar.expert" + nxt
        if max_pages and state["pages"] >= max_pages:
            print(f"[p1] hit max_pages={max_pages}", flush=True)
            break
    json.dump(state, open(IDX, "w"))
    uw = len({v["wasm"] for v in records.values() if v["wasm"]})
    print(f"[p1] DONE contracts={len(records)} unique_wasm={uw}", flush=True)
    return records


def _fetch_wasm(sample_contract, wasm_hash):
    dst = os.path.join(WASM_CACHE, f"{wasm_hash}.wasm")
    if os.path.exists(dst) and os.path.getsize(dst) > 0:
        return dst
    try:
        subprocess.run(
            ["stellar", "contract", "fetch", "--id", sample_contract,
             "--network", "mainnet", "--out-file", dst],
            capture_output=True, timeout=90, check=True,
        )
        return dst if os.path.exists(dst) and os.path.getsize(dst) > 0 else None
    except Exception as e:
        print(f"[p2] fetch fail {wasm_hash[:12]} via {sample_contract[:8]}: {repr(e)[:90]}", flush=True)
        return None


def _leb(bs, i):
    r = s = 0
    while True:
        x = bs[i]; i += 1; r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, i
        s += 7


def _exports_check_auth(wasm_path):
    """True only if `__check_auth` is a real func EXPORT (not an incidental
    string in a data/error section). Parses the wasm export section (id 7)."""
    try:
        b = open(wasm_path, "rb").read()
        if b[:4] != b"\x00asm":
            return False
        pos = 8
        while pos < len(b):
            sid = b[pos]; pos += 1
            size, pos = _leb(b, pos)
            end = pos + size
            if sid == 7:
                count, pos = _leb(b, pos)
                for _ in range(count):
                    nlen, pos = _leb(b, pos)
                    name = b[pos:pos + nlen]; pos += nlen
                    kind = b[pos]; pos += 1
                    _, pos = _leb(b, pos)
                    if kind == 0 and name == b"__check_auth":
                        return True
                return False
            pos = end
        return False
    except Exception:
        return False


def phase2(records):
    detect = {}
    if os.path.exists(DETECT):
        detect = json.load(open(DETECT))
    # wasm_hash -> representative contract + instance list
    by_wasm = {}
    for c, v in records.items():
        w = v.get("wasm")
        if not w:
            continue
        by_wasm.setdefault(w, []).append(c)
    uniq = list(by_wasm.keys())
    print(f"[p2] {len(uniq)} unique wasm to inspect", flush=True)
    for i, w in enumerate(uniq):
        if w in detect:
            continue
        sample = by_wasm[w][0]
        path = _fetch_wasm(sample, w)
        ok = bool(path) and _exports_check_auth(path)
        detect[w] = {"check_auth": ok, "fetched": bool(path), "instances": len(by_wasm[w])}
        if (i + 1) % 25 == 0:
            hits = sum(1 for d in detect.values() if d["check_auth"])
            print(f"[p2] inspected={i+1}/{len(uniq)} check_auth_wasm={hits}", flush=True)
            json.dump(detect, open(DETECT, "w"))
    json.dump(detect, open(DETECT, "w"))
    return by_wasm, detect


def summarize(records, by_wasm, detect):
    ca_wasm = [w for w, d in detect.items() if d.get("check_auth")]
    instances = []
    for w in ca_wasm:
        for c in by_wasm.get(w, []):
            v = records[c]
            act = (v.get("invocations") or 0) + (v.get("events") or 0)
            instances.append({"contract": c, "wasm": w, "activity": act,
                              "invocations": v.get("invocations"), "events": v.get("events")})
    instances.sort(key=lambda x: x["activity"], reverse=True)
    live = [i for i in instances if i["activity"] > 0]
    census = {
        "total_contracts": len(records),
        "unique_wasm": len(by_wasm),
        "check_auth_wasm_count": len(ca_wasm),
        "check_auth_instances": len(instances),
        "check_auth_instances_with_activity": len(live),
        "check_auth_wasm_hashes": ca_wasm,
        "top_instances": instances[:50],
    }
    json.dump(census, open(CENSUS, "w"), indent=2)
    print("\n=== CENSUS ===", flush=True)
    for k in ("total_contracts", "unique_wasm", "check_auth_wasm_count",
              "check_auth_instances", "check_auth_instances_with_activity"):
        print(f"{k}: {census[k]}", flush=True)
    print(f"written: {CENSUS}", flush=True)
    return census


if __name__ == "__main__":
    mp = None
    if "--max-pages" in sys.argv:
        mp = int(sys.argv[sys.argv.index("--max-pages") + 1])
    recs = phase1(max_pages=mp)
    by_wasm, detect = phase2(recs)
    summarize(recs, by_wasm, detect)
