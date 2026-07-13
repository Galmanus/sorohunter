#!/usr/bin/env python3
"""One clean experiment: does the stellar.expert contract index deep-paginate?
Waits out any 429 cooldown politely, then compares page 1 vs page 2 via an
EXPLICIT paging_token cursor (and also tries order=asc). Read-only."""
import urllib.request, json, time, sys

UA = {"User-Agent": "wave-probe/1.0"}
BASE = "https://api.stellar.expert/explorer/public/contract"


def get(url, tries=30):
    for _ in range(tries):
        try:
            return json.loads(urllib.request.urlopen(
                urllib.request.Request(url, headers=UA), timeout=30).read())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print(f"[probe] 429 cooldown, wait 20s...", flush=True)
                time.sleep(20)
                continue
            raise
        except Exception as e:
            print(f"[probe] err {repr(e)[:100]}, wait 5s", flush=True)
            time.sleep(5)
    raise SystemExit("[probe] gave up after retries")


def ids(d):
    return [r["contract"] for r in d["_embedded"]["records"]]


print("[probe] page 1 (order=desc)...", flush=True)
d1 = get(f"{BASE}?order=desc&limit=200")
p1 = ids(d1)
tok = d1["_embedded"]["records"][-1].get("paging_token")
print(f"[probe] page1 n={len(p1)} first={p1[0][:10]} last={p1[-1][:10]} last_token={str(tok)[:14]}", flush=True)
nxt = d1.get("_links", {}).get("next", {}).get("href")
print(f"[probe] next href = {nxt}", flush=True)

time.sleep(3)
print("[probe] page 2 via explicit &cursor=<last paging_token>...", flush=True)
d2 = get(f"{BASE}?order=desc&limit=200&cursor={tok}")
p2 = ids(d2)
print(f"[probe] page2 n={len(p2)} first={p2[0][:10]} last={p2[-1][:10]}", flush=True)

overlap = len(set(p1) & set(p2))
print(f"[probe] overlap(page1,page2) = {overlap} / {len(p1)}", flush=True)
if overlap == len(p1):
    print("[probe] VERDICT: cursor IGNORED — endpoint does NOT deep-paginate.", flush=True)
else:
    print(f"[probe] VERDICT: cursor WORKS — {len(p1)-overlap} new ids on page 2. Sweep is viable with backoff.", flush=True)

# also test order=asc from oldest, as an alternate paging direction
time.sleep(3)
print("[probe] page asc (oldest)...", flush=True)
da = get(f"{BASE}?order=asc&limit=200")
pa = ids(da)
print(f"[probe] asc n={len(pa)} first={pa[0][:10]} last={pa[-1][:10]} distinct_from_desc={len(set(pa)&set(p1))==0}", flush=True)
print("[probe] DONE", flush=True)
