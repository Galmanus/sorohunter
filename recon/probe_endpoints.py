#!/usr/bin/env python3
"""Probe stellar.expert for a usable enumeration surface: reverse-by-wasm,
a wasm/code listing, or a network-level contract count. Read-only, backoff."""
import urllib.request, json, time

UA = {"User-Agent": "wave-probe/1.0"}
WASM = "ecd990f0b45ca6817149b6175f79b32efb442f35731985a084131e8265c4cd90"

CANDIDATES = [
    ("contract?wasm=<h>",     f"https://api.stellar.expert/explorer/public/contract?wasm={WASM}&limit=200"),
    ("contract?code=<h>",     f"https://api.stellar.expert/explorer/public/contract?code={WASM}&limit=200"),
    ("wasm/<h>",              f"https://api.stellar.expert/explorer/public/wasm/{WASM}"),
    ("contract-code/<h>",     f"https://api.stellar.expert/explorer/public/contract-code/{WASM}"),
    ("contract-code list",    "https://api.stellar.expert/explorer/public/contract-code?limit=10"),
    ("wasm list",             "https://api.stellar.expert/explorer/public/wasm?limit=10"),
    ("network stats",         "https://api.stellar.expert/explorer/public/stats"),
    ("directory root",        "https://api.stellar.expert/explorer/public"),
]


def get(url, tries=8):
    for _ in range(tries):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30)
            return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(20); continue
            return e.code, (e.read() if hasattr(e, "read") else b"")
        except Exception as e:
            return -1, repr(e)[:120].encode()
    return -2, b"gaveup"


for label, url in CANDIDATES:
    code, body = get(url)
    txt = body.decode("utf-8", "replace")[:400] if isinstance(body, bytes) else str(body)
    # try to surface record count if JSON list
    hint = ""
    try:
        j = json.loads(body)
        if isinstance(j, dict) and "_embedded" in j:
            hint = f" [records={len(j['_embedded'].get('records', []))}]"
        elif isinstance(j, dict):
            hint = f" [keys={list(j.keys())[:8]}]"
    except Exception:
        pass
    print(f"### {label}: HTTP {code}{hint}\n{txt}\n", flush=True)
    time.sleep(4)
print("DONE", flush=True)
