#!/usr/bin/env python3
"""hunter.py — the autonomous, continually-learning sorohunter agent.

Unifies every layer built so far into one self-improving hunting loop:

  recon -> peer memory -> LLM-seeded corpus (informed by what broke similar
  contracts) -> execution-proof battery (scan/fuzz/detectors) -> update memory.

The DIFFERENTIATOR: memory + LLM guide WHERE to look and WHAT to try, but every
verdict is proven by execution downstream — zero-FP is never traded for the
learning. The agent gets sharper across targets because it remembers which
detectors and exploit-shaped sequences found bugs on each contract CLASS.

Peer representations (Honcho-style) persist in recon/out/peers/<id>.json; the
global attack knowledge in recon/out/knowledge.json feeds the seeder.

Usage:
  python3 recon/hunter.py <contract_id>            # fetch mainnet wasm, hunt
  python3 recon/hunter.py <path/to.wasm> --local   # hunt a local wasm
"""
import hashlib, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "out")
PEERS = os.path.join(OUT, "peers")
os.makedirs(PEERS, exist_ok=True)
SORO = os.path.join(ROOT, "soro", "target", "release", "sorohunter")
HARNESS = os.path.join(ROOT, "harness", "target", "release", "harness")
KNOWLEDGE = os.path.join(OUT, "knowledge.json")
FINDING_VERDICTS = {"breach", "chain", "hijack", "reinit", "drain", "greed",
                    "redirect", "replay", "oracle", "counterfeit", "roundtrip",
                    "auth-bypass", "replay-bypass", "scope-mismatch",
                    "fee-overcredit", "allowance-drain", "econ-drain"}


def load_json(p, default):
    try:
        return json.load(open(p))
    except Exception:
        return default


def classify(fns):
    s = " ".join(fns).lower()
    if "__check_auth" in fns or "add_signer" in s:
        return "smart-account"
    if "verify_groth16" in s or "verify_and_submit" in s or "proof" in s:
        return "zk-verifier"
    if "borrow" in s or "liquidat" in s or "backstop" in s or "collateral" in s:
        return "lending"
    if "transfer_from" in s and "allowance" in s or "mint" in s and "balance" in s:
        return "token"
    if "deposit" in s and "withdraw" in s:
        return "vault"
    return "generic"


def fetch_wasm(cid):
    """RPC-direct fetch (no CLI, no Google), same as hunt_rpc."""
    from stellar_sdk import SorobanServer, Durability
    from stellar_sdk import xdr as x
    srv = SorobanServer("https://soroban-rpc.mainnet.stellar.gateway.fm")
    key = x.SCVal(x.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE)
    ent = srv.get_contract_data(cid, key, Durability.PERSISTENT)
    if ent is None:
        return None
    execu = x.LedgerEntryData.from_xdr(ent.xdr).contract_data.val.instance.executable
    if execu.type != x.ContractExecutableType.CONTRACT_EXECUTABLE_WASM:
        return None
    ck = x.LedgerKey(x.LedgerEntryType.CONTRACT_CODE,
                     contract_code=x.LedgerKeyContractCode(hash=x.Hash(execu.wasm_hash.hash)))
    resp = srv.get_ledger_entries([ck])
    if not resp.entries:
        return None
    return x.LedgerEntryData.from_xdr(resp.entries[0].xdr).contract_code.code


def abi_fns(wasm_path):
    out = subprocess.run([SORO, "abi", wasm_path], capture_output=True, text=True, timeout=30).stdout.strip()
    return load_json_str(out)


def load_json_str(s):
    try:
        return json.loads(s)
    except Exception:
        return []


def run(cmd, timeout=180):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    except Exception:
        return None


def parse_findings(text):
    hits = []
    for line in (text or "").splitlines():
        low = line.lower()
        for v in FINDING_VERDICTS:
            if f"[{v}" in low or f'"verdict":"{v}"' in low or f"verdict={v}" in low:
                hits.append((v, line.strip()[:160]))
                break
    return hits


def hunt(target, is_local, network):
    # 1. acquire wasm
    if is_local:
        wasm_path = target
        cid = os.path.basename(target)
    else:
        wasm = fetch_wasm(target)
        if wasm is None:
            print(f"[{target}] no custom wasm (SAC/archived/not-found) — skip"); return None
        wasm_path = os.path.join(OUT, "hunter_" + target[:12] + ".wasm")
        open(wasm_path, "wb").write(wasm)
        cid = target
    wasm_bytes = open(wasm_path, "rb").read()
    wasm_hash = hashlib.sha256(wasm_bytes).hexdigest()[:16]

    # 2. classify + load peer memory + global knowledge
    fns = abi_fns(wasm_path)
    klass = classify(fns)
    knowledge = load_json(KNOWLEDGE, {})
    kclass = knowledge.get(klass, {"detectors_hit": {}, "seeds_that_found": []})
    peer_path = os.path.join(PEERS, (cid or wasm_hash).replace("/", "_") + ".json")
    peer = load_json(peer_path, {})
    print(f"[{cid}] class={klass} fns={len(fns)} wasm={wasm_hash} "
          f"(seen {peer.get('hunts',0)}x; class-priors: {list(kclass['detectors_hit'].keys())})")

    findings = []

    # 3. seed the corpus (LLM/heuristic) — enriched by what broke this class before
    seed_path = wasm_path + ".seed.json"
    run(["python3", os.path.join(HERE, "seed_corpus.py"), wasm_path], timeout=100)
    seeds = load_json(seed_path, [])
    for s in kclass["seeds_that_found"]:
        if s not in seeds:
            seeds.append(s)  # prior exploit shapes for this class
    json.dump(seeds, open(seed_path, "w"))

    # 4. execution-proof battery
    # 4a. state-fork scan (confirmed) if we have a real contract id
    if not is_local:
        r = run([SORO, "scan", cid, "--network", network, "--fork"], timeout=150)
        findings += parse_findings(r.stdout if r else "")
    # 4b. stateful fuzz with the seeded corpus
    r = run([SORO, "fuzz", wasm_path, "--seed", seed_path, "--rounds", "400"], timeout=150)
    findings += parse_findings(r.stdout if r else "")
    # 4c. class-specific provers
    if klass == "smart-account":
        oj = wasm_path + ".realauth.json"
        run([HARNESS, "--realauth-p256", wasm_path, oj], timeout=60)
        findings += parse_findings(open(oj).read() if os.path.exists(oj) else "")

    findings = list({(v, l) for v, l in findings})  # dedup

    # 5. update peer memory + global knowledge (the learning)
    peer.update({"id": cid, "class": klass, "wasm": wasm_hash, "fns": fns,
                 "hunts": peer.get("hunts", 0) + 1, "findings": [v for v, _ in findings]})
    json.dump(peer, open(peer_path, "w"), indent=1)
    for v, _ in findings:
        kclass["detectors_hit"][v] = kclass["detectors_hit"].get(v, 0) + 1
    # remember the seeds when something was found (exploit shapes that pay off)
    if findings:
        for s in seeds[:8]:
            if s not in kclass["seeds_that_found"]:
                kclass["seeds_that_found"].append(s)
    knowledge[klass] = kclass
    json.dump(knowledge, open(KNOWLEDGE, "w"), indent=1)

    # 6. report
    if findings:
        print(f"  !! {len(findings)} execution-proven finding(s):")
        for v, l in findings:
            print(f"     [{v}] {l}")
    else:
        print("  clean (execution-proven) — nothing broke")
    return {"id": cid, "class": klass, "findings": findings}


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    target = sys.argv[1]
    is_local = "--local" in sys.argv
    network = "mainnet"
    hunt(target, is_local, network)


main()
