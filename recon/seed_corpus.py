#!/usr/bin/env python3
"""seed_corpus.py — LLM-seeded fuzzer corpus. Reads a contract's exported function
names (via `soro abi`), asks an LLM to propose exploit-shaped call SEQUENCES, and
writes them to <wasm>.seed.json for `sorohunter fuzz --seed`.

The LLM only GUIDES exploration (biases the fuzzer toward exploit-shaped orderings);
every verdict is still proven by execution downstream, so a bad LLM guess just
wastes a dead branch — zero-FP is preserved. Output is cached to disk so the
deterministic fuzzer replays identically.

LLM backend: Wave's free providers (wave_providers.py: Llama/Gemini). Falls back
to a heuristic seeder if the LLM is unavailable, so the feature always works.

Usage: python3 recon/seed_corpus.py <wasm> [--n 12]
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SORO = os.path.join(ROOT, "soro", "target", "release", "sorohunter")
WAVE_PROVIDERS = os.path.expanduser("~/wave-workspace/wave_providers.py")


def abi_fns(wasm):
    out = subprocess.run([SORO, "abi", wasm], capture_output=True, text=True, timeout=30).stdout.strip()
    try:
        return json.loads(out)
    except Exception:
        return []


def llm_sequences(fns, n):
    if not os.path.exists(WAVE_PROVIDERS):
        return None
    prompt = (
        "You are a smart-contract exploit strategist. Given these Soroban contract "
        f"function names:\n{json.dumps(fns)}\n\n"
        f"Propose up to {n} SEQUENCES of function calls (2-5 calls each) that an "
        "attacker would try to break the contract's invariants — e.g. set up state "
        "then exploit it (initialize then an admin setter; deposit then withdraw "
        "twice; approve then a redirected transfer). Only use function names from "
        "the list. Reply with ONLY a JSON array of arrays of strings, nothing else."
    )
    try:
        r = subprocess.run(["python3", WAVE_PROVIDERS, prompt], capture_output=True, text=True, timeout=90)
        txt = r.stdout
        m = re.search(r"\[\s*\[.*\]\s*\]", txt, re.DOTALL)
        if not m:
            return None
        seqs = json.loads(m.group(0))
        clean = []
        fset = set(fns)
        for s in seqs:
            if isinstance(s, list):
                seq = [x for x in s if isinstance(x, str) and x in fset]
                if len(seq) >= 2:
                    clean.append(seq[:5])
        return clean or None
    except Exception:
        return None


def heuristic_sequences(fns):
    """Pattern-based fallback: pair setup-like fns with sensitive-like fns."""
    low = {f: f.lower() for f in fns}
    setup = [f for f in fns if any(k in low[f] for k in ("init", "deposit", "approve", "arm", "open", "create", "add", "queue", "set"))]
    sensitive = [f for f in fns if any(k in low[f] for k in ("withdraw", "admin", "owner", "drain", "claim", "transfer", "mint", "upgrade", "fire", "draw", "swap", "borrow", "pay", "accept", "clawback"))]
    seqs = []
    for s in setup[:5]:
        for t in sensitive[:5]:
            if s != t:
                seqs.append([s, t])
    # replay-shaped: a sensitive fn called twice after setup
    for t in sensitive[:4]:
        for s in setup[:2]:
            seqs.append([s, t, t])
    # dedup
    seen, out = set(), []
    for q in seqs:
        k = tuple(q)
        if k not in seen:
            seen.add(k); out.append(q)
    return out[:16]


def main():
    if len(sys.argv) < 2:
        print("usage: seed_corpus.py <wasm> [--n 12]"); sys.exit(1)
    wasm = sys.argv[1]
    n = 12
    if "--n" in sys.argv:
        n = int(sys.argv[sys.argv.index("--n") + 1])
    fns = abi_fns(wasm)
    if not fns:
        print("no exported fns (bad wasm or no spec)"); sys.exit(2)
    seqs = llm_sequences(fns, n)
    source = "llm"
    if not seqs:
        seqs = heuristic_sequences(fns)
        source = "heuristic (llm unavailable)"
    out_path = wasm + ".seed.json"
    json.dump(seqs, open(out_path, "w"), indent=1)
    print(f"seeded {len(seqs)} exploit-shaped sequences via {source} -> {out_path}")
    for s in seqs[:8]:
        print("  " + " -> ".join(s))


main()
