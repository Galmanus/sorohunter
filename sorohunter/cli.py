#!/usr/bin/env python3
"""sorohunter — adversarial hunter for agentic Soroban contracts.

    sorohunter bench                 run the engine over the benchmark corpus
    sorohunter scan <contract-id>    acquire a public contract and probe it

The tool only ever reads a contract's public ABI + WASM and runs it in a LOCAL
fork. It never sends a transaction to any network. Disclosure is manual.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from sorohunter.abi import parse_spec  # noqa: E402
from sorohunter import report as rep  # noqa: E402

BENCH_WASM = os.path.join(ROOT, "bench", "target", "wasm32v1-none", "release")
ATTACKER_WASM = os.path.join(BENCH_WASM, "attacker_pwn.wasm")
REPORTS = os.path.join(ROOT, "reports")


def harness_bin() -> str:
    for prof in ("release", "debug"):
        p = os.path.join(ROOT, "harness", "target", prof, "harness")
        if os.path.exists(p):
            return p
    print("building harness ...", file=sys.stderr)
    subprocess.run(["cargo", "build"], cwd=os.path.join(ROOT, "harness"), check=True)
    return os.path.join(ROOT, "harness", "target", "debug", "harness")


def abi_entries(*info_args: str) -> list[dict]:
    out = subprocess.run(
        ["stellar", "contract", "info", "interface", *info_args, "--output", "json"],
        capture_output=True, text=True,
    ).stdout
    # the CLI prints a status line before the JSON array; find the '['
    i = out.find("[")
    return json.loads(out[i:]) if i >= 0 else []


def probe_wasm(wasm_path: str, entries: list[dict], out_json: str) -> list[dict]:
    """Run the harness over the synthesizable functions; fold in skipped ones."""
    plan = parse_spec(entries)
    # real contracts (Protocol 22+) carry a __constructor: pull its arg types out
    # to deploy with, and never probe it as an attack surface.
    ctor = next((p for p in plan if p["name"] == "__constructor"), None)
    ctor_csv = ",".join(ctor["inputs"]) if (ctor and ctor["synthesizable"]) else ""
    plan = [p for p in plan if p["name"] != "__constructor"]
    specs = [f"{p['name']}:{','.join(p['inputs'])}" for p in plan if p["synthesizable"]]
    verdicts: list[dict] = []
    if specs:
        subprocess.run([harness_bin(), wasm_path, out_json, ctor_csv, *specs], check=True,
                       capture_output=True, text=True)
        verdicts = json.load(open(out_json))
    for p in plan:
        if not p["synthesizable"]:
            verdicts.append({"fn": p["name"], "arg_types": ",".join(p["inputs"]),
                             "verdict": "skipped", "events_delta": 0, "detail": p["skip_reason"]})
    verdicts += probe_chains(wasm_path, plan, verdicts, out_json, ctor_csv)
    verdicts += probe_upgrades(wasm_path, plan, out_json, ctor_csv)
    return verdicts


def probe_upgrades(wasm_path: str, plan: list[dict], out_json: str,
                   ctor_csv: str = "") -> list[dict]:
    """Fork-validate unprotected-upgrade hijacks (TP-01).

    Candidate upgrade entry points are functions taking a 32-byte hash
    (`bytes_n:32` — a wasm hash). The harness uploads an attacker payload, calls
    the candidate under empty auth with the payload's hash, and confirms the
    hijack only if the code actually swapped (the payload's marker executes). A
    non-upgrade function that merely takes a hash swaps nothing and is not
    flagged, so the heuristic cannot raise a false positive.
    """
    if not os.path.exists(ATTACKER_WASM):
        return []  # no payload to swap in (bench not built)
    up_out = out_json + ".upgrade"
    found: list[dict] = []
    for p in plan:
        if not p["synthesizable"] or "bytes_n:32" not in p["inputs"]:
            continue
        spec = f"{p['name']}:{','.join(p['inputs'])}"
        subprocess.run([harness_bin(), "--upgrade", wasm_path, ATTACKER_WASM, up_out, ctor_csv, spec],
                       check=True, capture_output=True, text=True)
        res = json.load(open(up_out))
        if res.get("verdict") == "hijack":
            found.append({"fn": p["name"], "arg_types": ",".join(p["inputs"]),
                          "verdict": "hijack", "events_delta": 0,
                          "detail": res.get("detail", "")})
    return found


def probe_chains(wasm_path: str, plan: list[dict], verdicts: list[dict],
                 out_json: str, ctor_csv: str = "") -> list[dict]:
    """Propose and fork-validate two-step privilege chains (TE-01 / SK-C01).

    Candidate footholds are synthesizable functions that take an address (a
    setter the attacker can point at itself); candidate targets are functions
    that HELD under empty auth (a gated action). For each pair the harness runs
    the chain in one fork, and only a confirmed `chain` verdict — the gated
    action actually executed for the attacker after the foothold — becomes a
    finding. The proposer is heuristic; the confirmation is by execution, so the
    heuristic cannot raise a false positive.
    """
    inputs_by_name = {p["name"]: p["inputs"] for p in plan}
    footholds = [p for p in plan if p["synthesizable"] and "address" in p["inputs"]]
    held = [v["fn"] for v in verdicts if v.get("verdict") == "held"]
    chain_out = out_json + ".chain"
    found: list[dict] = []
    for fh in footholds:
        for tgt in held:
            if fh["name"] == tgt:
                continue
            f_spec = f"{fh['name']}:{','.join(fh['inputs'])}"
            t_spec = f"{tgt}:{','.join(inputs_by_name.get(tgt, []))}"
            subprocess.run([harness_bin(), "--chain", wasm_path, chain_out, ctor_csv, f_spec, t_spec],
                           check=True, capture_output=True, text=True)
            res = json.load(open(chain_out))
            if res.get("verdict") == "chain":
                found.append({"fn": f"{fh['name']}->{tgt}", "arg_types": "",
                              "verdict": "chain", "events_delta": 0,
                              "detail": res.get("detail", "")})
    return found


def cmd_bench(args) -> int:
    gt = json.load(open(os.path.join(ROOT, "bench", "ground_truth.json")))
    results = []
    for contract in gt:
        wasm = os.path.join(BENCH_WASM, f"{contract}.wasm")
        if not os.path.exists(wasm):
            print(f"missing {wasm} — run `stellar contract build` in bench/ first")
            return 1
        entries = abi_entries("--wasm", wasm)
        verdicts = probe_wasm(wasm, entries, os.path.join(REPORTS, f"_{contract}.json"))
        results.append({"contract": contract, "wasm": wasm, "verdicts": verdicts})

    ev = rep.evaluate(results, gt)
    date = datetime.date.today().strftime("%Y%m%d")
    prefix = os.path.join(REPORTS, f"bench_{date}")
    rep.write_artifacts(ev, results, prefix)

    print(f"precision {ev['precision']:.0%} · recall {ev['recall']:.0%} "
          f"(tp {ev['tp']}, fp {ev['fp']}, fn {ev['fn']})")
    for pc in ev["per_contract"]:
        flag = ", ".join(pc["flagged"]) or "clean"
        print(f"  {pc['contract']:<14} findings: {flag}")
    print(f"report: {prefix}.md")
    return 0 if ev["fp"] == 0 and ev["fn"] == 0 else 1


def cmd_scan(args) -> int:
    scratch = os.path.join(REPORTS, "_scan")
    os.makedirs(scratch, exist_ok=True)
    print(f"acquiring {args.contract_id} ({args.network}) — read-only ...")
    entries = abi_entries("--id", args.contract_id, "--network", args.network)
    if not entries:
        print("no contract spec found")
        return 1
    wasm = os.path.join(scratch, f"{args.contract_id}.wasm")
    subprocess.run(["stellar", "contract", "fetch", "--id", args.contract_id,
                    "--network", args.network, "--out-file", wasm],
                   check=True, capture_output=True, text=True)
    verdicts = probe_wasm(wasm, entries, os.path.join(scratch, "verdicts.json"))
    print(f"\n{args.contract_id}: {len(verdicts)} probes")
    for v in verdicts:
        mark = {"breach": "BREACH", "chain": "CHAIN", "hijack": "HIJACK"}.get(v["verdict"], v["verdict"])
        print(f"  [{mark:<7}] {v['fn']}({v['arg_types']})  {v['detail']}")
    findings = [v for v in verdicts if v["verdict"] in ("breach", "chain")]
    if findings:
        print("\nNOTE: fresh-deploy probing. A finding here is a CANDIDATE — confirm against "
              "a state-fork before any disclosure. Never touch the live contract.")
    return 0


def cmd_probe(args) -> int:
    """Run the engine over local contract wasm file(s) — the way to point it at
    real contracts (e.g. soroban-examples) without a network fetch."""
    rows = []
    total_findings = 0
    for wasm in args.wasm:
        if not os.path.exists(wasm):
            print(f"skip (no file): {wasm}")
            continue
        label = os.path.splitext(os.path.basename(wasm))[0]
        entries = abi_entries("--wasm", wasm)
        if not entries:
            print(f"skip (no spec): {label}")
            continue
        verdicts = probe_wasm(wasm, entries, os.path.join(REPORTS, f"_probe_{label}.json"))
        findings = [v for v in verdicts if v["verdict"] in ("breach", "chain", "hijack")]
        total_findings += len(findings)
        rows.append((label, len(verdicts), findings))
        if args.verbose or findings:
            print(f"\n{label}: {len(verdicts)} probes")
            for v in verdicts:
                mark = {"breach": "BREACH", "chain": "CHAIN", "hijack": "HIJACK"}.get(
                    v["verdict"], v["verdict"])
                print(f"  [{mark:<7}] {v['fn']}({v['arg_types']})  {v['detail']}")

    print("\n=== summary ===")
    for label, n, findings in rows:
        flag = ", ".join(f["fn"] for f in findings) or "clean"
        print(f"  {label:<30} {n:>2} probes  ->  {flag}")
    print(f"\n{len(rows)} contracts probed, {total_findings} finding(s)")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sorohunter")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bench", help="run the engine over the benchmark corpus")
    b.set_defaults(func=cmd_bench)
    s = sub.add_parser("scan", help="acquire a public contract and probe it (read-only)")
    s.add_argument("contract_id")
    s.add_argument("--network", default="testnet")
    s.set_defaults(func=cmd_scan)
    pr = sub.add_parser("probe", help="run the engine on local contract wasm file(s)")
    pr.add_argument("wasm", nargs="+")
    pr.add_argument("-v", "--verbose", action="store_true")
    pr.set_defaults(func=cmd_probe)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
