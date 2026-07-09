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
    specs = [f"{p['name']}:{','.join(p['inputs'])}" for p in plan if p["synthesizable"]]
    verdicts: list[dict] = []
    if specs:
        subprocess.run([harness_bin(), wasm_path, out_json, *specs], check=True,
                       capture_output=True, text=True)
        verdicts = json.load(open(out_json))
    for p in plan:
        if not p["synthesizable"]:
            verdicts.append({"fn": p["name"], "arg_types": ",".join(p["inputs"]),
                             "verdict": "skipped", "events_delta": 0, "detail": p["skip_reason"]})
    return verdicts


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
        mark = "BREACH" if v["verdict"] == "breach" else v["verdict"]
        print(f"  [{mark:<7}] {v['fn']}({v['arg_types']})  {v['detail']}")
    breaches = [v for v in verdicts if v["verdict"] == "breach"]
    if breaches:
        print("\nNOTE: fresh-deploy probing. A breach here is a CANDIDATE — confirm against "
              "a state-fork before any disclosure. Never touch the live contract.")
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
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
