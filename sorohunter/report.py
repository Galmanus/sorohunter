"""Evaluate harness verdicts against ground truth and render the report.

A "finding" is a verdict of `breach` (a state change under empty auth). Scored
against a ground-truth map {contract: [vulnerable_fn, ...]}:
  true positive  = flagged fn that is a known vuln
  false positive = flagged fn that is clean   (the reputation killer)
  false negative = known vuln that was not flagged
Precision/recall are 1.0 by convention when there is nothing to get wrong.
"""
from __future__ import annotations

import json
import os


# verdicts that count as a real finding. A fresh-deploy `init-guarded` is NOT
# one — it is a one-time initializer that is guarded on live state.
FINDING_VERDICTS = ("breach", "chain", "hijack", "reinit")
MARKS = {"breach": "BREACH", "chain": "CHAIN", "hijack": "HIJACK", "reinit": "REINIT"}


def _findings(verdicts: list[dict]) -> list[str]:
    return [v["fn"] for v in verdicts if v.get("verdict") in FINDING_VERDICTS]


def evaluate(results: list[dict], ground_truth: dict[str, list[str]]) -> dict:
    tp = fp = fn = 0
    per_contract = []
    for r in results:
        contract = r["contract"]
        flagged = _findings(r["verdicts"])
        expected = list(ground_truth.get(contract, []))
        c_tp = [f for f in flagged if f in expected]
        c_fp = [f for f in flagged if f not in expected]
        c_fn = [f for f in expected if f not in flagged]
        tp += len(c_tp)
        fp += len(c_fp)
        fn += len(c_fn)
        per_contract.append({
            "contract": contract,
            "flagged": flagged,
            "expected": expected,
            "tp": c_tp, "fp": c_fp, "fn": c_fn,
        })
    precision = 1.0 if (tp + fp) == 0 else tp / (tp + fp)
    recall = 1.0 if (tp + fn) == 0 else tp / (tp + fn)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall,
        "per_contract": per_contract,
    }


def report_md(ev: dict, results: list[dict]) -> str:
    L = []
    L.append("# sorohunter — benchmark report")
    L.append("")
    L.append(f"**Precision {ev['precision']:.0%} · Recall {ev['recall']:.0%}** "
             f"(tp {ev['tp']}, fp {ev['fp']}, fn {ev['fn']})")
    L.append("")
    L.append("An ABI-driven adversarial hunter, run in local fork-sim over a benchmark "
             "corpus of Soroban contracts with planted missing-auth bugs and clean decoys. "
             "Each function is invoked under empty authorization; a call that changes state "
             "(emits an event) without a signature is a missing-auth finding, with the "
             "invocation itself as the executed PoC.")
    L.append("")
    L.append("## Scoreboard")
    L.append("")
    L.append("| contract | flagged (findings) | expected (ground truth) | fp | fn |")
    L.append("|---|---|---|---|---|")
    for pc in ev["per_contract"]:
        L.append(f"| {pc['contract']} | {', '.join(pc['flagged']) or '-'} | "
                 f"{', '.join(pc['expected']) or '-'} | {len(pc['fp'])} | {len(pc['fn'])} |")
    L.append("")
    L.append("## Probes (executed, with verdict)")
    by_contract = {r["contract"]: r for r in results}
    for pc in ev["per_contract"]:
        r = by_contract.get(pc["contract"])
        if not r:
            continue
        L.append(f"\n### {pc['contract']}")
        for v in r["verdicts"]:
            mark = MARKS.get(v.get("verdict"), v.get("verdict"))
            L.append(f"- **[{mark}] {v['fn']}({v.get('arg_types','')})** — {v.get('detail','')}")
    L.append("")
    L.append("## Reading")
    L.append("")
    if ev["fp"] == 0 and ev["fn"] == 0:
        L.append("The hunter caught every planted missing-auth bug and raised no false alarms "
                 "on the clean decoys. It also does not flag read-only views. This is the "
                 "precision that makes it safe to point at real public contracts: a false "
                 "positive on a live protocol would burn the exact credibility this is for.")
    else:
        if ev["fp"]:
            L.append(f"{ev['fp']} false positive(s): the hunter flagged clean functions. "
                     "Fix precision before pointing at anything real.")
        if ev["fn"]:
            L.append(f"{ev['fn']} false negative(s): the hunter missed a planted vuln. "
                     "The event-diff signal is not catching this mutation shape.")
    return "\n".join(L)


def write_artifacts(ev: dict, results: list[dict], out_prefix: str) -> None:
    os.makedirs(os.path.dirname(out_prefix) or ".", exist_ok=True)
    with open(f"{out_prefix}.json", "w") as f:
        json.dump({"evaluation": ev, "results": results}, f, indent=2)
    with open(f"{out_prefix}.md", "w") as f:
        f.write(report_md(ev, results))
