"""Evaluate harness verdicts against ground truth: a breach on a known-vulnerable
function is a true positive; a breach on a clean function is a false positive; a
missed vulnerable function is a false negative. Precision/recall is what proves
the hunter is safe to point at real contracts."""
from sorohunter.report import evaluate


def result(contract, **verdicts):
    return {"contract": contract, "verdicts": [{"fn": f, "verdict": v} for f, v in verdicts.items()]}


def test_perfect_precision_and_recall():
    results = [
        result("vuln_vault", deposit="held", withdraw="breach", balance="view"),
        result("safe_vault", deposit="held", withdraw="held", balance="view"),
    ]
    gt = {"vuln_vault": ["withdraw"], "safe_vault": []}
    ev = evaluate(results, gt)
    assert ev["tp"] == 1 and ev["fp"] == 0 and ev["fn"] == 0
    assert ev["precision"] == 1.0 and ev["recall"] == 1.0


def test_false_positive_lowers_precision():
    results = [result("safe_vault", withdraw="breach")]
    gt = {"safe_vault": []}
    ev = evaluate(results, gt)
    assert ev["fp"] == 1 and ev["tp"] == 0
    assert ev["precision"] == 0.0


def test_false_negative_lowers_recall():
    results = [result("vuln_vault", withdraw="held")]  # missed the planted vuln
    gt = {"vuln_vault": ["withdraw"]}
    ev = evaluate(results, gt)
    assert ev["fn"] == 1 and ev["tp"] == 0
    assert ev["recall"] == 0.0


def test_no_findings_no_vulns_is_clean():
    results = [result("safe_vault", deposit="held", balance="view")]
    gt = {"safe_vault": []}
    ev = evaluate(results, gt)
    assert ev["tp"] == 0 and ev["fp"] == 0 and ev["fn"] == 0
    # precision/recall are defined as 1.0 when there is nothing to get wrong
    assert ev["precision"] == 1.0 and ev["recall"] == 1.0


def test_per_contract_breakdown():
    results = [result("vuln_vault", withdraw="breach")]
    gt = {"vuln_vault": ["withdraw"]}
    ev = evaluate(results, gt)
    pc = ev["per_contract"][0]
    assert pc["contract"] == "vuln_vault"
    assert pc["flagged"] == ["withdraw"]
    assert pc["expected"] == ["withdraw"]
