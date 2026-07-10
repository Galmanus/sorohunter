//! Score verdicts against ground truth and label findings. Port of `report.py`.

use std::collections::BTreeMap;

use crate::engine::{Verdict, FINDING_VERDICTS};

/// A finding is a breach (TA-01), a confirmed chain (TE-01), an upgrade hijack
/// (TP-01), or a re-initialization (TA-03). `init-guarded` is NOT a finding.
pub fn findings(verdicts: &[Verdict]) -> Vec<String> {
    verdicts
        .iter()
        .filter(|v| FINDING_VERDICTS.contains(&v.verdict.as_str()))
        .map(|v| v.fn_name.clone())
        .collect()
}

pub fn mark(verdict: &str) -> &'static str {
    match verdict {
        "breach" => "BREACH",
        "chain" => "CHAIN",
        "hijack" => "HIJACK",
        "reinit" => "REINIT",
        "drain" => "DRAIN",
        "greed" => "GREED",
        "redirect" => "REDIRECT",
        "init-guarded" => "init-guarded",
        "held" => "held",
        "view" => "view",
        "skipped" => "skipped",
        _ => "?",
    }
}

pub struct PerContract {
    pub contract: String,
    pub flagged: Vec<String>,
    pub fp: Vec<String>,
    pub fn_: Vec<String>,
}

pub struct Eval {
    pub tp: usize,
    pub fp: usize,
    pub fn_: usize,
    pub precision: f64,
    pub recall: f64,
    pub per: Vec<PerContract>,
}

pub fn evaluate(results: &[(String, Vec<Verdict>)], gt: &BTreeMap<String, Vec<String>>) -> Eval {
    let (mut tp, mut fp, mut fnn) = (0usize, 0usize, 0usize);
    let mut per = Vec::new();
    for (contract, verdicts) in results {
        let flagged = findings(verdicts);
        let expected = gt.get(contract).cloned().unwrap_or_default();
        let c_fp: Vec<String> = flagged.iter().filter(|f| !expected.contains(f)).cloned().collect();
        let c_fn: Vec<String> = expected.iter().filter(|e| !flagged.contains(e)).cloned().collect();
        let c_tp = flagged.len() - c_fp.len();
        tp += c_tp;
        fp += c_fp.len();
        fnn += c_fn.len();
        per.push(PerContract { contract: contract.clone(), flagged, fp: c_fp, fn_: c_fn });
    }
    let precision = if tp + fp == 0 { 1.0 } else { tp as f64 / (tp + fp) as f64 };
    let recall = if tp + fnn == 0 { 1.0 } else { tp as f64 / (tp + fnn) as f64 };
    Eval { tp, fp, fn_: fnn, precision, recall, per }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Verdict;

    fn v(fn_name: &str, verdict: &str) -> Verdict {
        Verdict { fn_name: fn_name.into(), arg_types: String::new(), verdict: verdict.into(), events_delta: 0, detail: String::new() }
    }

    #[test]
    fn findings_counts_the_right_verdicts() {
        let vs = vec![v("withdraw", "breach"), v("a->b", "chain"), v("upgrade", "hijack"), v("initialize", "init-guarded"), v("deposit", "held"), v("name", "view")];
        let f = findings(&vs);
        assert_eq!(f, vec!["withdraw", "a->b", "upgrade"]);
    }

    #[test]
    fn perfect_score_on_planted_vulns() {
        let mut gt = BTreeMap::new();
        gt.insert("vuln".to_string(), vec!["withdraw".to_string()]);
        gt.insert("safe".to_string(), vec![]);
        let results = vec![
            ("vuln".to_string(), vec![v("withdraw", "breach"), v("deposit", "held")]),
            ("safe".to_string(), vec![v("withdraw", "held")]),
        ];
        let ev = evaluate(&results, &gt);
        assert_eq!((ev.tp, ev.fp, ev.fn_), (1, 0, 0));
        assert_eq!(ev.precision, 1.0);
        assert_eq!(ev.recall, 1.0);
    }

    #[test]
    fn init_guarded_is_not_a_false_positive() {
        let mut gt = BTreeMap::new();
        gt.insert("real".to_string(), vec![]);
        let results = vec![("real".to_string(), vec![v("initialize", "init-guarded"), v("swap", "held")])];
        let ev = evaluate(&results, &gt);
        assert_eq!((ev.tp, ev.fp, ev.fn_), (0, 0, 0));
    }
}
