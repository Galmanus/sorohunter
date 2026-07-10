//! Supply-chain layer: the SDK betrays the author.
//!
//! Three 2026 CVEs live in `rs-soroban-sdk` itself, not in contract logic. A
//! contract compiled against a pre-patch SDK carries the flaw baked in and
//! immutable — there is no hotfix for an on-chain WASM without a redeploy, and
//! redeploy inertia is high. So a contract's `rssdkver` (recorded in the
//! `contractmetav0` WASM section) cross-referenced against the patched-version
//! table is a dated, non-circular vulnerability signal — evidence that is
//! *signed*, not *inferred*. This is the check no contract-logic scanner runs.
//!
//! Version-vulnerable is NECESSARY, not sufficient: e.g. CVE-2026-26267 also
//! needs a trait/inherent name collision in the code. This flags exposure; the
//! code pattern or a dynamic probe confirms exploitability.

use std::io::Cursor;
use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScMetaEntry};
use wasmparser::{Parser, Payload};

/// A confirmed soroban-sdk advisory and the first patched version per major branch.
pub struct Cve {
    pub id: &'static str,
    pub sev: &'static str,
    pub what: &'static str,
    pub needs: &'static str,
    /// (major, minor, patch) first fixed, per major branch.
    pub patched: &'static [(u64, u64, u64)],
}

/// Verified against GitHub Security Advisories + NVD (2026-07).
pub const CVES: &[Cve] = &[
    Cve {
        id: "CVE-2026-26267", sev: "HIGH",
        what: "#[contractimpl] calls inherent fn instead of trait fn on name collision -> AUTH BYPASS",
        needs: "a trait fn and an inherent fn share a name; require_auth lives in the trait one",
        patched: &[(22, 0, 10), (23, 5, 2), (25, 1, 1)],
    },
    Cve {
        id: "CVE-2026-24889", sev: "MED",
        what: "silent overflow in Bytes::slice / Vec::slice / Prng::gen_range (u64)",
        needs: "a user-controlled bound passed to slice/gen_range under overflow-checks=false",
        patched: &[(22, 0, 10), (23, 5, 2), (25, 1, 1)],
    },
    Cve {
        id: "CVE-2026-32322", sev: "MED",
        what: "Fr (BN254/BLS12-381) equality skips modular reduction -> validation bypass",
        needs: "an Fr equality check on an attacker-supplied scalar (ZK verifier)",
        patched: &[(22, 0, 11), (23, 5, 3), (25, 3, 0)],
    },
];

/// Parse "22.0.7#<githash>" -> (22,0,7).
pub fn parse_ver(s: &str) -> Option<(u64, u64, u64)> {
    let head = s.split(['#', '-', '+']).next().unwrap_or(s);
    let mut it = head.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    Some((a, b, c))
}

/// Is `ver` vulnerable to `cve`? A version on a patched branch is vulnerable
/// below its fix; a major older than any patched branch has no backport; a major
/// newer than every patched branch is treated as safe.
pub fn is_vulnerable(ver: (u64, u64, u64), cve: &Cve) -> bool {
    let majors: Vec<u64> = cve.patched.iter().map(|p| p.0).collect();
    let min_major = *majors.iter().min().unwrap();
    let max_major = *majors.iter().max().unwrap();
    if let Some(fix) = cve.patched.iter().find(|p| p.0 == ver.0) {
        return ver < *fix;
    }
    if ver.0 < min_major {
        return true; // ancient branch, no backport
    }
    if ver.0 > max_major {
        return false; // newer than any patched line
    }
    true // between patched branches with no listed fix
}

/// Read `rssdkver` from the WASM `contractmetav0` custom section. `None` for SACs
/// (host-native, no meta) or contracts stripped of meta.
pub fn sdk_version_from_wasm(wasm: &[u8]) -> Option<String> {
    let mut raw: Option<Vec<u8>> = None;
    for payload in Parser::new(0).parse_all(wasm) {
        if let Ok(Payload::CustomSection(s)) = payload {
            if s.name() == "contractmetav0" {
                raw = Some(s.data().to_vec());
                break;
            }
        }
    }
    let raw = raw?;
    let mut lim = Limited::new(Cursor::new(raw), Limits { depth: 100, len: 0x100000 });
    for entry in ScMetaEntry::read_xdr_iter(&mut lim).flatten() {
        let ScMetaEntry::ScMetaV0(v) = entry;
        if v.key.to_string() == "rssdkver" {
            return Some(v.val.to_string());
        }
    }
    None
}

/// The CVEs a given SDK version string is exposed to (by version alone).
pub fn exposure(sdkver: &str) -> Vec<&'static Cve> {
    match parse_ver(sdkver) {
        Some(ver) => CVES.iter().filter(|c| is_vulnerable(ver, c)).collect(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rssdkver_string() {
        assert_eq!(parse_ver("22.0.7#211569aa49c8"), Some((22, 0, 7)));
        assert_eq!(parse_ver("25.3.0"), Some((25, 3, 0)));
    }

    #[test]
    fn branch_aware_vulnerability() {
        let auth_bypass = &CVES[0]; // patched 22.0.10 / 23.5.2 / 25.1.1
        assert!(is_vulnerable((22, 0, 7), auth_bypass), "22.0.7 < 22.0.10 -> vuln");
        assert!(!is_vulnerable((22, 0, 10), auth_bypass), "22.0.10 is the fix -> safe");
        assert!(is_vulnerable((20, 2, 0), auth_bypass), "ancient 20.x -> no backport, vuln");
        assert!(!is_vulnerable((25, 1, 1), auth_bypass), "25.1.1 is the fix -> safe");
        assert!(!is_vulnerable((26, 0, 0), auth_bypass), "newer than any patched line -> safe");
    }

    #[test]
    fn fr_cve_has_later_fix_line() {
        let fr = &CVES[2]; // patched 25.3.0
        assert!(is_vulnerable((25, 1, 1), fr), "25.1.1 < 25.3.0 -> still Fr-vuln");
        assert!(!is_vulnerable((25, 3, 0), fr), "25.3.0 is the Fr fix -> safe");
    }
}
