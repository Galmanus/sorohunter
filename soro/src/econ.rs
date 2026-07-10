//! Economic-bug probing against real forked state. Step 1 (this module): the
//! value-measurement primitive — identify the token(s) a contract holds and,
//! in the fork, read how much of each the contract actually holds. That balance
//! delta across an attacker's calls is the drain signal.

use soroban_sdk::xdr::{ContractId, LedgerEntry, LedgerEntryData, ScAddress, ScVal};
use soroban_sdk::{Address, Env, String as SString, Symbol, TryFromVal, Val, Vec as SVec};

use crate::abi::FnPlan;

/// Recursively collect every contract `Address` reachable inside a ScVal — the
/// tokens/dependencies a contract references may be nested in a Vec, Map, or the
/// instance storage.
pub fn collect_contract_addrs(v: &ScVal, out: &mut Vec<String>) {
    match v {
        ScVal::Address(ScAddress::Contract(ContractId(h))) => {
            out.push(stellar_strkey::Contract(h.0).to_string());
        }
        ScVal::Vec(Some(items)) => {
            for x in items.iter() {
                collect_contract_addrs(x, out);
            }
        }
        ScVal::Map(Some(map)) => {
            for e in map.iter() {
                collect_contract_addrs(&e.key, out);
                collect_contract_addrs(&e.val, out);
            }
        }
        ScVal::ContractInstance(inst) => {
            if let Some(map) = &inst.storage {
                for e in map.iter() {
                    collect_contract_addrs(&e.key, out);
                    collect_contract_addrs(&e.val, out);
                }
            }
        }
        _ => {}
    }
}

/// Candidate tokens referenced anywhere in a contract's instance entry.
pub fn tokens_from_instance(entry: &LedgerEntry) -> Vec<String> {
    let mut out = Vec::new();
    if let LedgerEntryData::ContractData(cd) = &entry.data {
        collect_contract_addrs(&cd.val, &mut out);
    }
    out
}

/// Candidate tokens returned by the contract's no-arg getters — the reliable
/// path when tokens live in per-key persistent storage (e.g. AMM `get_tokens`).
/// Calls each no-arg function in the fork (real state) and collects any contract
/// address in the returned value.
pub fn tokens_from_getters(env: &Env, contract: &str, plan: &[FnPlan]) -> Vec<String> {
    let caddr = Address::from_string(&SString::from_str(env, contract));
    let mut out = Vec::new();
    for p in plan.iter().filter(|p| p.inputs.is_empty() && p.name != "__constructor") {
        env.mock_all_auths();
        if let Ok(Ok(val)) =
            env.try_invoke_contract::<Val, soroban_sdk::Error>(&caddr, &Symbol::new(env, &p.name), SVec::new(env))
        {
            if let Ok(scv) = ScVal::try_from_val(env, &val) {
                collect_contract_addrs(&scv, &mut out);
            }
        }
    }
    out
}

/// The contract's candidate tokens: instance references + getter returns, deduped.
pub fn candidate_tokens(env: &Env, contract: &str, instance: &LedgerEntry, plan: &[FnPlan]) -> Vec<String> {
    let mut out = tokens_from_instance(instance);
    out.extend(tokens_from_getters(env, contract, plan));
    out.sort();
    out.dedup();
    out
}
