//! Native Soroban RPC acquisition: fetch a deployed contract's WASM by id via
//! JSON-RPC `getLedgerEntries`, with no `stellar` CLI. Two hops: the contract
//! instance entry gives the WASM hash; the contract-code entry gives the bytes.
//! Read-only — this only reads public ledger state.

use soroban_sdk::xdr::{
    ContractCodeEntry, ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntry,
    LedgerEntryData, LedgerEntryExt, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData,
    Limits, ReadXdr, ScAddress, ScContractInstance, ScVal, WriteXdr,
};

pub fn rpc_url(network: &str) -> &'static str {
    match network {
        "mainnet" | "public" => "https://mainnet.sorobanrpc.com",
        "futurenet" => "https://rpc-futurenet.stellar.org",
        _ => "https://soroban-testnet.stellar.org",
    }
}

/// One `getLedgerEntries` call; returns each entry's `LedgerEntryData` XDR (b64).
fn get_entries(url: &str, keys_b64: &[String]) -> Option<Vec<String>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getLedgerEntries",
        "params": { "keys": keys_b64 }
    });
    let resp: serde_json::Value = ureq::post(url).send_json(body).ok()?.into_json().ok()?;
    let entries = resp.get("result")?.get("entries")?.as_array()?;
    Some(
        entries
            .iter()
            .filter_map(|e| e.get("xdr").and_then(|x| x.as_str()).map(String::from))
            .collect(),
    )
}

/// `getLatestLedger` -> (sequence, protocol_version), for the snapshot header.
pub fn latest_ledger(url: &str) -> Option<(u32, u32)> {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "getLatestLedger"});
    let resp: serde_json::Value = ureq::post(url).send_json(body).ok()?.into_json().ok()?;
    let r = resp.get("result")?;
    Some((r.get("sequence")?.as_u64()? as u32, r.get("protocolVersion")?.as_u64()? as u32))
}

/// `getLedgerEntries` returning (data-xdr-b64, last_modified_seq, live_until) per key.
fn get_entries_full(url: &str, keys_b64: &[String]) -> Option<Vec<(String, u32, Option<u32>)>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getLedgerEntries",
        "params": { "keys": keys_b64 }
    });
    let resp: serde_json::Value = ureq::post(url).send_json(body).ok()?.into_json().ok()?;
    let entries = resp.get("result")?.get("entries")?.as_array()?;
    Some(
        entries
            .iter()
            .filter_map(|e| {
                let x = e.get("xdr")?.as_str()?.to_string();
                let lm = e.get("lastModifiedLedgerSeq").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let lu = e.get("liveUntilLedgerSeq").and_then(|v| v.as_u64()).map(|v| v as u32);
                Some((x, lm, lu))
            })
            .collect(),
    )
}

fn make_entry(data: LedgerEntryData, last_modified: u32) -> LedgerEntry {
    LedgerEntry { last_modified_ledger_seq: last_modified, data, ext: LedgerEntryExt::V0 }
}

/// Fetch the contract's instance + code entries as full `LedgerEntry`s for a
/// minimal state-fork: the instance carries the real admin/config storage, the
/// code is the WASM. Enough to probe against real auth state (not per-address
/// balances). Returns entries shaped for `LedgerSnapshot::ledger_entries`.
pub fn fetch_snapshot_entries(
    url: &str,
    contract_id: &str,
) -> Option<Vec<(Box<LedgerKey>, (Box<LedgerEntry>, Option<u32>))>> {
    let sk = stellar_strkey::Contract::from_string(contract_id).ok()?;
    let hash = Hash(sk.0);

    let inst_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(hash)),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let inst_b64 = inst_key.to_xdr_base64(Limits::none()).ok()?;
    let (inst_xdr, inst_lm, inst_lu) = get_entries_full(url, &[inst_b64])?.into_iter().next()?;
    let inst_data = LedgerEntryData::from_xdr_base64(&inst_xdr, Limits::none()).ok()?;
    let wasm_hash = match &inst_data {
        LedgerEntryData::ContractData(cd) => match &cd.val {
            ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(h),
                ..
            }) => h.clone(),
            _ => return None,
        },
        _ => return None,
    };

    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: wasm_hash });
    let code_b64 = code_key.to_xdr_base64(Limits::none()).ok()?;
    let (code_xdr, code_lm, code_lu) = get_entries_full(url, &[code_b64])?.into_iter().next()?;
    let code_data = LedgerEntryData::from_xdr_base64(&code_xdr, Limits::none()).ok()?;

    Some(vec![
        (Box::new(inst_key), (Box::new(make_entry(inst_data, inst_lm)), inst_lu)),
        (Box::new(code_key), (Box::new(make_entry(code_data, code_lm)), code_lu)),
    ])
}

/// Fetch a deployed contract's WASM bytes by contract id (C...). None on any
/// miss (bad id, not found, not a wasm contract, RPC error).
pub fn fetch_wasm(url: &str, contract_id: &str) -> Option<Vec<u8>> {
    let sk = stellar_strkey::Contract::from_string(contract_id).ok()?;
    let hash = Hash(sk.0);

    // hop 1: the contract instance entry -> the wasm hash
    let inst_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(hash)),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let inst_b64 = inst_key.to_xdr_base64(Limits::none()).ok()?;
    let inst_xdr = get_entries(url, &[inst_b64])?.into_iter().next()?;
    let wasm_hash = match LedgerEntryData::from_xdr_base64(&inst_xdr, Limits::none()).ok()? {
        LedgerEntryData::ContractData(cd) => match cd.val {
            ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(h),
                ..
            }) => h,
            _ => return None,
        },
        _ => return None,
    };

    // hop 2: the contract code entry -> the wasm bytes
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: wasm_hash });
    let code_b64 = code_key.to_xdr_base64(Limits::none()).ok()?;
    let code_xdr = get_entries(url, &[code_b64])?.into_iter().next()?;
    match LedgerEntryData::from_xdr_base64(&code_xdr, Limits::none()).ok()? {
        LedgerEntryData::ContractCode(ContractCodeEntry { code, .. }) => Some(code.into()),
        _ => None,
    }
}
