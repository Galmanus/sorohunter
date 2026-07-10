//! Native Soroban RPC acquisition: fetch a deployed contract's WASM by id via
//! JSON-RPC `getLedgerEntries`, with no `stellar` CLI. Two hops: the contract
//! instance entry gives the WASM hash; the contract-code entry gives the bytes.
//! Read-only — this only reads public ledger state.

use soroban_sdk::xdr::{
    ContractCodeEntry, ContractDataDurability, ContractExecutable, ContractId, Hash,
    LedgerEntryData, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limits, ReadXdr,
    ScAddress, ScContractInstance, ScVal, WriteXdr,
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
