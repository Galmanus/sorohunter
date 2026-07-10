//! Lazy Soroban RPC snapshot source. When the host reads a ledger key the fork
//! does not yet have, this fetches that exact entry via `getLedgerEntries`
//! (cached), so the fork sees the contract's REAL full on-chain state —
//! balances, reserves, config — on demand. No history-archive download, no key
//! enumeration: the host pulls only the keys the contract actually touches.
//! This is what economic-bug probing needs (real liquidity/balances).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use soroban_sdk::testutils::{HostError, SnapshotSource};
use soroban_sdk::xdr::{LedgerEntry, LedgerKey, Limits, WriteXdr};

use crate::rpc;

pub struct RpcSnapshotSource {
    url: String,
    cache: RefCell<HashMap<String, Option<(Rc<LedgerEntry>, Option<u32>)>>>,
}

impl RpcSnapshotSource {
    pub fn new(url: &str) -> Self {
        Self { url: url.to_string(), cache: RefCell::new(HashMap::new()) }
    }
}

impl SnapshotSource for RpcSnapshotSource {
    fn get(&self, key: &Rc<LedgerKey>) -> Result<Option<(Rc<LedgerEntry>, Option<u32>)>, HostError> {
        let key_b64 = match key.to_xdr_base64(Limits::none()) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };
        if let Some(hit) = self.cache.borrow().get(&key_b64) {
            return Ok(hit.clone());
        }
        let out = rpc::fetch_entry(&self.url, &key_b64).map(|(e, lu)| (Rc::new(e), lu));
        self.cache.borrow_mut().insert(key_b64, out.clone());
        Ok(out)
    }
}
