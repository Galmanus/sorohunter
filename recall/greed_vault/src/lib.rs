#![no_std]
//! Recall test for the "greed" detector: a vault that pays ANY authorizing
//! caller from its reserves with no eligibility check.
//!
//! `claim` calls `caller.require_auth()` — so under EMPTY auth it reverts, and
//! the unauthenticated drain detector never sees it. But it never verifies the
//! caller deposited or is owed anything, so under the caller's OWN auth it hands
//! out reserves to whoever signs. That is the authorized-but-broken-accounting
//! class. `token()` is the getter the detector uses to find the reserve token.
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
enum DataKey {
    Token,
}

#[contract]
pub struct GreedVault;

#[contractimpl]
impl GreedVault {
    pub fn __constructor(e: Env, token: Address) {
        e.storage().instance().set(&DataKey::Token, &token);
    }
    pub fn token(e: Env) -> Address {
        e.storage().instance().get(&DataKey::Token).unwrap()
    }
    /// VULN: caller authorizes, but there is NO check they are owed anything —
    /// anyone who signs receives `amount` of the vault's reserves.
    pub fn claim(e: Env, caller: Address, amount: i128) {
        caller.require_auth();
        let token: Address = e.storage().instance().get(&DataKey::Token).unwrap();
        token::Client::new(&e, &token).transfer(&e.current_contract_address(), &caller, &amount);
    }
}
