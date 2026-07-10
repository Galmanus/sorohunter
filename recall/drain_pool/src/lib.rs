#![no_std]
//! Recall test for the economic drain detector: a pool that holds a token and
//! has an UNPROTECTED drain — `steal` transfers the pool's reserves out with NO
//! caller auth. The detector should flag it (pool's real token balance drops
//! under empty auth). `token()` is the getter the detector uses to find the token.
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
enum DataKey { Token }

#[contract]
pub struct DrainPool;

#[contractimpl]
impl DrainPool {
    pub fn __constructor(e: Env, token: Address) {
        e.storage().instance().set(&DataKey::Token, &token);
    }
    pub fn token(e: Env) -> Address {
        e.storage().instance().get(&DataKey::Token).unwrap()
    }
    /// VULN: no `require_auth` — anyone drains the pool's reserves.
    pub fn steal(e: Env, to: Address, amount: i128) {
        let token: Address = e.storage().instance().get(&DataKey::Token).unwrap();
        token::Client::new(&e, &token).transfer(&e.current_contract_address(), &to, &amount);
    }
}
