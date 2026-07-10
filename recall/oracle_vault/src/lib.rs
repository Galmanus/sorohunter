#![no_std]
//! Recall target for the "oracle" detector — caller-supplied-oracle trust.
//!
//! `borrow` lets the caller draw reserves up to a limit read from an oracle it is
//! HANDED and never validates. An attacker passes a contract they control that
//! lies about the price, and borrows the reserves. "Everything that communicates
//! is attack surface": the return value of the caller-supplied contract is trusted.
use soroban_sdk::{contract, contractimpl, contracttype, token, vec, Address, Env, Symbol};

#[contracttype]
enum Key { Token }

#[contract]
pub struct OracleVault;

#[contractimpl]
impl OracleVault {
    pub fn __constructor(e: Env, token: Address) {
        e.storage().instance().set(&Key::Token, &token);
    }
    pub fn borrow(e: Env, user: Address, oracle: Address, amount: i128) {
        user.require_auth();
        // VULN: trusts a caller-supplied oracle with no allowlist check.
        let limit: i128 = e.invoke_contract(&oracle, &Symbol::new(&e, "get_price"), vec![&e]);
        if amount > limit {
            panic!("over limit");
        }
        let t: Address = e.storage().instance().get(&Key::Token).unwrap();
        token::Client::new(&e, &t).transfer(&e.current_contract_address(), &user, &amount);
    }
}
