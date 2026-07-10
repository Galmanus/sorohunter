#![no_std]
//! The liar payload for the oracle-lie detector ("everything that communicates is
//! attack surface"). A contract that trusts a caller-supplied oracle/token calls
//! back into whatever address it was handed; if that address is attacker-planted,
//! it lies. This one returns a settable price under every common oracle getter
//! name, so the detector can seed price=1 (honest) vs price=huge (lie) and see if
//! the victim's payout scales with the return.
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
enum Key { Price }

#[contract]
pub struct LiarOracle;

#[contractimpl]
impl LiarOracle {
    pub fn set_price(e: Env, p: i128) {
        e.storage().instance().set(&Key::Price, &p);
    }
    fn p(e: &Env) -> i128 { e.storage().instance().get(&Key::Price).unwrap_or(0) }

    pub fn get_price(e: Env) -> i128 { Self::p(&e) }
    pub fn lastprice(e: Env) -> i128 { Self::p(&e) }
    pub fn price(e: Env) -> i128 { Self::p(&e) }
    pub fn read_price(e: Env) -> i128 { Self::p(&e) }
    pub fn get_rate(e: Env) -> i128 { Self::p(&e) }
    // token-balance lie surface, same knob
    pub fn balance(e: Env, _id: Address) -> i128 { Self::p(&e) }
}
