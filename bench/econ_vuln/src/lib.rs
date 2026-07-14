#![no_std]
//! Fixture: a SEQUENCE-DEPENDENT ECONOMIC drain. A bank where `withdraw` checks
//! the credit but FORGETS to decrement it. Every call is legitimately authorized
//! by the actor (no auth bug), and each function in isolation looks fine. Only a
//! multi-call sequence — deposit(100), withdraw(100), withdraw(100), ... — leaves
//! the attacker richer than they started, draining the reserve. Auth-scan sees
//! nothing (all authorized); single-shot sees nothing (withdraw needs credit).
//! Only an economic fuzzer tracking net attacker profit over a sequence finds it.
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};
#[contracttype]
enum K { Token, Credit(Address) }
#[contract]
pub struct EconVuln;
#[contractimpl]
impl EconVuln {
    pub fn __constructor(env: Env, token: Address) { env.storage().instance().set(&K::Token, &token); }
    fn tok(env: &Env) -> Address { env.storage().instance().get(&K::Token).unwrap() }
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        if amount <= 0 { panic!("bad amount"); }
        let me = env.current_contract_address();
        token::TokenClient::new(&env, &Self::tok(&env)).transfer_from(&me, &from, &me, &amount);
        let c: i128 = env.storage().persistent().get(&K::Credit(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&K::Credit(from), &(c + amount));
    }
    pub fn withdraw(env: Env, from: Address, amount: i128) {
        from.require_auth();
        if amount <= 0 { panic!("bad amount"); }
        let c: i128 = env.storage().persistent().get(&K::Credit(from.clone())).unwrap_or(0);
        if c < amount { panic!("insufficient credit"); }
        // BUG: credit is NOT decremented -> withdraw is replayable, drains the reserve.
        let me = env.current_contract_address();
        token::TokenClient::new(&env, &Self::tok(&env)).transfer(&me, &from, &amount);
    }
}
