#![no_std]
//! Fixture: the CORRECT bank. Identical, but `withdraw` decrements the credit —
//! so no sequence lets the attacker withdraw more than they deposited. The
//! economic fuzzer must find no profit here.
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};
#[contracttype]
enum K { Token, Credit(Address) }
#[contract]
pub struct EconSafe;
#[contractimpl]
impl EconSafe {
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
        env.storage().persistent().set(&K::Credit(from.clone()), &(c - amount)); // THE FIX
        let me = env.current_contract_address();
        token::TokenClient::new(&env, &Self::tok(&env)).transfer(&me, &from, &amount);
    }
}
