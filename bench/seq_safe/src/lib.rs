#![no_std]
//! Fixture: the CORRECT control. Same arm/fire shape, but `fire` requires the
//! admin's authorization regardless of armed state — so no call sequence lets an
//! unauthenticated attacker fire. The fuzzer must report `held` no matter what
//! sequence it explores.
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol};
const ARMED: Symbol = symbol_short!("armed");
#[contracttype]
enum K { Admin }
#[contract]
pub struct SeqSafe;
#[contractimpl]
impl SeqSafe {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&K::Admin, &admin);
    }
    pub fn arm(env: Env) {
        env.storage().instance().set(&ARMED, &true);
    }
    pub fn fire(env: Env) {
        let admin: Address = env.storage().instance().get(&K::Admin).unwrap();
        admin.require_auth(); // gated regardless of armed -> no sequence bypasses it
        env.events().publish((symbol_short!("fired"),), true);
    }
}
