#![no_std]
//! Recall target for the "hijack" (admin-capture / TA-02) detector: a contract
//! whose `set_admin` overwrites the admin with NO current-admin auth check.
//!
//! `admin()` is the getter the detector reads to learn who holds control.
//! `set_admin(new_admin)` is the unprotected privilege setter — anyone can call
//! it under empty auth and seize the admin role. A correctly-written setter would
//! call `current_admin.require_auth()` first, which reverts under empty auth; this
//! one omits it, so `scan --fork` sees the attacker become admin against real state.
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
enum DataKey {
    Admin,
}

#[contract]
pub struct AdminCapture;

#[contractimpl]
impl AdminCapture {
    pub fn __constructor(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn admin(e: Env) -> Address {
        e.storage().instance().get(&DataKey::Admin).unwrap()
    }

    // VULN: no `current_admin.require_auth()` — unprotected privilege setter.
    pub fn set_admin(e: Env, new_admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &new_admin);
    }
}
