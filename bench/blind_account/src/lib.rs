#![no_std]
//! Fixture: the canonical broken smart account. `__check_auth` returns Ok(())
//! without ever inspecting the signature. This is the "forgot to verify" bug,
//! the highest-severity auth-bypass class: any caller authorizes as this
//! account. The prover must flag EVERY hypothesis against it.

use soroban_sdk::{auth::Context, contract, contracterror, contractimpl, BytesN, Env, Val, Vec};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    Never = 1,
}

#[contract]
pub struct BlindAccount;

#[contractimpl]
impl BlindAccount {
    #[allow(non_snake_case)]
    pub fn __check_auth(
        _env: Env,
        _signature_payload: BytesN<32>,
        _signature: Val,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        // No verification. Anyone is authorized.
        Ok(())
    }
}
