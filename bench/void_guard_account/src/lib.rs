#![no_std]
//! Fixture: a subtly broken smart account. `__check_auth` rejects only a void
//! signature and accepts anything non-void without cryptographic verification.
//! This is the SDK's own NoopAccount example turned into a bug: it looks like it
//! "checks" something, but any garbage 64-byte blob (or an integer) passes. The
//! prover must reject the void hypothesis on it yet still flag the non-void ones,
//! proving it detects more than a bare `Ok(())` stub.

use soroban_sdk::{auth::Context, contract, contracterror, contractimpl, BytesN, Env, Val, Vec};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    Void = 1,
}

#[contract]
pub struct VoidGuardAccount;

#[contractimpl]
impl VoidGuardAccount {
    #[allow(non_snake_case)]
    pub fn __check_auth(
        _env: Env,
        _signature_payload: BytesN<32>,
        signature: Val,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        // Presence check masquerading as verification.
        if signature.is_void() {
            Err(Error::Void)
        } else {
            Ok(())
        }
    }
}
