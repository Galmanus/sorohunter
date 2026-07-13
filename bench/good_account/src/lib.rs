#![no_std]
//! Fixture: a CORRECT ed25519 smart account. The false-positive control for the
//! auth-bypass prover. `__check_auth` verifies the ed25519 signature over the
//! signature payload with the pubkey fixed at construction. Every forged or
//! absent signature the prover submits must be rejected, so this contract must
//! produce ZERO bypass. If the prover flags it, the prover is broken.

use soroban_sdk::{
    auth::Context, contract, contracterror, contractimpl, symbol_short, Bytes, BytesN, Env,
    TryIntoVal, Val, Vec,
};

const PK: soroban_sdk::Symbol = symbol_short!("pk");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    BadSig = 1,
}

#[contract]
pub struct GoodAccount;

#[contractimpl]
impl GoodAccount {
    /// Bind the account to a single ed25519 public key.
    pub fn __constructor(env: Env, pubkey: BytesN<32>) {
        env.storage().instance().set(&PK, &pubkey);
    }

    #[allow(non_snake_case)]
    pub fn __check_auth(
        env: Env,
        signature_payload: BytesN<32>,
        signature: Val,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        // A non-BytesN<64> signature (void, int, empty bytes, wrong length)
        // fails to convert and is rejected. This is the type-confusion guard.
        let sig: BytesN<64> = signature
            .try_into_val(&env)
            .map_err(|_| Error::BadSig)?;
        let pubkey: BytesN<32> = env.storage().instance().get(&PK).ok_or(Error::BadSig)?;
        let msg = Bytes::from_array(&env, &signature_payload.to_array());
        // Panics (auth fails) if the signature does not verify.
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        Ok(())
    }
}
