#![no_std]
//! Fixture: the PASSKEY BINDING BUG (swig-wallet #143 class). It verifies a real
//! ECDSA-secp256r1 WebAuthn assertion correctly — so the forgery battery finds
//! nothing — but never checks that the signed `clientDataJSON` challenge equals
//! the `signature_payload` the host is authorizing. One genuine assertion the
//! user ever produced (observable on-chain) can therefore be replayed to
//! authorize a DIFFERENT payload.
//!
//! It differs from `bound_passkey` by exactly one removed block (the challenge
//! binding). Both verify the same signature over the same WebAuthn digest, so a
//! `replay-bypass` verdict here reads the binding bug specifically, not a parse
//! failure or a missing verify.

use soroban_sdk::{
    auth::Context, contract, contracterror, contractimpl, contracttype, symbol_short, Bytes,
    BytesN, Env, Map, TryIntoVal, Val, Vec,
};

const PK: soroban_sdk::Symbol = symbol_short!("pk");

// --- passkey-kit ABI mirror (byte-identical Val/XDR encoding) ---------------
#[contracttype]
#[derive(Clone)]
pub struct SignerExpiration(pub Option<u32>);
#[contracttype]
#[derive(Clone)]
pub struct SignerLimits(pub Option<Map<soroban_sdk::Address, Option<Vec<SignerKey>>>>);
#[contracttype]
#[derive(Clone)]
pub struct Secp256r1Signature {
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    pub signature: BytesN<64>,
}
#[contracttype]
#[derive(Clone)]
pub struct Signatures(pub Map<SignerKey, Signature>);
#[contracttype]
#[derive(Clone)]
pub enum SignerStorage {
    Persistent,
    Temporary,
}
#[contracttype]
#[derive(Clone)]
pub enum Signer {
    Policy(soroban_sdk::Address, SignerExpiration, SignerLimits, SignerStorage),
    Ed25519(BytesN<32>, SignerExpiration, SignerLimits, SignerStorage),
    Secp256r1(Bytes, BytesN<65>, SignerExpiration, SignerLimits, SignerStorage),
}
#[contracttype]
#[derive(Clone)]
pub enum SignerKey {
    Policy(soroban_sdk::Address),
    Ed25519(BytesN<32>),
    Secp256r1(Bytes),
}
#[contracttype]
#[derive(Clone)]
pub enum Signature {
    Policy,
    Ed25519(BytesN<64>),
    Secp256r1(Secp256r1Signature),
}
// ----------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    BadSig = 1,
    NoSigner = 2,
}

#[contract]
pub struct UnboundPasskey;

#[contractimpl]
impl UnboundPasskey {
    pub fn __constructor(env: Env, signer: Signer) {
        let pk = match signer {
            Signer::Secp256r1(_id, pubkey, _e, _l, _s) => pubkey,
            _ => panic!("unbound_passkey requires a Secp256r1 signer"),
        };
        env.storage().instance().set(&PK, &pk);
    }

    #[allow(non_snake_case)]
    pub fn __check_auth(
        env: Env,
        _signature_payload: BytesN<32>,
        signature: Val,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        let sigs: Signatures = signature.try_into_val(&env).map_err(|_| Error::BadSig)?;
        let (_key, sig) = sigs.0.iter().next().ok_or(Error::NoSigner)?;
        let asrt = match sig {
            Signature::Secp256r1(a) => a,
            _ => return Err(Error::BadSig),
        };

        // NO challenge binding here. The signature is verified over the WebAuthn
        // digest, but nothing ties `client_data_json.challenge` to
        // `_signature_payload`. THE BUG.
        let cdj_hash = env.crypto().sha256(&asrt.client_data_json).to_array();
        let mut msg = asrt.authenticator_data.clone();
        msg.extend_from_array(&cdj_hash);
        let digest = env.crypto().sha256(&msg);

        let pubkey: BytesN<65> = env.storage().instance().get(&PK).ok_or(Error::NoSigner)?;
        env.crypto()
            .secp256r1_verify(&pubkey, &digest, &asrt.signature);
        Ok(())
    }
}
