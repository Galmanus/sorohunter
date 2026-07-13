#![no_std]
//! Fixture: a CORRECT secp256r1 (passkey / WebAuthn) smart account, the
//! false-positive control for the `--realauth-p256` prover. It speaks the real
//! passkey-kit ABI: a `Signer` constructor and a `Signatures(Map<SignerKey,
//! Signature>)` `__check_auth`, verifying an ECDSA-secp256r1 assertion the way a
//! WebAuthn wallet must.
//!
//! The one line that makes it correct is the challenge binding: it recomputes
//! the base64url-encoded `signature_payload` and asserts the signed
//! `client_data_json` actually carries it as its `challenge`. Its buggy twin
//! `unbound_passkey` verifies the very same signature but skips that check — the
//! executable analogue of a passkey wallet that trusts an attacker-reconstructed
//! `clientDataJSON` (cf. swig-wallet #143). If this fixture ever flags a bypass,
//! the prover is broken.

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
    ChallengeMismatch = 3,
}

/// base64url (no padding) of a 32-byte payload → 43 bytes.
fn b64url_challenge(env: &Env, data: &[u8; 32]) -> Bytes {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = [0u8; 43];
    let mut oi = 0usize;
    let mut i = 0usize;
    while i + 3 <= 32 {
        let n = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | (data[i + 2] as u32);
        out[oi] = T[((n >> 18) & 63) as usize];
        out[oi + 1] = T[((n >> 12) & 63) as usize];
        out[oi + 2] = T[((n >> 6) & 63) as usize];
        out[oi + 3] = T[(n & 63) as usize];
        oi += 4;
        i += 3;
    }
    // trailing 2 bytes (32 mod 3 == 2) -> 3 chars
    let n = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8;
    out[oi] = T[((n >> 18) & 63) as usize];
    out[oi + 1] = T[((n >> 12) & 63) as usize];
    out[oi + 2] = T[((n >> 6) & 63) as usize];
    Bytes::from_array(env, &out)
}

/// Naive substring search over host `Bytes`.
fn contains(hay: &Bytes, needle: &Bytes) -> bool {
    let (hl, nl) = (hay.len(), needle.len());
    if nl == 0 {
        return true;
    }
    if nl > hl {
        return false;
    }
    let mut i = 0u32;
    while i + nl <= hl {
        let mut j = 0u32;
        let mut ok = true;
        while j < nl {
            if hay.get(i + j) != needle.get(j) {
                ok = false;
                break;
            }
            j += 1;
        }
        if ok {
            return true;
        }
        i += 1;
    }
    false
}

#[contract]
pub struct BoundPasskey;

#[contractimpl]
impl BoundPasskey {
    /// Bind the account to a single secp256r1 public key, taken from the real
    /// `Signer` constructor shape.
    pub fn __constructor(env: Env, signer: Signer) {
        let pk = match signer {
            Signer::Secp256r1(_id, pubkey, _e, _l, _s) => pubkey,
            _ => panic!("bound_passkey requires a Secp256r1 signer"),
        };
        env.storage().instance().set(&PK, &pk);
    }

    #[allow(non_snake_case)]
    pub fn __check_auth(
        env: Env,
        signature_payload: BytesN<32>,
        signature: Val,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        let sigs: Signatures = signature.try_into_val(&env).map_err(|_| Error::BadSig)?;
        let (_key, sig) = sigs.0.iter().next().ok_or(Error::NoSigner)?;
        let asrt = match sig {
            Signature::Secp256r1(a) => a,
            _ => return Err(Error::BadSig),
        };

        // THE BINDING: the signed clientDataJSON must carry this exact payload as
        // its WebAuthn challenge. Without this line a valid assertion for payload
        // A authorizes any other payload.
        let expected = b64url_challenge(&env, &signature_payload.to_array());
        if !contains(&asrt.client_data_json, &expected) {
            return Err(Error::ChallengeMismatch);
        }

        // WebAuthn digest: sha256(authenticatorData || sha256(clientDataJSON)).
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
