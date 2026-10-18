//! Core cryptographic types, field aliases, and data structures.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::{PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BN254 scalar field representing prime field elements Fr.
pub type ScalarField = Fr;

/// Groth16 curve pairing engine type.
pub type CurveEngine = Bn254;

/// Groth16 zero-knowledge proof over BN254.
pub type ZkProof = Proof<CurveEngine>;

/// Groth16 proving key (SRS evaluation key).
pub type ZkProvingKey = ProvingKey<CurveEngine>;

/// Groth16 verifying key.
pub type ZkVerifyingKey = VerifyingKey<CurveEngine>;

/// Prepared verifying key optimized for repeated batch pairings.
pub type ZkPreparedVerifyingKey = PreparedVerifyingKey<CurveEngine>;

/// User private master identity secret. Zeroized on drop for memory security.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecret {
    pub secret: ScalarField,
    pub salt: ScalarField,
}

impl IdentitySecret {
    pub fn new(secret: ScalarField, salt: ScalarField) -> Self {
        Self { secret, salt }
    }
}

/// Public commitment to an identity: C = Poseidon(secret, salt).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityCommitment(pub ScalarField);

/// Application-specific scope identifier (e.g. domain hash, app ID).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopeId(pub ScalarField);

/// Sybil-resistant, unlinkable nullifier derived for a scope: N = Poseidon(secret, scope).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub ScalarField);

/// Selective disclosure attributes container.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityAttributes {
    pub age: u64,
    pub credit_score: u64,
    pub country_code: u64,
    pub expiration_epoch: u64,
}

/// Verification threshold predicates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssertionPredicates {
    pub min_age: u64,
    pub min_credit_score: u64,
    pub allowed_country_mask: u64,
    pub current_epoch: u64,
}

/// Serialized proof container for transport over wire / WASM boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofEnvelope {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub circuit_type: String,
    pub created_at_unix: u64,
}
