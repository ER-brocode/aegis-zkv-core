//! # Aegis ZKV Core
//!
//! **Hardware-Accelerated Zero-Knowledge Proof Identity Vault in Rust/WASM**
//!
//! Aegis ZKV is a production-grade cryptographic vault providing privacy-preserving
//! digital identity assertion, anonymous group membership verification, and selective
//! attribute disclosure using Groth16 zero-knowledge SNARKs over the BN254 elliptic curve.
//!
//! ## Architecture Highlights
//! - **Cryptographic Primitives**: Groth16 SNARKs, Poseidon algebraic sponge hash over BN254 Fr.
//! - **Circuits**: Selective disclosure identity assertion, sparse/binary Merkle membership proofs, and unified composite vaults.
//! - **Hardware Acceleration**: Rayon-multithreaded multi-scalar multiplication (MSM) and SIMD vectorization.
//! - **Zero-Memory Leakage**: Secrets zeroized immediately on drop with `zeroize`.
//! - **WASM & Browser Native**: Ultra-lightweight verifier compiled to WebAssembly for sub-10ms in-browser proofs.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod circuits;
pub mod error;
pub mod merkle;
pub mod poseidon;
pub mod prover;
pub mod types;
pub mod verifier;
pub mod wasm;

pub use circuits::{IdentityAssertionCircuit, MembershipProofCircuit, VaultCompositeCircuit};
pub use error::{Result, ZkvError};
pub use merkle::{MerkleProof, MerkleProofGadget, MerkleTree};
pub use poseidon::{poseidon_hash_2, PoseidonNative};
pub use prover::{AegisProver, BatchProver, HardwareAccelerator};
pub use types::{
    AssertionPredicates, CurveEngine, IdentityAttributes, IdentityCommitment, IdentitySecret,
    Nullifier, ScalarField, ScopeId, ZkPreparedVerifyingKey, ZkProof, ZkProvingKey, ZkVerifyingKey,
};
pub use verifier::{BatchVerifier, LightweightVerifier};
