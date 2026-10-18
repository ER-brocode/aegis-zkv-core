//! Core SNARK proof generation pipeline for identity and vault circuits.

use crate::circuits::{
    composite::VaultCompositeCircuit, identity::IdentityAssertionCircuit,
    membership::MembershipProofCircuit,
};
use crate::error::{Result, ZkvError};
use crate::types::{ZkProof, ZkProvingKey, ZkVerifyingKey};
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::rngs::OsRng;

/// High-performance SNARK Prover engine for Aegis ZKV.
pub struct AegisProver;

impl AegisProver {
    /// Performs one-time trusted setup for the Identity Assertion Circuit.
    pub fn setup_identity_circuit() -> Result<(ZkProvingKey, ZkVerifyingKey)> {
        let circuit = IdentityAssertionCircuit::new_empty();
        let mut rng = OsRng;
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ZkvError::ProofGenerationError(format!("Setup error: {:?}", e)))?;
        Ok((pk, vk))
    }

    /// Performs one-time trusted setup for the Membership Proof Circuit.
    pub fn setup_membership_circuit<const DEPTH: usize>() -> Result<(ZkProvingKey, ZkVerifyingKey)> {
        let circuit = MembershipProofCircuit::<DEPTH>::new_empty();
        let mut rng = OsRng;
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ZkvError::ProofGenerationError(format!("Membership setup error: {:?}", e)))?;
        Ok((pk, vk))
    }

    /// Performs one-time trusted setup for the Composite Vault Circuit.
    pub fn setup_composite_circuit<const DEPTH: usize>() -> Result<(ZkProvingKey, ZkVerifyingKey)> {
        let circuit = VaultCompositeCircuit::<DEPTH>::new_empty();
        let mut rng = OsRng;
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ZkvError::ProofGenerationError(format!("Composite setup error: {:?}", e)))?;
        Ok((pk, vk))
    }

    /// Generates a Zero-Knowledge Proof for the Identity Assertion Circuit.
    pub fn prove_identity(
        pk: &ZkProvingKey,
        circuit: IdentityAssertionCircuit,
    ) -> Result<ZkProof> {
        let mut rng = OsRng;
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| ZkvError::ProofGenerationError(format!("Proving error: {:?}", e)))?;
        Ok(proof)
    }

    /// Generates a Zero-Knowledge Proof for the Membership Circuit.
    pub fn prove_membership<const DEPTH: usize>(
        pk: &ZkProvingKey,
        circuit: MembershipProofCircuit<DEPTH>,
    ) -> Result<ZkProof> {
        let mut rng = OsRng;
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| ZkvError::ProofGenerationError(format!("Membership proving error: {:?}", e)))?;
        Ok(proof)
    }

    /// Generates a Zero-Knowledge Proof for the Composite Vault Circuit.
    pub fn prove_composite<const DEPTH: usize>(
        pk: &ZkProvingKey,
        circuit: VaultCompositeCircuit<DEPTH>,
    ) -> Result<ZkProof> {
        let mut rng = OsRng;
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| ZkvError::ProofGenerationError(format!("Composite proving error: {:?}", e)))?;
        Ok(proof)
    }
}
