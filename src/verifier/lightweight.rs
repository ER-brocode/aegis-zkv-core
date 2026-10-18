//! Fast, lightweight Groth16 verifier with minimal memory overhead.

use crate::error::{Result, ZkvError};
use crate::types::{ScalarField, ZkPreparedVerifyingKey, ZkProof, ZkVerifyingKey};
use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey};
use ark_snark::SNARK;

/// Minimal-footprint verifier suitable for WebAssembly, mobile, and smart-contract verification.
pub struct LightweightVerifier;

impl LightweightVerifier {
    /// Verifies a Groth16 proof using standard verifying key.
    pub fn verify(
        vk: &ZkVerifyingKey,
        public_inputs: &[ScalarField],
        proof: &ZkProof,
    ) -> Result<bool> {
        let is_valid = Groth16::<Bn254>::verify(vk, public_inputs, proof)
            .map_err(|e| ZkvError::VerificationError(format!("Verification execution error: {:?}", e)))?;
        Ok(is_valid)
    }

    /// Verifies a Groth16 proof with pre-computed pairings via `PreparedVerifyingKey`.
    /// Significantly reduces pairing operations on repeated calls.
    pub fn verify_prepared(
        pvk: &ZkPreparedVerifyingKey,
        public_inputs: &[ScalarField],
        proof: &ZkProof,
    ) -> Result<bool> {
        let is_valid = Groth16::<Bn254>::verify_with_processed_vk(pvk, public_inputs, proof)
            .map_err(|e| ZkvError::VerificationError(format!("Prepared verification error: {:?}", e)))?;
        Ok(is_valid)
    }

    /// Prepares a verifying key for fast verification.
    pub fn prepare_vk(vk: &ZkVerifyingKey) -> ZkPreparedVerifyingKey {
        PreparedVerifyingKey::from(vk.clone())
    }
}
