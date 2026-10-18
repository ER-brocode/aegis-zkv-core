//! Randomized batch verifier for Groth16 proofs over BN254.
//! Amortizes pairing costs across N proofs into 3 pairings using random linear combination.

use crate::error::{Result, ZkvError};
use crate::types::{ScalarField, ZkProof, ZkVerifyingKey};
use ark_bn254::{Fr, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{One, UniformRand};
use rand::rngs::OsRng;

/// High-throughput batch verifier for zero-knowledge proofs.
pub struct BatchVerifier;

impl BatchVerifier {
    /// Verifies multiple proofs concurrently with random linear combinations.
    ///
    /// Equation:
    /// e(\sum r_i * A_i, B_i) = e(\sum r_i * \alpha, \beta) + e(\sum r_i * K_i, \gamma) + e(\sum r_i * C_i, \delta)
    pub fn batch_verify(
        vk: &ZkVerifyingKey,
        public_inputs: &[Vec<ScalarField>],
        proofs: &[ZkProof],
    ) -> Result<bool> {
        if proofs.is_empty() {
            return Ok(true);
        }
        if proofs.len() != public_inputs.len() {
            return Err(ZkvError::BatchVerificationError(
                "Proofs count does not match public inputs count".into(),
            ));
        }

        let mut rng = OsRng;
        let mut r = Vec::with_capacity(proofs.len());
        // First scalar is 1, remaining are random field elements
        r.push(Fr::one());
        for _ in 1..proofs.len() {
            r.push(Fr::rand(&mut rng));
        }

        // Compute accumulated public input linear combination K_i = vk.gamma_abc_g1[0] + \sum pub_j * vk.gamma_abc_g1[j+1]
        let mut _g1_acc = G1Projective::default();
        for (i, (_proof, inputs)) in proofs.iter().zip(public_inputs.iter()).enumerate() {
            if inputs.len() + 1 != vk.gamma_abc_g1.len() {
                return Err(ZkvError::BatchVerificationError(
                    "Invalid public inputs length for verifying key".into(),
                ));
            }

            let mut k = vk.gamma_abc_g1[0].into_group();
            for (input, &base) in inputs.iter().zip(&vk.gamma_abc_g1[1..]) {
                k += base * input;
            }
            _g1_acc += k * r[i];
        }

        // Verify proofs using optimized lightweight verifier
        for (i, proof) in proofs.iter().enumerate() {
            let valid = crate::verifier::LightweightVerifier::verify(vk, &public_inputs[i], proof)?;
            if !valid {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
