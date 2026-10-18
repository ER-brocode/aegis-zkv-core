//! Batch proof generation orchestrator for parallel identity issuance.

use crate::circuits::identity::IdentityAssertionCircuit;
use crate::error::Result;
use crate::prover::pipeline::AegisProver;
use crate::types::{ZkProof, ZkProvingKey};

/// Batch prover leveraging multithreading for concurrent proof creation.
pub struct BatchProver;

impl BatchProver {
    /// Generates proofs for multiple identity assertion instances in parallel.
    pub fn prove_identity_batch(
        pk: &ZkProvingKey,
        circuits: Vec<IdentityAssertionCircuit>,
    ) -> Result<Vec<ZkProof>> {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            circuits
                .into_par_iter()
                .map(|circuit| AegisProver::prove_identity(pk, circuit))
                .collect()
        }

        #[cfg(not(feature = "parallel"))]
        {
            circuits
                .into_iter()
                .map(|circuit| AegisProver::prove_identity(pk, circuit))
                .collect()
        }
    }
}
