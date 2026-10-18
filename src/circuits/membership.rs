//! Membership Proof Circuit for Zero-Knowledge group inclusion verification.

use crate::merkle::tree::MerkleProofGadget;
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Circuit proving membership of a private leaf in a Merkle tree with public root.
#[derive(Clone, Debug)]
pub struct MembershipProofCircuit<const DEPTH: usize> {
    // Private witness
    pub leaf: Option<Fr>,
    pub path_elements: Option<[Fr; DEPTH]>,
    pub path_indices: Option<[bool; DEPTH]>,

    // Public input
    pub root: Option<Fr>,
}

impl<const DEPTH: usize> Default for MembershipProofCircuit<DEPTH> {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl<const DEPTH: usize> MembershipProofCircuit<DEPTH> {
    pub fn new_empty() -> Self {
        Self {
            leaf: None,
            path_elements: None,
            path_indices: None,
            root: None,
        }
    }
}

impl<const DEPTH: usize> ConstraintSynthesizer<Fr> for MembershipProofCircuit<DEPTH> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public Root
        let pub_root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Private Leaf
        let priv_leaf = FpVar::new_witness(cs.clone(), || {
            self.leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Private Path Elements and Direction Indices
        let mut path_vars = Vec::with_capacity(DEPTH);
        let mut index_vars = Vec::with_capacity(DEPTH);

        for i in 0..DEPTH {
            let elem_val = self.path_elements.as_ref().map(|arr| arr[i]);
            let path_var = FpVar::new_witness(cs.clone(), || {
                elem_val.ok_or(SynthesisError::AssignmentMissing)
            })?;
            path_vars.push(path_var);

            let idx_val = self.path_indices.as_ref().map(|arr| arr[i]);
            let idx_var = Boolean::new_witness(cs.clone(), || {
                idx_val.ok_or(SynthesisError::AssignmentMissing)
            })?;
            index_vars.push(idx_var);
        }

        // Compute Merkle root along the authentication path
        let computed_root = MerkleProofGadget::verify_path::<DEPTH>(
            cs.clone(),
            &priv_leaf,
            &path_vars,
            &index_vars,
        )?;

        // Enforce computed root == public root
        computed_root.enforce_equal(&pub_root)?;

        Ok(())
    }
}
