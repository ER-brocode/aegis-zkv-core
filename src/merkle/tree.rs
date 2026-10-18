//! Binary Merkle Tree implementation with Poseidon hashing and R1CS verification gadget.

use crate::error::{Result, ZkvError};
use crate::poseidon::{gadget::PoseidonGadget, poseidon_hash_2};
use ark_bn254::Fr;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use serde::{Deserialize, Serialize};

/// Merkle authentication path proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof<const DEPTH: usize> {
    pub leaf_index: usize,
    pub path_elements: [Fr; DEPTH],
    pub path_indices: [bool; DEPTH],
}

/// Binary Merkle Tree with fixed depth using Poseidon hash.
#[derive(Clone, Debug)]
pub struct MerkleTree<const DEPTH: usize> {
    pub zero_values: [Fr; DEPTH],
    pub leaves: Vec<Fr>,
    pub root: Fr,
}

impl<const DEPTH: usize> Default for MerkleTree<DEPTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize> MerkleTree<DEPTH> {
    /// Creates a new empty Merkle Tree of fixed depth.
    pub fn new() -> Self {
        let mut zero_values = [Fr::from(0u64); DEPTH];
        let mut current_zero = Fr::from(0u64);
        for i in 0..DEPTH {
            zero_values[i] = current_zero;
            current_zero = poseidon_hash_2(current_zero, current_zero);
        }

        Self {
            zero_values,
            leaves: Vec::new(),
            root: current_zero,
        }
    }

    /// Inserts a leaf into the tree and recomputes root.
    pub fn insert(&mut self, leaf: Fr) -> usize {
        let index = self.leaves.len();
        self.leaves.push(leaf);
        self.recompute_root();
        index
    }

    /// Recomputes the Merkle root from current leaves.
    pub fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            let mut curr = Fr::from(0u64);
            for _ in 0..DEPTH {
                curr = poseidon_hash_2(curr, curr);
            }
            self.root = curr;
            return;
        }

        let mut current_level = self.leaves.clone();
        for d in 0..DEPTH {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 {
                    chunk[1]
                } else {
                    self.zero_values[d]
                };
                next_level.push(poseidon_hash_2(left, right));
            }
            current_level = next_level;
        }
        self.root = current_level[0];
    }

    /// Generates an authentication proof for a given leaf index.
    pub fn generate_proof(&self, leaf_index: usize) -> Result<MerkleProof<DEPTH>> {
        if leaf_index >= self.leaves.len() {
            return Err(ZkvError::MerkleTreeError("Leaf index out of bounds".into()));
        }

        let mut path_elements = [Fr::from(0u64); DEPTH];
        let mut path_indices = [false; DEPTH];
        let mut current_level = self.leaves.clone();
        let mut idx = leaf_index;

        for d in 0..DEPTH {
            let is_right = (idx % 2) == 1;
            path_indices[d] = is_right;

            let sibling = if is_right {
                current_level[idx - 1]
            } else if idx + 1 < current_level.len() {
                current_level[idx + 1]
            } else {
                self.zero_values[d]
            };
            path_elements[d] = sibling;

            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 {
                    chunk[1]
                } else {
                    self.zero_values[d]
                };
                next_level.push(poseidon_hash_2(left, right));
            }
            current_level = next_level;
            idx /= 2;
        }

        Ok(MerkleProof {
            leaf_index,
            path_elements,
            path_indices,
        })
    }

    /// Verifies a Merkle proof natively.
    pub fn verify_proof(root: Fr, leaf: Fr, proof: &MerkleProof<DEPTH>) -> bool {
        let mut current = leaf;
        for i in 0..DEPTH {
            let (left, right) = if proof.path_indices[i] {
                (proof.path_elements[i], current)
            } else {
                (current, proof.path_elements[i])
            };
            current = poseidon_hash_2(left, right);
        }
        current == root
    }
}

/// Merkle authentication path verification gadget for R1CS.
pub struct MerkleProofGadget;

impl MerkleProofGadget {
    /// Constrains the calculation of the Merkle root from leaf and path variables.
    pub fn verify_path<const DEPTH: usize>(
        cs: ConstraintSystemRef<Fr>,
        leaf_var: &FpVar<Fr>,
        path_elements_vars: &[FpVar<Fr>],
        path_indices_vars: &[Boolean<Fr>],
    ) -> std::result::Result<FpVar<Fr>, SynthesisError> {
        assert_eq!(path_elements_vars.len(), DEPTH);
        assert_eq!(path_indices_vars.len(), DEPTH);

        let mut current = leaf_var.clone();
        for i in 0..DEPTH {
            let is_right = &path_indices_vars[i];
            let sibling = &path_elements_vars[i];

            // If is_right == true: left = sibling, right = current
            // If is_right == false: left = current, right = sibling
            let left = FpVar::conditionally_select(is_right, sibling, &current)?;
            let right = FpVar::conditionally_select(is_right, &current, sibling)?;

            current = PoseidonGadget::hash_2(cs.clone(), &left, &right)?;
        }
        Ok(current)
    }
}
