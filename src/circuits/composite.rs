//! Vault Composite Circuit combining Identity Verification, Range Assertions,
//! and Merkle Tree Membership in a single succinct zero-knowledge proof.

use crate::merkle::tree::MerkleProofGadget;
use crate::poseidon::gadget::PoseidonGadget;
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Unified Vault Circuit: Proves identity ownership, group membership, and attribute criteria.
#[derive(Clone, Debug)]
pub struct VaultCompositeCircuit<const DEPTH: usize> {
    // Private Witnesses
    pub secret_key: Option<Fr>,
    pub salt: Option<Fr>,
    pub age: Option<u64>,
    pub credit_score: Option<u64>,
    pub expiration_epoch: Option<u64>,
    pub path_elements: Option<[Fr; DEPTH]>,
    pub path_indices: Option<[bool; DEPTH]>,

    // Public Statements
    pub merkle_root: Option<Fr>,
    pub scope_id: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub min_age: Option<u64>,
    pub min_credit_score: Option<u64>,
    pub current_epoch: Option<u64>,
}

impl<const DEPTH: usize> Default for VaultCompositeCircuit<DEPTH> {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl<const DEPTH: usize> VaultCompositeCircuit<DEPTH> {
    pub fn new_empty() -> Self {
        Self {
            secret_key: None,
            salt: None,
            age: None,
            credit_score: None,
            expiration_epoch: None,
            path_elements: None,
            path_indices: None,
            merkle_root: None,
            scope_id: None,
            nullifier: None,
            min_age: None,
            min_credit_score: None,
            current_epoch: None,
        }
    }
}

impl<const DEPTH: usize> ConstraintSynthesizer<Fr> for VaultCompositeCircuit<DEPTH> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 1. Allocate Public Inputs
        let pub_merkle_root = FpVar::new_input(cs.clone(), || {
            self.merkle_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pub_scope_id = FpVar::new_input(cs.clone(), || {
            self.scope_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pub_nullifier = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pub_min_age = FpVar::new_input(cs.clone(), || {
            self.min_age
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pub_min_credit = FpVar::new_input(cs.clone(), || {
            self.min_credit_score
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pub_current_epoch = FpVar::new_input(cs.clone(), || {
            self.current_epoch
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. Allocate Private Identity Witnesses
        let priv_secret = FpVar::new_witness(cs.clone(), || {
            self.secret_key.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let priv_salt = FpVar::new_witness(cs.clone(), || {
            self.salt.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let priv_age = FpVar::new_witness(cs.clone(), || {
            self.age
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let priv_credit = FpVar::new_witness(cs.clone(), || {
            self.credit_score
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let priv_expiry = FpVar::new_witness(cs.clone(), || {
            self.expiration_epoch
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 3. Compute Commitment: Leaf = Poseidon(secret, salt)
        let identity_leaf = PoseidonGadget::hash_2(cs.clone(), &priv_secret, &priv_salt)?;

        // 4. Merkle Membership constraint: identity_leaf must be in pub_merkle_root
        let mut path_vars = Vec::with_capacity(DEPTH);
        let mut index_vars = Vec::with_capacity(DEPTH);
        for i in 0..DEPTH {
            let elem_val = self.path_elements.as_ref().map(|arr| arr[i]);
            path_vars.push(FpVar::new_witness(cs.clone(), || {
                elem_val.ok_or(SynthesisError::AssignmentMissing)
            })?);

            let idx_val = self.path_indices.as_ref().map(|arr| arr[i]);
            index_vars.push(Boolean::new_witness(cs.clone(), || {
                idx_val.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }

        let computed_root = MerkleProofGadget::verify_path::<DEPTH>(
            cs.clone(),
            &identity_leaf,
            &path_vars,
            &index_vars,
        )?;
        computed_root.enforce_equal(&pub_merkle_root)?;

        // 5. Scoped Nullifier constraint: nullifier = Poseidon(secret, scope_id)
        let computed_nullifier =
            PoseidonGadget::hash_2(cs.clone(), &priv_secret, &pub_scope_id)?;
        computed_nullifier.enforce_equal(&pub_nullifier)?;

        // 6. Range predicates (64-bit decomposition)
        let age_delta = &priv_age - &pub_min_age;
        let age_delta_bits = age_delta.to_bits_le()?;
        for bit in &age_delta_bits[64..] {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        let credit_delta = &priv_credit - &pub_min_credit;
        let credit_delta_bits = credit_delta.to_bits_le()?;
        for bit in &credit_delta_bits[64..] {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        let expiry_delta = &priv_expiry - &pub_current_epoch;
        let expiry_delta_bits = expiry_delta.to_bits_le()?;
        for bit in &expiry_delta_bits[64..] {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        Ok(())
    }
}
