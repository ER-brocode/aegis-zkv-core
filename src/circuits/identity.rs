//! Identity Assertion Circuit for selective disclosure and privacy-preserving credential verification.

use crate::poseidon::gadget::PoseidonGadget;
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Circuit proving knowledge of identity credentials satisfying assertion predicates
/// without revealing the private identity attributes or master secret.
#[derive(Clone, Debug)]
pub struct IdentityAssertionCircuit {
    // Private Witness Inputs
    pub secret_key: Option<Fr>,
    pub salt: Option<Fr>,
    pub age: Option<u64>,
    pub credit_score: Option<u64>,
    pub expiration_epoch: Option<u64>,

    // Public Statement Inputs
    pub identity_commitment: Option<Fr>,
    pub scope_id: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub min_age: Option<u64>,
    pub min_credit_score: Option<u64>,
    pub current_epoch: Option<u64>,
}

impl Default for IdentityAssertionCircuit {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl IdentityAssertionCircuit {
    pub fn new_empty() -> Self {
        Self {
            secret_key: None,
            salt: None,
            age: None,
            credit_score: None,
            expiration_epoch: None,
            identity_commitment: None,
            scope_id: None,
            nullifier: None,
            min_age: None,
            min_credit_score: None,
            current_epoch: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for IdentityAssertionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 1. Allocate Public Inputs
        let pub_commitment = FpVar::new_input(cs.clone(), || {
            self.identity_commitment.ok_or(SynthesisError::AssignmentMissing)
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

        // 2. Allocate Private Witness Variables
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

        // 3. Constrain Identity Commitment: Poseidon(secret, salt) == pub_commitment
        let computed_commitment =
            PoseidonGadget::hash_2(cs.clone(), &priv_secret, &priv_salt)?;
        computed_commitment.enforce_equal(&pub_commitment)?;

        // 4. Constrain Scoped Nullifier: Poseidon(secret, scope_id) == pub_nullifier
        let computed_nullifier =
            PoseidonGadget::hash_2(cs.clone(), &priv_secret, &pub_scope_id)?;
        computed_nullifier.enforce_equal(&pub_nullifier)?;

        // 5. Constrain Range Predicate: age >= min_age
        let age_delta = &priv_age - &pub_min_age;
        let age_delta_bits = age_delta.to_bits_le()?;
        for bit in &age_delta_bits[64..] {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        // 6. Constrain Range Predicate: credit_score >= min_credit_score
        let credit_delta = &priv_credit - &pub_min_credit;
        let credit_delta_bits = credit_delta.to_bits_le()?;
        for bit in &credit_delta_bits[64..] {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        // 7. Constrain Validity Expiration: expiration_epoch >= current_epoch
        let expiry_delta = &priv_expiry - &pub_current_epoch;
        let expiry_delta_bits = expiry_delta.to_bits_le()?;
        for bit in &expiry_delta_bits[64..] {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        Ok(())
    }
}
