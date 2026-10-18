//! R1CS circuit gadget for Poseidon hash over BN254 Fr.

use super::constants::{generate_mds_matrix, generate_round_constants, ROUNDS_FULL, ROUNDS_PARTIAL, STATE_WIDTH};
use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// R1CS Poseidon Gadget matching native computation bit-for-bit.
pub struct PoseidonGadget;

impl PoseidonGadget {
    /// Quintic S-box in R1CS: computes x^5 with 3 constraints.
    /// c1 = x * x (x^2)
    /// c2 = c1 * c1 (x^4)
    /// c3 = c2 * x (x^5)
    fn sbox_gadget(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        let x2 = x.square()?;
        let x4 = x2.square()?;
        x4.mul(x)
    }

    /// Linear MDS layer for circuit state variables.
    fn apply_mds(
        state: &[FpVar<Fr>; STATE_WIDTH],
        mds: &[[Fr; STATE_WIDTH]; STATE_WIDTH],
    ) -> Result<[FpVar<Fr>; STATE_WIDTH], SynthesisError> {
        let mut new_state = state.clone();
        for i in 0..STATE_WIDTH {
            let mut acc = state[0].mul_by_constant(mds[i][0])?;
            for j in 1..STATE_WIDTH {
                let term = state[j].mul_by_constant(mds[i][j])?;
                acc = acc.add(&term);
            }
            new_state[i] = acc;
        }
        Ok(new_state)
    }

    /// R1CS permutation matching `PoseidonNative::permute`.
    pub fn permute_gadget(
        _cs: ConstraintSystemRef<Fr>,
        mut state: [FpVar<Fr>; STATE_WIDTH],
    ) -> Result<[FpVar<Fr>; STATE_WIDTH], SynthesisError> {
        let round_constants = generate_round_constants();
        let mds = generate_mds_matrix();
        let half_full = ROUNDS_FULL / 2;

        // First half full rounds
        for r in 0..half_full {
            for i in 0..STATE_WIDTH {
                let rc = round_constants[r][i];
                let elem = state[i].add_constant(rc)?;
                state[i] = Self::sbox_gadget(&elem)?;
            }
            state = Self::apply_mds(&state, &mds)?;
        }

        // Partial rounds
        for r in half_full..(half_full + ROUNDS_PARTIAL) {
            for i in 0..STATE_WIDTH {
                let rc = round_constants[r][i];
                state[i] = state[i].add_constant(rc)?;
            }
            state[0] = Self::sbox_gadget(&state[0])?;
            state = Self::apply_mds(&state, &mds)?;
        }

        // Second half full rounds
        for r in (half_full + ROUNDS_PARTIAL)..(ROUNDS_FULL + ROUNDS_PARTIAL) {
            for i in 0..STATE_WIDTH {
                let rc = round_constants[r][i];
                let elem = state[i].add_constant(rc)?;
                state[i] = Self::sbox_gadget(&elem)?;
            }
            state = Self::apply_mds(&state, &mds)?;
        }

        Ok(state)
    }

    /// Hashes two circuit variables: returns output variable.
    pub fn hash_2(
        cs: ConstraintSystemRef<Fr>,
        left: &FpVar<Fr>,
        right: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let zero = FpVar::constant(Fr::from(0u64));
        let state = [zero, left.clone(), right.clone()];
        let out_state = Self::permute_gadget(cs, state)?;
        Ok(out_state[0].clone())
    }
}
