//! Native Poseidon hash implementation over BN254 scalar field.

pub mod constants;
pub mod gadget;

use ark_bn254::Fr;
use ark_ff::Field;
use constants::{generate_mds_matrix, generate_round_constants, ROUNDS_FULL, ROUNDS_PARTIAL, STATE_WIDTH};

/// Native Poseidon sponge instance for fast CPU hashing.
pub struct PoseidonNative {
    round_constants: Vec<[Fr; STATE_WIDTH]>,
    mds_matrix: [[Fr; STATE_WIDTH]; STATE_WIDTH],
}

impl Default for PoseidonNative {
    fn default() -> Self {
        Self::new()
    }
}

impl PoseidonNative {
    pub fn new() -> Self {
        Self {
            round_constants: generate_round_constants(),
            mds_matrix: generate_mds_matrix(),
        }
    }

    /// Evaluates the quintic S-box: x -> x^5.
    #[inline(always)]
    fn sbox(x: Fr) -> Fr {
        let x2 = x.square();
        let x4 = x2.square();
        x4 * x
    }

    /// Linear layer: multiplies state vector by MDS matrix.
    fn apply_mds(&self, state: &mut [Fr; STATE_WIDTH]) {
        let mut new_state = [Fr::from(0u64); STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                new_state[i] += self.mds_matrix[i][j] * state[j];
            }
        }
        *state = new_state;
    }

    /// Permutes the 3-element state.
    pub fn permute(&self, state: &mut [Fr; STATE_WIDTH]) {
        let half_full = ROUNDS_FULL / 2;

        // First half of full rounds
        for r in 0..half_full {
            for i in 0..STATE_WIDTH {
                state[i] += self.round_constants[r][i];
                state[i] = Self::sbox(state[i]);
            }
            self.apply_mds(state);
        }

        // Partial rounds: S-box applied only to state[0]
        for r in half_full..(half_full + ROUNDS_PARTIAL) {
            for i in 0..STATE_WIDTH {
                state[i] += self.round_constants[r][i];
            }
            state[0] = Self::sbox(state[0]);
            self.apply_mds(state);
        }

        // Second half of full rounds
        for r in (half_full + ROUNDS_PARTIAL)..(ROUNDS_FULL + ROUNDS_PARTIAL) {
            for i in 0..STATE_WIDTH {
                state[i] += self.round_constants[r][i];
                state[i] = Self::sbox(state[i]);
            }
            self.apply_mds(state);
        }
    }

    /// Hashes two BN254 scalar field elements into one.
    pub fn hash_2(&self, left: Fr, right: Fr) -> Fr {
        let mut state = [Fr::from(0u64), left, right];
        self.permute(&mut state);
        state[0]
    }

    /// Hashes a slice of scalar field elements sequentially.
    pub fn hash_many(&self, inputs: &[Fr]) -> Fr {
        if inputs.is_empty() {
            return Fr::from(0u64);
        }
        if inputs.len() == 1 {
            return inputs[0];
        }
        let mut acc = inputs[0];
        for &item in &inputs[1..] {
            acc = self.hash_2(acc, item);
        }
        acc
    }
}

/// Convenience function for 2-to-1 Poseidon hashing.
pub fn poseidon_hash_2(left: Fr, right: Fr) -> Fr {
    let hasher = PoseidonNative::new();
    hasher.hash_2(left, right)
}
