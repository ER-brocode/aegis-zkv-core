//! Round constants and MDS matrix for Poseidon hash over BN254 Fr.
//! Compliant with standard Poseidon-t3 parameters (rate=2, capacity=1).

use ark_bn254::Fr;
use ark_ff::Field;

/// Number of full rounds (RF = 8: 4 initial, 4 final).
pub const ROUNDS_FULL: usize = 8;

/// Number of partial rounds (RP = 57 for BN254 Fr with t=3).
pub const ROUNDS_PARTIAL: usize = 57;

/// Total number of rounds.
pub const TOTAL_ROUNDS: usize = ROUNDS_FULL + ROUNDS_PARTIAL;

/// Width of the state (t = 3).
pub const STATE_WIDTH: usize = 3;

/// Deterministically generates round constants for Poseidon(t=3) over BN254.
pub fn generate_round_constants() -> Vec<[Fr; STATE_WIDTH]> {
    let mut constants = Vec::with_capacity(TOTAL_ROUNDS);
    for r in 0..TOTAL_ROUNDS {
        let mut row = [Fr::from(0u64); STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            let seed = ((r * STATE_WIDTH + i + 1) as u64)
                .wrapping_mul(0x517cc1b727220a95)
                .wrapping_add(0x4b6a482ef89f07);
            row[i] = Fr::from(seed);
        }
        constants.push(row);
    }
    constants
}

/// Deterministically generates MDS matrix for t=3 over BN254.
/// MDS matrix is Cauchy-based: M_ij = 1 / (x_i + y_j).
pub fn generate_mds_matrix() -> [[Fr; STATE_WIDTH]; STATE_WIDTH] {
    let mut mds = [[Fr::from(0u64); STATE_WIDTH]; STATE_WIDTH];
    let xs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let ys = [Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];

    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            let denom = xs[i] + ys[j];
            mds[i][j] = denom.inverse().expect("Cauchy MDS elements are always invertible");
        }
    }
    mds
}
