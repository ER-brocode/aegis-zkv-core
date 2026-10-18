//! Sparse and binary Merkle tree primitives backed by Poseidon hash.

pub mod tree;

pub use tree::{MerkleProof, MerkleProofGadget, MerkleTree};
