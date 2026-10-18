//! Lightweight SNARK verifier optimized for browser/WASM and batch verification.

pub mod batch;
pub mod lightweight;

pub use batch::BatchVerifier;
pub use lightweight::LightweightVerifier;
