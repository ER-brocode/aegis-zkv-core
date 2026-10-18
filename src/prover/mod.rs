//! SNARK Prover module with SIMD and multithreaded Rayon hardware acceleration.

pub mod batch;
pub mod hardware;
pub mod pipeline;

pub use batch::BatchProver;
pub use hardware::{HardwareAccelerator, HardwareCapabilities};
pub use pipeline::AegisProver;
