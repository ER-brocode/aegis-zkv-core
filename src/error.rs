//! Error definitions for the Aegis ZKV Core identity vault.

use thiserror::Error;

/// Core error enumeration representing all failure modes in Aegis ZKV.
#[derive(Error, Debug)]
pub enum ZkvError {
    #[error("Circuit synthesis error: {0}")]
    CircuitSynthesisError(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),

    #[error("Proof verification failed: {0}")]
    VerificationError(String),

    #[error("Batch verification failed: {0}")]
    BatchVerificationError(String),

    #[error("Serialization/deserialization error: {0}")]
    SerializationError(String),

    #[error("Merkle tree error: {0}")]
    MerkleTreeError(String),

    #[error("Invalid witness provided: {0}")]
    InvalidWitness(String),

    #[error("Constraint system is unsatisfied")]
    ConstraintSystemUnsatisfied,

    #[error("Hardware acceleration error: {0}")]
    HardwareAccelerationError(String),

    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("Arkworks serialization error: {0}")]
    ArkSerializationError(#[from] ark_serialize::SerializationError),
}

/// Convenience alias for `Result<T, ZkvError>`.
pub type Result<T> = std::result::Result<T, ZkvError>;
