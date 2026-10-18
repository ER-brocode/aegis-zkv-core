//! WebAssembly bindings for Aegis ZKV in browser and edge environments.

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::poseidon::poseidon_hash_2;
use crate::types::{ScalarField, ZkProof, ZkVerifyingKey};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;

#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
pub fn init_wasm() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Computes Poseidon 2-to-1 hash on two hex-encoded field elements.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn wasm_poseidon_hash(left_hex: &str, right_hex: &str) -> std::result::Result<String, String> {
    let left_clean = left_hex.trim_start_matches("0x");
    let right_clean = right_hex.trim_start_matches("0x");

    let left_bytes = hex::decode(left_clean).map_err(|e| format!("Invalid left hex: {}", e))?;
    let right_bytes = hex::decode(right_clean).map_err(|e| format!("Invalid right hex: {}", e))?;

    let left = Fr::from_le_bytes_mod_order(&left_bytes);
    let right = Fr::from_le_bytes_mod_order(&right_bytes);

    let result = poseidon_hash_2(left, right);
    let mut out_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&result, &mut out_bytes)
        .map_err(|e| format!("Serialization error: {}", e))?;

    Ok(hex::encode(out_bytes))
}

/// Generates an identity commitment: Poseidon(secret, salt).
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn wasm_generate_identity_commitment(
    secret_hex: &str,
    salt_hex: &str,
) -> std::result::Result<String, String> {
    wasm_poseidon_hash(secret_hex, salt_hex)
}

/// Generates an unlinkable nullifier: Poseidon(secret, scope_id).
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn wasm_generate_nullifier(
    secret_hex: &str,
    scope_hex: &str,
) -> std::result::Result<String, String> {
    wasm_poseidon_hash(secret_hex, scope_hex)
}

/// Verifies a Groth16 proof from byte buffers in WASM.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn wasm_verify_proof(
    vk_bytes: &[u8],
    public_inputs_bytes: &[u8],
    proof_bytes: &[u8],
) -> std::result::Result<bool, String> {
    let vk = ZkVerifyingKey::deserialize_compressed(vk_bytes)
        .map_err(|e| format!("Failed to deserialize VK: {}", e))?;
    let proof = ZkProof::deserialize_compressed(proof_bytes)
        .map_err(|e| format!("Failed to deserialize Proof: {}", e))?;
    let inputs: Vec<ScalarField> = Vec::<ScalarField>::deserialize_compressed(public_inputs_bytes)
        .map_err(|e| format!("Failed to deserialize inputs: {}", e))?;

    crate::verifier::LightweightVerifier::verify(&vk, &inputs, &proof)
        .map_err(|e| format!("Verification failed: {}", e))
}
