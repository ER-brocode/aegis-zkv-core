use aegis_zkv_core::circuits::IdentityAssertionCircuit;
use aegis_zkv_core::poseidon::poseidon_hash_2;
use aegis_zkv_core::prover::AegisProver;
use aegis_zkv_core::verifier::LightweightVerifier;
use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

#[test]
fn test_identity_assertion_valid_proof() {
    let mut rng = OsRng;

    // Generate credentials
    let secret_key = Fr::rand(&mut rng);
    let salt = Fr::rand(&mut rng);
    let scope_id = Fr::rand(&mut rng);

    let identity_commitment = poseidon_hash_2(secret_key, salt);
    let nullifier = poseidon_hash_2(secret_key, scope_id);

    let age = 25u64;
    let min_age = 18u64;
    let credit_score = 750u64;
    let min_credit_score = 650u64;
    let expiration_epoch = 1800000000u64;
    let current_epoch = 1700000000u64;

    // Perform one-time setup
    let (pk, vk) = AegisProver::setup_identity_circuit().expect("Setup failed");

    // Construct witness circuit
    let circuit = IdentityAssertionCircuit {
        secret_key: Some(secret_key),
        salt: Some(salt),
        age: Some(age),
        credit_score: Some(credit_score),
        expiration_epoch: Some(expiration_epoch),
        identity_commitment: Some(identity_commitment),
        scope_id: Some(scope_id),
        nullifier: Some(nullifier),
        min_age: Some(min_age),
        min_credit_score: Some(min_credit_score),
        current_epoch: Some(current_epoch),
    };

    // Generate proof
    let proof = AegisProver::prove_identity(&pk, circuit).expect("Proving failed");

    // Public inputs vector matching constraint order:
    // [pub_commitment, pub_scope_id, pub_nullifier, pub_min_age, pub_min_credit, pub_current_epoch]
    let public_inputs = vec![
        identity_commitment,
        scope_id,
        nullifier,
        Fr::from(min_age),
        Fr::from(min_credit_score),
        Fr::from(current_epoch),
    ];

    // Verify proof
    let is_valid = LightweightVerifier::verify(&vk, &public_inputs, &proof).expect("Verification failed");
    assert!(is_valid, "Identity proof must be valid");
}

#[test]
fn test_identity_assertion_invalid_tampered_input() {
    let mut rng = OsRng;

    let secret_key = Fr::rand(&mut rng);
    let salt = Fr::rand(&mut rng);
    let scope_id = Fr::rand(&mut rng);

    let identity_commitment = poseidon_hash_2(secret_key, salt);
    let nullifier = poseidon_hash_2(secret_key, scope_id);

    let (pk, vk) = AegisProver::setup_identity_circuit().expect("Setup failed");

    let circuit = IdentityAssertionCircuit {
        secret_key: Some(secret_key),
        salt: Some(salt),
        age: Some(30),
        credit_score: Some(800),
        expiration_epoch: Some(2000000000),
        identity_commitment: Some(identity_commitment),
        scope_id: Some(scope_id),
        nullifier: Some(nullifier),
        min_age: Some(21),
        min_credit_score: Some(700),
        current_epoch: Some(1900000000),
    };

    let proof = AegisProver::prove_identity(&pk, circuit).expect("Proving failed");

    // Tamper with public input: change min_age from 21 to 50
    let tampered_inputs = vec![
        identity_commitment,
        scope_id,
        nullifier,
        Fr::from(50u64), // Tampered!
        Fr::from(700u64),
        Fr::from(1900000000u64),
    ];

    let is_valid = LightweightVerifier::verify(&vk, &tampered_inputs, &proof).expect("Verification failed");
    assert!(!is_valid, "Tampered proof must be rejected");
}
