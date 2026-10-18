use aegis_zkv_core::circuits::IdentityAssertionCircuit;
use aegis_zkv_core::poseidon::poseidon_hash_2;
use aegis_zkv_core::prover::AegisProver;
use aegis_zkv_core::verifier::BatchVerifier;
use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

#[test]
fn test_batch_verification_multiple_proofs() {
    let mut rng = OsRng;
    let (pk, vk) = AegisProver::setup_identity_circuit().expect("Setup failed");

    let mut proofs = Vec::new();
    let mut all_public_inputs = Vec::new();

    // Generate 3 distinct valid proofs
    for i in 0..3 {
        let secret_key = Fr::rand(&mut rng);
        let salt = Fr::rand(&mut rng);
        let scope_id = Fr::rand(&mut rng);

        let commitment = poseidon_hash_2(secret_key, salt);
        let nullifier = poseidon_hash_2(secret_key, scope_id);

        let circuit = IdentityAssertionCircuit {
            secret_key: Some(secret_key),
            salt: Some(salt),
            age: Some(25 + i as u64),
            credit_score: Some(700 + i as u64 * 10),
            expiration_epoch: Some(2000000000),
            identity_commitment: Some(commitment),
            scope_id: Some(scope_id),
            nullifier: Some(nullifier),
            min_age: Some(18),
            min_credit_score: Some(600),
            current_epoch: Some(1700000000),
        };

        let proof = AegisProver::prove_identity(&pk, circuit).expect("Proving failed");
        let inputs = vec![
            commitment,
            scope_id,
            nullifier,
            Fr::from(18u64),
            Fr::from(600u64),
            Fr::from(1700000000u64),
        ];

        proofs.push(proof);
        all_public_inputs.push(inputs);
    }

    let batch_valid = BatchVerifier::batch_verify(&vk, &all_public_inputs, &proofs)
        .expect("Batch verification error");
    assert!(batch_valid, "All batched proofs should verify simultaneously");
}
