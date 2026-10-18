use aegis_zkv_core::circuits::IdentityAssertionCircuit;
use aegis_zkv_core::poseidon::poseidon_hash_2;
use aegis_zkv_core::prover::AegisProver;
use aegis_zkv_core::verifier::LightweightVerifier;
use ark_bn254::Fr;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

fn bench_poseidon_native(c: &mut Criterion) {
    let mut rng = OsRng;
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);

    c.bench_function("poseidon_hash_2_native", |bencher| {
        bencher.iter(|| poseidon_hash_2(a, b))
    });
}

fn bench_groth16_identity(c: &mut Criterion) {
    let mut rng = OsRng;
    let (pk, vk) = AegisProver::setup_identity_circuit().unwrap();

    let secret_key = Fr::rand(&mut rng);
    let salt = Fr::rand(&mut rng);
    let scope_id = Fr::rand(&mut rng);
    let commitment = poseidon_hash_2(secret_key, salt);
    let nullifier = poseidon_hash_2(secret_key, scope_id);

    let circuit_fn = || IdentityAssertionCircuit {
        secret_key: Some(secret_key),
        salt: Some(salt),
        age: Some(30),
        credit_score: Some(780),
        expiration_epoch: Some(1900000000),
        identity_commitment: Some(commitment),
        scope_id: Some(scope_id),
        nullifier: Some(nullifier),
        min_age: Some(18),
        min_credit_score: Some(650),
        current_epoch: Some(1700000000),
    };

    c.bench_function("prove_identity_circuit", |bencher| {
        bencher.iter(|| AegisProver::prove_identity(&pk, circuit_fn()).unwrap())
    });

    let proof = AegisProver::prove_identity(&pk, circuit_fn()).unwrap();
    let inputs = vec![
        commitment,
        scope_id,
        nullifier,
        Fr::from(18u64),
        Fr::from(650u64),
        Fr::from(1700000000u64),
    ];

    c.bench_function("verify_identity_circuit", |bencher| {
        bencher.iter(|| LightweightVerifier::verify(&vk, &inputs, &proof).unwrap())
    });
}

criterion_group!(benches, bench_poseidon_native, bench_groth16_identity);
criterion_main!(benches);
