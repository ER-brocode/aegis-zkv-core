use aegis_zkv_core::circuits::MembershipProofCircuit;
use aegis_zkv_core::merkle::MerkleTree;
use aegis_zkv_core::prover::AegisProver;
use aegis_zkv_core::verifier::LightweightVerifier;
use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

const TEST_DEPTH: usize = 4;

#[test]
fn test_merkle_membership_circuit_proof() {
    let mut rng = OsRng;
    let mut tree = MerkleTree::<TEST_DEPTH>::new();

    // Insert 5 test identity leaves
    let mut leaves = Vec::new();
    for _ in 0..5 {
        let leaf = Fr::rand(&mut rng);
        leaves.push(leaf);
        tree.insert(leaf);
    }

    let target_idx = 2;
    let target_leaf = leaves[target_idx];
    let proof = tree.generate_proof(target_idx).expect("Proof generation failed");

    // Setup circuit
    let (pk, vk) = AegisProver::setup_membership_circuit::<TEST_DEPTH>().expect("Setup failed");

    let circuit = MembershipProofCircuit::<TEST_DEPTH> {
        leaf: Some(target_leaf),
        path_elements: Some(proof.path_elements),
        path_indices: Some(proof.path_indices),
        root: Some(tree.root),
    };

    let zk_proof = AegisProver::prove_membership(&pk, circuit).expect("Proving failed");
    let public_inputs = vec![tree.root];

    let is_valid = LightweightVerifier::verify(&vk, &public_inputs, &zk_proof).expect("Verification failed");
    assert!(is_valid, "Merkle membership proof must verify");
}

#[test]
fn test_merkle_membership_invalid_root_rejection() {
    let mut rng = OsRng;
    let mut tree = MerkleTree::<TEST_DEPTH>::new();

    let leaf = Fr::rand(&mut rng);
    tree.insert(leaf);
    let proof = tree.generate_proof(0).expect("Proof generation failed");

    let (pk, vk) = AegisProver::setup_membership_circuit::<TEST_DEPTH>().expect("Setup failed");

    let circuit = MembershipProofCircuit::<TEST_DEPTH> {
        leaf: Some(leaf),
        path_elements: Some(proof.path_elements),
        path_indices: Some(proof.path_indices),
        root: Some(tree.root),
    };

    let zk_proof = AegisProver::prove_membership(&pk, circuit).expect("Proving failed");

    // Invalid root input
    let fake_root = Fr::rand(&mut rng);
    let public_inputs = vec![fake_root];

    let is_valid = LightweightVerifier::verify(&vk, &public_inputs, &zk_proof).expect("Verification failed");
    assert!(!is_valid, "Invalid Merkle root must be rejected");
}
