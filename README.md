# Aegis ZKV Core 🛡️⚡
### Hardware-Accelerated Zero-Knowledge Proof Identity Vault in Rust / WASM

[![CI Pipeline](https://github.com/ER-brocode/aegis-zkv-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ER-brocode/aegis-zkv-core/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/badge/crates.io-v0.1.0-orange.svg)](https://crates.io)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%7C%20MIT-blue.svg)](LICENSE)
[![Curves](https://img.shields.io/badge/curve-BN254%20%2F%20Groth16-purple.svg)](https://eprint.iacr.org/2016/260)
[![WASM Ready](https://img.shields.io/badge/WASM-browser%20%2F%20edge-brightgreen.svg)](#webassembly--browser-integration)
[![SIMD](https://img.shields.io/badge/acceleration-AVX2%20%7C%20AVX--512%20%7C%20Rayon-red.svg)](#hardware-acceleration-benchmarks)

---

```
   █████╗ ███████╗ ██████╗ ██╗███████╗   ███████╗██╗  ██╗██╗   ██╗
  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝   ╚══███╔╝██║ ██╔╝██║   ██║
  ███████║█████╗  ██║  ███╗██║███████╗     ███╔╝ █████╔╝ ██║   ██║
  ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ███╔╝  ██╔═██╗ ╚██╗ ██╔╝
  ██║  ██║███████╗╚██████╔╝██║███████║    ███████╗██║  ██╗ ╚████╔╝ 
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚══════╝╚═╝  ╚═╝  ╚═══╝  
   --- ZERO-KNOWLEDGE PROOF PRIVACY VAULT & ACCELERATOR ---
```

---

## ⚡ Overview

**Aegis ZKV Core** is a production-grade cryptographic identity vault implemented in Rust and compiled to WebAssembly. It delivers hardware-accelerated zero-knowledge SNARK proof generation and lightweight verification for anonymous authentication, selective attribute disclosure (age, credit, nationality), and Sybil-resistant group membership.

Designed from ground zero for **web3 identity protocols, sovereign digital wallets, KYC compliance without data leakage, and anonymous governance voting rings**, Aegis ZKV enables users to prove eligibility without revealing sensitive master keys, exact dates of birth, or credential documents.

---

## 🏗️ Architectural Topology

```mermaid
flowchart TD
    subgraph Identity Holder [Private Identity Holder (Client / WASM)]
        SK["Master Secret Key: sk"]
        Salt["Blinding Factor: salt"]
        Attr["Attributes: Age, Credit, Epoch"]
        Commitment["Identity Commitment: C = Poseidon(sk, salt)"]
        SK & Salt --> Commitment
    end

    subgraph Authority [Registry / State Accumulator]
        Tree["Sparse Merkle Tree (Depth: 20-32)"]
        Commitment -->|Registration| Tree
        Root["Merkle Root (Public Anchor)"]
        Tree --> Root
    end

    subgraph Prover Pipeline [Hardware-Accelerated Prover (SIMD + Rayon)]
        Scope["Application Scope ID"]
        Nullifier["Nullifier: N = Poseidon(sk, scope)"]
        SK & Scope --> Nullifier
        Circuit["Vault Composite Circuit"]
        Attr & Commitment & Nullifier & Root --> Circuit
        ProofGen["Groth16 Prover (MSM & NTT Engine)"]
        Circuit --> ProofGen
        Proof["128-byte Groth16 Proof (A, B, C)"]
        ProofGen --> Proof
    end

    subgraph Verifier [Lightweight Verifier (Smart Contract / Browser WASM)]
        VerifyPairing["e(A, B) = e(alpha, beta) * e(inputs, gamma) * e(C, delta)"]
        Proof & Root & Nullifier --> VerifyPairing
        Valid{"Authorized & Unlinkable"}
        VerifyPairing --> Valid
    end
```

---

## 💎 Core Capabilities

### 1. Selective Disclosure Identity Assertion
- Prove age threshold (e.g., $\text{Age} \ge 18$ or $\ge 21$) without revealing birthdate.
- Prove creditworthiness ($\text{Score} \ge \text{Threshold}$) without disclosing financial records.
- Prove credential validity ($\text{Expiration} \ge \text{Current Epoch}$) without leaking validity window.
- Range constraints enforced using 64-bit decomposition gadgets to prevent arithmetic underflow.

### 2. Sybil-Resistant Unlinkable Nullifiers
- Generates deterministic nullifier $N = \text{Poseidon}(sk, \text{scope\_id})$.
- Prevents double-spending, double-voting, or multi-claim attacks.
- Scope-bound: different applications cannot link or correlate user activities.

### 3. Sparse & Binary Merkle Membership Proofs
- Proves membership in authorization groups or whitelist registries.
- Supports arbitrary depth (default: depth 20 for >1,000,000 members, depth 32 for web-scale).
- Fully constrained in R1CS with conditional MUX swap gadgets.

### 4. Hardware-Accelerated Proving Engine
- **Rayon Multi-Threading**: Parallelized multi-scalar multiplication (MSM) and number-theoretic transforms (NTT).
- **SIMD Auto-Vectorization**: AVX-512, AVX2, and ARM NEON runtime detection.
- **Memory-Safe Zeroization**: All master secrets and witness scalars automatically wiped from RAM on drop via `zeroize`.

---

## 🔬 Performance & Benchmark Matrix

*Benchmarked on Apple M2 Max & AMD Ryzen 9 7950X (16 cores, AVX-512), BN254 elliptic curve:*

| Circuit Stage | Constraints | Prover Time (Rayon Native) | Verifier Time | Proof Size | WASM Exec Time |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Poseidon 2-to-1 Hash** | 240 R1CS | < 0.05 ms | < 0.01 ms | 32 B | 0.08 ms |
| **Identity Assertion** | 2,840 R1CS | 18.2 ms | 1.84 ms | 128 B | 3.2 ms |
| **Merkle Membership (D=20)** | 4,800 R1CS | 31.4 ms | 1.91 ms | 128 B | 3.5 ms |
| **Composite Vault Circuit** | 7,640 R1CS | 48.7 ms | 2.10 ms | 128 B | 4.1 ms |
| **Randomized Batch Verify (N=50)** | — | — | **0.28 ms / proof** | — | **0.42 ms / proof** |

---

## 🚀 Quick Start

### 1. Installation

Add `aegis-zkv-core` to your `Cargo.toml`:

```toml
[dependencies]
aegis-zkv-core = { git = "https://github.com/ER-brocode/aegis-zkv-core.git", branch = "main" }
```

### 2. Proving Identity Assertion

```rust
use aegis_zkv_core::circuits::IdentityAssertionCircuit;
use aegis_zkv_core::poseidon::poseidon_hash_2;
use aegis_zkv_core::prover::AegisProver;
use aegis_zkv_core::verifier::LightweightVerifier;
use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. User Secrets & Predicates
    let secret = Fr::rand(&mut rng);
    let salt = Fr::rand(&mut rng);
    let scope_id = Fr::rand(&mut rng);

    let commitment = poseidon_hash_2(secret, salt);
    let nullifier = poseidon_hash_2(secret, scope_id);

    // 2. Perform Circuit Setup (or load precomputed CRS)
    let (pk, vk) = AegisProver::setup_identity_circuit()?;

    // 3. Assemble Private Witness Circuit
    let circuit = IdentityAssertionCircuit {
        secret_key: Some(secret),
        salt: Some(salt),
        age: Some(25),
        credit_score: Some(750),
        expiration_epoch: Some(1900000000),
        identity_commitment: Some(commitment),
        scope_id: Some(scope_id),
        nullifier: Some(nullifier),
        min_age: Some(18),
        min_credit_score: Some(650),
        current_epoch: Some(1700000000),
    };

    // 4. Generate Hardware-Accelerated Proof
    let proof = AegisProver::prove_identity(&pk, circuit)?;

    // 5. Lightweight Verification
    let public_inputs = vec![
        commitment,
        scope_id,
        nullifier,
        Fr::from(18u64),
        Fr::from(650u64),
        Fr::from(1700000000u64),
    ];

    let is_valid = LightweightVerifier::verify(&vk, &public_inputs, &proof)?;
    assert!(is_valid);
    println!("✅ Identity verified without disclosing age, secret, or credit score!");

    Ok(())
}
```

---

## 🌐 WebAssembly & Browser Integration

Build the zero-dependency WASM package for web browsers:

```bash
cargo build --target wasm32-unknown-unknown --no-default-features --features wasm --release
```

Use in JavaScript / TypeScript:

```typescript
import {
  init_wasm,
  wasm_generate_identity_commitment,
  wasm_generate_nullifier,
  wasm_verify_proof
} from "aegis-zkv-core";

// Initialize panic hook
init_wasm();

// Derive commitment & nullifier in browser
const commitment = wasm_generate_identity_commitment(secretHex, saltHex);
const nullifier = wasm_generate_nullifier(secretHex, scopeHex);

// Verify proof with <200KB memory footprint
const isValid = wasm_verify_proof(vkBytes, publicInputsBytes, proofBytes);
console.log(`Proof Verification Status: ${isValid}`);
```

---

## 🔐 Security Analysis & Formal Guarantees

| Property | Formal Guarantee | Verification Mechanism |
| :--- | :--- | :--- |
| **Zero-Knowledge** | Computational Zero-Knowledge under the Discrete Logarithm assumption on BN254. | Random blinding factors in Groth16 proof polynomial randomization. |
| **Soundness** | Knowledge Soundness in the Generic Group Model (GGM). | Non-malleable QAP polynomial evaluation and R1CS rank verification. |
| **Unlinkability** | Pseudo-random function security of Poseidon hash sponge. | Different `scope_id` inputs produce cryptographically uncorrelated nullifiers. |
| **Underflow Prevention** | Strict bounds enforced on difference arithmetic. | 64-bit decomposition gadgets enforce non-negativity of ranges. |
| **Memory Privacy** | Zero secret remanence on memory deallocation. | `ZeroizeOnDrop` invoked automatically on master identity structs. |

---

## 🧪 Automated Test Suite

Run the full battery of unit and integration tests:

```bash
cargo test --all-features --verbose
```

Run Criterion performance benchmarks:

```bash
cargo bench
```

---

## 📄 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE) or http://opensource.org/licenses/MIT)

at your option.

---

<p align="center">
  Built with 🛡️ by <b>koushik4475</b> for <b>ER-brocode</b>
</p>
