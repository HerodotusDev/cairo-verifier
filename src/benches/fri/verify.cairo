use cairo_verifier::{fri::fri::fri_verify, tests::stone_proof_fibonacci_keccak,};

fn bench_fri_verify() {
    let queries = stone_proof_fibonacci_keccak::queries::get().span();
    let commitment = stone_proof_fibonacci_keccak::fri::commitment::get();
    let decommitment = stone_proof_fibonacci_keccak::fri::decommitment::get();
    let witness = stone_proof_fibonacci_keccak::fri::witness::get();

    fri_verify(queries, commitment, decommitment, witness)
}

