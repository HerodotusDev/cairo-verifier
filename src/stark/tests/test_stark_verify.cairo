use cairo_verifier::{
    stark::stark_verify::stark_verify,
    air::layouts::recursive::constants::{NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND},
    tests::{stone_proof_fibonacci, stone_proof_fibonacci_keccak}
};

#[cfg(feature: 'blake2s')]
#[test]
#[available_gas(9999999999)]
fn test_stark_verify() {
    let queries = stone_proof_fibonacci::queries::get().span();
    let commitment = stone_proof_fibonacci::stark::commitment::get();
    let witness = stone_proof_fibonacci::stark::witness::get();
    let stark_domains = stone_proof_fibonacci::stark::domains::get();

    stark_verify(
        NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND, queries, commitment, witness, stark_domains,
    )
}

#[cfg(feature: 'keccak')]
#[test]
#[available_gas(9999999999)]
fn test_stark_verify() {
    let queries = stone_proof_fibonacci_keccak::queries::get().span();
    let commitment = stone_proof_fibonacci_keccak::stark::commitment::get();
    let witness = stone_proof_fibonacci_keccak::stark::witness::get();
    let stark_domains = stone_proof_fibonacci_keccak::stark::domains::get();

    stark_verify(
        NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND, queries, commitment, witness, stark_domains,
    )
}
