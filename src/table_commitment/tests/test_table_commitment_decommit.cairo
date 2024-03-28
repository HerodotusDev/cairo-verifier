use cairo_verifier::{
    vector_commitment::vector_commitment::{
        VectorCommitment, VectorCommitmentConfig, VectorCommitmentWitness
    },
    table_commitment::table_commitment::{
        table_decommit, TableCommitment, TableCommitmentConfig, TableDecommitment,
        TableCommitmentWitness
    },
    tests::{stone_proof_fibonacci_keccak, stone_proof_fibonacci}
};

#[cfg(feature: 'blake2s')]
#[test]
#[available_gas(9999999999)]
fn test_table_commitment_decommit() {
    let commitment = stone_proof_fibonacci::traces::commitment::get().original;
    let queries = stone_proof_fibonacci::queries::get().span();
    let decommitment = stone_proof_fibonacci::traces::decommitment::get().original;
    let witness = stone_proof_fibonacci::traces::witness::get().original;

    table_decommit(commitment, queries, decommitment, witness);
}

#[cfg(feature: 'keccak')]
#[test]
#[available_gas(9999999999)]
fn test_table_commitment_decommit() {
    let commitment = stone_proof_fibonacci_keccak::traces::commitment::get().original;
    let queries = stone_proof_fibonacci_keccak::queries::get().span();
    let decommitment = stone_proof_fibonacci_keccak::traces::decommitment::get().original;
    let witness = stone_proof_fibonacci_keccak::traces::witness::get().original;

    table_decommit(commitment, queries, decommitment, witness);
}

