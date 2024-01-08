#[derive(Drop, Serde)]
struct StarkWitness {
    traces_decommitment: TracesDecommitment,
    traces_witness: TracesWitness,
    interaction: TableCommitmentWitness,
    composition_decommitment: TableDecommitment,
    composition_witness: TableCommitmentWitness,
    fri_witness: FriWitness,
}

#[derive(Drop, Serde)]
struct TracesDecommitment {
    original: TableDecommitment,
    interaction: TableDecommitment,
}

#[derive(Drop, Serde)]
struct TableDecommitment {
    n_values: felt252,
    values: Array<felt252>,
}

#[derive(Drop, Serde)]
struct TracesWitness {
    original: TableCommitmentWitness,
}

#[derive(Drop, Serde)]
struct TableCommitmentWitness {
    vector: VectorCommitmentWitness,
}

#[derive(Drop, Serde)]
struct VectorCommitmentWitness {
    n_authentications: felt252,
    authentications: Array<felt252>,
}

#[derive(Drop, Serde)]
struct FriWitness {
    layers: Array<felt252>,
}
