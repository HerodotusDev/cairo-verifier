#[derive(Drop, Serde)]
struct StarkUnsentCommitment {
    traces: TracesUnsentCommitment,
    composition: felt252,
    oods_values: Array<felt252>,
    fri: FriUnsentCommitment,
    proof_of_work: ProofOfWorkUnsentCommitment,
}

#[derive(Drop, Serde)]
struct TracesUnsentCommitment {
    original: felt252,
    interaction: felt252,
}

#[derive(Drop, Serde)]
struct FriUnsentCommitment {
    inner_layers: Array<felt252>,
    last_layer_coefficients: Array<felt252>,
}

#[derive(Drop, Serde)]
struct ProofOfWorkUnsentCommitment {
    nonce: felt252,
}
