use cairo_verifier::vector_commitment::vector_commitment::VectorCommitmentConfig;

#[derive(Drop, Serde)]
struct StarkConfig {
    traces: TracesConfig,
    composition: TableCommitmentConfig,
    fri: FriConfig,
    proof_of_work: ProofOfWorkConfig,
    // Log2 of the trace domain size.
    log_trace_domain_size: felt252,
    // Number of queries to the last component, FRI.
    n_queries: felt252,
    // Log2 of the number of cosets composing the evaluation domain, where the coset size is the
    // trace length.
    log_n_cosets: felt252,
    // Number of layers that use a verifier friendly hash in each commitment.
    n_verifier_friendly_commitment_layers: felt252,
}

#[derive(Drop, Serde)]
struct TracesConfig {
    original: TableCommitmentConfig,
    interaction: TableCommitmentConfig,
}

#[derive(Drop, Serde)]
struct TableCommitmentConfig {
    n_columns: felt252,
    vector: VectorCommitmentConfig
}

#[derive(Drop, Serde)]
struct FriConfig {
    // Log2 of the size of the input layer to FRI.
    log_input_size: felt252,
    // Number of layers in the FRI. Inner + last layer.
    n_layers: felt252,
    // Array of size n_layers - 1, each entry is a configuration of a table commitment for the
    // corresponding inner layer.
    inner_layers: Array<felt252>,
    // Array of size n_layers, each entry represents the FRI step size,
    // i.e. the number of FRI-foldings between layer i and i+1.
    fri_step_sizes: Array<felt252>,
    log_last_layer_degree_bound: felt252,
}

#[derive(Drop, Serde)]
struct ProofOfWorkConfig {
    // Proof of work difficulty (number of bits required to be 0).
    n_bits: felt252,
}
