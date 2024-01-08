use cairo_verifier::{
    common::asserts::assert_in_range,
    fri::fri_config::FriConfig as DeserializationUnfriendlyFriConfig,
    table_commitment::TableCommitmentConfig,
    vector_commitment::vector_commitment::{VectorCommitmentConfig, validate_vector_commitment},
    validation::proof_of_work::proof_of_work_config_validate, fri::fri_config::fri_config_validate,
};

const MAX_N_COLUMNS: felt252 = 128;
const AIR_LAYOUT_N_ORIGINAL_COLUMNS: felt252 = 12;
const AIR_LAYOUT_N_INTERACTION_COLUMNS: felt252 = 3;

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

fn stark_config_validate(stark_config: StarkConfig, security_bits: felt252) {
    proof_of_work_config_validate(stark_config.proof_of_work);

    let log_eval_domain_size = stark_config.log_trace_domain_size + stark_config.log_n_cosets;
    traces_config_validate(stark_config.traces, log_eval_domain_size, security_bits);

    validate_vector_commitment(
        stark_config.composition.vector,
        log_eval_domain_size,
        stark_config.n_verifier_friendly_commitment_layers
    );
    fri_config_validate(
        stark_config.fri.into(),
        stark_config.log_n_cosets,
        stark_config.n_verifier_friendly_commitment_layers
    );
}

#[derive(Drop, Serde)]
struct TracesConfig {
    original: TableCommitmentConfig,
    interaction: TableCommitmentConfig,
}

// Validates the configuration of the traces.
// log_eval_domain_size - Log2 of the evaluation domain size.
fn traces_config_validate(
    config: TracesConfig,
    log_eval_domain_size: felt252,
    n_verifier_friendly_commitment_layers: felt252,
) {
    assert_in_range(config.original.n_columns, 1, MAX_N_COLUMNS + 1);
    assert_in_range(config.interaction.n_columns, 1, MAX_N_COLUMNS + 1);
    assert(config.original.n_columns == AIR_LAYOUT_N_ORIGINAL_COLUMNS, 'Wrong number of columns');
    assert(
        config.interaction.n_columns == AIR_LAYOUT_N_INTERACTION_COLUMNS, 'Wrong number of columns'
    );

    validate_vector_commitment(
        config.original.vector, log_eval_domain_size, n_verifier_friendly_commitment_layers,
    );
    validate_vector_commitment(
        config.interaction.vector, log_eval_domain_size, n_verifier_friendly_commitment_layers,
    );
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

impl IntoDeserializationUnfriendlyFriConfig of Into<FriConfig, DeserializationUnfriendlyFriConfig> {
    fn into(self: FriConfig) -> DeserializationUnfriendlyFriConfig {
        let mut inner_layers = ArrayTrait::<TableCommitmentConfig>::new();
        let mut i = 0;
        loop {
            if i == self.inner_layers.len() {
                break;
            }

            inner_layers
                .append(
                    TableCommitmentConfig {
                        n_columns: *self.inner_layers.at(i),
                        vector: VectorCommitmentConfig {
                            height: *self.inner_layers.at(i + 1),
                            n_verifier_friendly_commitment_layers: *self.inner_layers.at(i + 2),
                        }
                    }
                );
            i += 3;
        };

        DeserializationUnfriendlyFriConfig {
            log_input_size: self.log_input_size,
            n_layers: self.n_layers,
            inner_layers: inner_layers.span(),
            fri_step_sizes: self.fri_step_sizes.span(),
            log_last_layer_degree_bound: self.log_last_layer_degree_bound,
        }
    }
}

#[derive(Drop, Serde)]
struct ProofOfWorkConfig {
    // Proof of work difficulty (number of bits required to be 0).
    n_bits: felt252,
}
