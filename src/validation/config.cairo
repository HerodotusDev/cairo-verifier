use cairo_verifier::{
    structs::stark_config::TracesConfig, validation::asserts::assert_in_range,
    vector_commitment::vector_commitment::validate_vector_commitment,
    fri::fri_config::fri_config_validate,
};

const MAX_N_COLUMNS: felt252 = 128;
const AIR_LAYOUT_N_ORIGINAL_COLUMNS: felt252 = 12;
const AIR_LAYOUT_N_INTERACTION_COLUMNS: felt252 = 3;

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
