use core::traits::TryInto;
use core::traits::Into;
use cairo_verifier::{
    common::math::{pow, Felt252PartialOrd}, table_commitment::TableCommitmentConfig,
    structs::stark_config::FriConfig as FriConfigInputStruct, common::asserts::assert_in_range,
    vector_commitment::vector_commitment::{validate_vector_commitment, VectorCommitmentConfig},
};

const MAX_LAST_LAYER_LOG_DEGREE_BOUND: felt252 = 15;
const MAX_FRI_LAYERS: felt252 = 15;
const MAX_FRI_STEP: felt252 = 4;

#[derive(Drop, Copy)]
struct FriConfig {
    // Log2 of the size of the input layer to FRI.
    log_input_size: felt252,
    // Number of layers in the FRI. Inner + last layer.
    n_layers: felt252,
    // Array of size n_layers - 1, each entry is a configuration of a table commitment for the
    // corresponding inner layer.
    inner_layers: Span<TableCommitmentConfig>,
    // Array of size n_layers, each entry represents the FRI step size,
    // i.e. the number of FRI-foldings between layer i and i+1.
    fri_step_sizes: Span<felt252>,
    log_last_layer_degree_bound: felt252,
}

fn fri_config_validate(
    config: FriConfig, log_n_cosets: felt252, n_verifier_friendly_commitment_layers: felt252
) -> felt252 {
    assert_in_range(config.n_layers, 2, MAX_FRI_LAYERS + 1);
    assert(config.log_last_layer_degree_bound <= MAX_LAST_LAYER_LOG_DEGREE_BOUND, 'Value too big');
    assert(*config.fri_step_sizes.at(0) == 0, 'Invalid value');

    let mut i: u32 = 1;
    let n_layers: u32 = config.n_layers.try_into().unwrap();
    let mut sum_of_step_sizes = 0;
    let mut log_input_size = config.log_input_size;
    loop {
        if i == n_layers {
            break;
        }

        let fri_step = *config.fri_step_sizes.at(i);
        let table_commitment = *config.inner_layers.at(i - 1);
        log_input_size -= fri_step;
        sum_of_step_sizes += fri_step;

        assert_in_range(fri_step, 1, MAX_FRI_STEP + 1);
        assert(table_commitment.n_columns == pow(2, fri_step), 'Invalid value');
        validate_vector_commitment(
            table_commitment.vector, log_input_size, n_verifier_friendly_commitment_layers,
        );

        i += 1;
    };

    let log_expected_input_degree = sum_of_step_sizes + config.log_last_layer_degree_bound;
    assert(
        log_expected_input_degree + log_n_cosets == config.log_input_size, 'Log input size mismatch'
    );
    log_expected_input_degree
}
