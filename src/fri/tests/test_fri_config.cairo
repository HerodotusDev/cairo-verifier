use cairo_verifier::{fri::fri_config::FriConfigTrait, tests::stone_proof_fibonacci_keccak};

// test data from cairo0-verifier keccak-native run on stone-prover generated proof
#[test]
#[available_gas(9999999999)]
fn test_fri_config() {
    let fri_config = stone_proof_fibonacci_keccak::fri::config::get();
    let log_n_cosets = 0x4;
    let n_verifier_friendly_commitment_layers = 0x64;
    let log_expected_input_degree = 0x12;

    assert(
        fri_config
            .validate(
                log_n_cosets, n_verifier_friendly_commitment_layers
            ) == log_expected_input_degree,
        'Invalid value'
    );
}
