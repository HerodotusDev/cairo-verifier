use cairo_verifier::{
    structs::stark_config::StarkConfig,
    validation::{proof_of_work::proof_of_work_config_validate, config::traces_config_validate},
    vector_commitment::vector_commitment::validate_vector_commitment,
    fri::fri_config::fri_config_validate,
};

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
