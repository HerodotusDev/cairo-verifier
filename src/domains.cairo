use core::traits::Div;
use cairo_verifier::{
    common::{consts::{FIELD_GENERATOR, STARK_PRIME_MINUS_ONE}, math::{pow, mul_inverse}},
    structs::stark_config::StarkConfig,
};

// Information about the domains that are used in the stark proof.
#[derive(Drop)]
struct StarkDomains {
    // Log2 of the evaluation domain size.
    log_eval_domain_size: felt252,
    // The evaluation domain size.
    eval_domain_size: felt252,
    // The generator of the evaluation domain (a primitive root of unity of order eval_domain_size).
    eval_generator: felt252,
    // Log2 of the trace domain size.
    log_trace_domain_size: felt252,
    // The trace domain size.
    trace_domain_size: felt252,
    // The generator of the trace domain (a primitive root of unity of order trace_domain_size).
    trace_generator: felt252,
}

fn stark_domains_create(stark_config: StarkConfig) -> StarkDomains {
    // Compute stark_domains.
    let log_eval_domain_size = stark_config.log_trace_domain_size + stark_config.log_n_cosets;
    let eval_domain_size = pow(2, log_eval_domain_size);
    let eval_generator = pow(
        FIELD_GENERATOR, STARK_PRIME_MINUS_ONE * mul_inverse(eval_domain_size)
    );
    let trace_domain_size = pow(2, stark_config.log_trace_domain_size);
    let trace_generator = pow(
        FIELD_GENERATOR, STARK_PRIME_MINUS_ONE * mul_inverse(trace_domain_size)
    );

    StarkDomains {
        log_eval_domain_size,
        eval_domain_size,
        eval_generator,
        log_trace_domain_size: stark_config.log_trace_domain_size,
        trace_domain_size,
        trace_generator,
    }
}
