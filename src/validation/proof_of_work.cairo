use cairo_verifier::structs::stark_config::ProofOfWorkConfig;
use cairo_verifier::common::math::Felt252PartialOrd;

const MIN_PROOF_OF_WORK_BITS: felt252 = 30;
const MAX_PROOF_OF_WORK_BITS: felt252 = 50;

fn proof_of_work_config_validate(config: ProofOfWorkConfig) {
    assert(MIN_PROOF_OF_WORK_BITS <= config.n_bits, 'Too few bits for proof of work');
    assert(config.n_bits < MAX_PROOF_OF_WORK_BITS, 'Too many bits for proof of work');
}
