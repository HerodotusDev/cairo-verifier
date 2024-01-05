use cairo_verifier::{
    input_structs::stark_proof::StarkProof,
    validation::stark_config::stark_config_validate
};

const SECURITY_BITS: felt252 = 9;


fn verify_stark_proof(proof: StarkProof) {
    stark_config_validate(proof.config, SECURITY_BITS);
}
