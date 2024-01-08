use core::clone::Clone;
use cairo_verifier::{
    domains::stark_domains_create,
    structs::{
        stark_config::{StarkConfig, stark_config_validate}, public_input::PublicInput,
        stark_unsent_commitment::StarkUnsentCommitment, stark_witness::StarkWitness,
    }
};

const SECURITY_BITS: felt252 = 9;


#[derive(Drop, Serde)]
struct StarkProof {
    config: StarkConfig,
    public_input: PublicInput,
    unsent_commitment: StarkUnsentCommitment,
    witness: StarkWitness,
}

fn verify_stark_proof(proof: StarkProof) {
    stark_config_validate(proof.config.clone(), SECURITY_BITS);
    let stark_domains = stark_domains_create(proof.config.clone());
}
