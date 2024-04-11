use cairo_verifier::{
    air::public_input::{PublicInput, get_public_input_hash},
    channel::channel::{Channel, ChannelImpl},
    fri::{
        fri_config::{FriConfig, FriConfigTrait},
        fri::{FriUnsentCommitment, FriDecommitment, fri_verify, FriWitness, FriCommitment}
    },
    queries::queries, domains::{StarkDomainsImpl, StarkDomains},
    table_commitment::table_commitment::{
        table_decommit, TableCommitmentConfig, TableCommitmentWitness, TableDecommitment, TableCommitment
    },
    proof_of_work::{
        config::{ProofOfWorkConfig, ProofOfWorkConfigTrait},
        proof_of_work::ProofOfWorkUnsentCommitment
    },
    vector_commitment::vector_commitment::VectorCommitmentConfigTrait,
    stark::{StarkUnsentCommitment, StarkWitness, StarkCommitment, StarkProof, StarkConfig, StarkConfigTrait, stark_commit},
    oods::{OodsEvaluationInfo, eval_oods_boundary_poly_at_points},
};

#[cfg(feature: 'dex')]
use cairo_verifier::air::layouts::dex::{
    traces::{traces_decommit, TracesConfig, TracesConfigTrait}, public_input::DexPublicInputImpl,
    traces::{TracesUnsentCommitment, TracesCommitment, TracesDecommitment, TracesWitness},
    constants::{NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND}
};

#[cfg(feature: 'recursive')]
use cairo_verifier::air::layouts::recursive::{
    traces::{traces_decommit, TracesConfig, TracesConfigTrait}, public_input::RecursivePublicInputImpl,
    traces::{TracesUnsentCommitment, TracesCommitment, TracesDecommitment, TracesWitness},
    constants::{NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND},
};

#[cfg(feature: 'recursive_with_poseidon')]
use cairo_verifier::air::layouts::recursive_with_poseidon::{
    traces::{traces_decommit, TracesConfig, TracesConfigTrait}, public_input::RecursiveWithPoseidonPublicInputImpl,
    traces::{TracesUnsentCommitment, TracesCommitment, TracesDecommitment, TracesWitness},
    constants::{NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND}
};

#[cfg(feature: 'small')]
use cairo_verifier::air::layouts::small::{
    traces::{traces_decommit, TracesConfig, TracesConfigTrait}, public_input::SmallPublicInputImpl,
    traces::{TracesUnsentCommitment, TracesCommitment, TracesDecommitment, TracesWitness},
    constants::{NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND}
};

#[cfg(feature: 'starknet')]
use cairo_verifier::air::layouts::starknet::{
    traces::{traces_decommit, TracesConfig, TracesConfigTrait}, public_input::StarknetPublicInputImpl,
    traces::{TracesUnsentCommitment, TracesCommitment, TracesDecommitment, TracesWitness},
    constants::{NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND}
};

#[cfg(feature: 'starknet_with_keccak')]
use cairo_verifier::air::layouts::starknet_with_keccak::{
    traces::{traces_decommit, TracesConfig, TracesConfigTrait}, public_input::StarknetWithKeccakPublicInputImpl,
    traces::{TracesUnsentCommitment, TracesCommitment, TracesDecommitment, TracesWitness},
    constants::{NUM_COLUMNS_FIRST, NUM_COLUMNS_SECOND}
};

#[derive(Drop, Serde)]
struct StarkProofStep1 {
    config: StarkConfig,
    public_input: PublicInput,
    unsent_commitment: StarkUnsentCommitment,
}

fn step1(proof: @StarkProofStep1, security_bits: felt252) -> ContextStep12 {
    // --- BEGIN STEP 1 --- (StarkConfig, PublicInput, StarkUnsentCommitment) -> (queries, stark_commitment, stark_domains)
    // Validate config.
    proof.config.validate(security_bits);

    // Validate the public input.
    let stark_domains = StarkDomainsImpl::new(
        *proof.config.log_trace_domain_size, *proof.config.log_n_cosets
    );
    proof.public_input.validate(@stark_domains);

    // Compute the initial hash seed for the Fiat-Shamir channel.
    let digest = get_public_input_hash(proof.public_input);
    // Construct the channel.
    let mut channel = ChannelImpl::new(digest);

    // STARK commitment phase.
    let stark_commitment = stark_commit::stark_commit(
        ref channel, proof.public_input, proof.unsent_commitment, proof.config, @stark_domains,
    );

    // Generate queries.
    let queries = queries::generate_queries(
        ref channel,
        (*proof.config.n_queries).try_into().unwrap(),
        stark_domains.eval_domain_size.try_into().unwrap()
    ).span();
    
    ContextStep12 {
        queries, stark_commitment, stark_domains
    }
}

#[derive(Drop)]
struct ContextStep12 {
    queries: Span<felt252>,
    stark_commitment: StarkCommitment,
    stark_domains: StarkDomains,
}

#[derive(Drop)]
struct StarkProofStep2 {
    witness: StarkWitness, // TOOD: separate FRI witness for step 3
}

fn step2(proof: @StarkProofStep2, context: ContextStep12) -> ContextStep23 {
    let n_original_columns = NUM_COLUMNS_FIRST;
    let n_interaction_columns = NUM_COLUMNS_SECOND;
    let queries = context.queries;
    let commitment = context.stark_commitment;
    let witness = *proof.witness;

    let stark_domains = context.stark_domains;

    // First layer decommit.
    traces_decommit(
        queries, commitment.traces, witness.traces_decommitment, witness.traces_witness
    );

    table_decommit(
        commitment.composition,
        queries,
        witness.composition_decommitment,
        witness.composition_witness,
    );

    // Compute query points.
    let points = queries::queries_to_points(queries, @stark_domains);

    // Evaluate the FRI input layer at query points.
    let eval_info = OodsEvaluationInfo {
        oods_values: commitment.oods_values,
        oods_point: commitment.interaction_after_composition,
        trace_generator: stark_domains.trace_generator,
        constraint_coefficients: commitment.interaction_after_oods,
    };
    let oods_poly_evals = eval_oods_boundary_poly_at_points(
        n_original_columns,
        n_interaction_columns,
        eval_info,
        points.span(),
        witness.traces_decommitment,
        witness.composition_decommitment,
    );

    // Decommit FRI.
    let fri_decommitment = FriDecommitment {
        values: oods_poly_evals.span(), points: points.span(),
    };
    ContextStep23 {
        queries, fri_commitment: commitment.fri, fri_decommitment
    }
}

#[derive(Drop)]
struct ContextStep23 {
    queries: Span<felt252>,
    fri_commitment: FriCommitment,
    fri_decommitment: FriDecommitment,
}

#[derive(Drop)]
struct StarkProofStep3 {
    witness: FriWitness,
}

fn step3(proof: @StarkProofStep3, context: ContextStep23) {
    fri_verify(
        queries: context.queries,
        commitment: context.fri_commitment,
        decommitment: context.fri_decommitment,
        witness: *proof.witness,
    )
}

fn verify(proof: StarkProof, security_bits: felt252) {
    let step1proof = StarkProofStep1 {
        config: proof.config,
        public_input: proof.public_input,
        unsent_commitment: proof.unsent_commitment,
    };
    let context12 = step1(@step1proof, security_bits);

    let step2proof = StarkProofStep2 {
        witness: proof.witness,
    };

    let context23 = step2(@step2proof, context12);

    let step3proof = StarkProofStep3 {
        witness: proof.witness.fri_witness,
    };

    step3(@step3proof, context23);
}





#[cfg(test)]
mod test {
    use super::verify;
    use cairo_verifier::{
        stark::{StarkProof, StarkProofTrait},
        tests::{stone_proof_fibonacci, stone_proof_fibonacci_keccak}
    };

    #[cfg(feature: 'blake2s')]
    #[test]
    #[available_gas(99999999999)]
    fn test_stark_proof_fibonacci_verify() {
        let security_bits: felt252 = 50;

        let stark_proof = StarkProof {
            config: stone_proof_fibonacci::stark::config::get(),
            public_input: stone_proof_fibonacci::public_input::get(),
            unsent_commitment: stone_proof_fibonacci::stark::unsent_commitment::get(),
            witness: stone_proof_fibonacci::stark::witness::get(),
        };

        verify(stark_proof, security_bits);
    }

    #[cfg(feature: 'keccak')]
    #[test]
    #[available_gas(9999999999)]
    fn test_stark_proof_fibonacci_verify() {
        let security_bits: felt252 = 50;

        let stark_proof = StarkProof {
            config: stone_proof_fibonacci_keccak::stark::config::get(),
            public_input: stone_proof_fibonacci_keccak::public_input::get(),
            unsent_commitment: stone_proof_fibonacci_keccak::stark::unsent_commitment::get(),
            witness: stone_proof_fibonacci_keccak::stark::witness::get(),
        };

        verify(stark_proof, security_bits);
    }
}