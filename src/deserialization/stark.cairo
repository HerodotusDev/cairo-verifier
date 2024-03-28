use cairo_verifier::{
    air::{
        public_input::{ContinuousPageHeader, PublicInput, SegmentInfo},
        public_memory::{AddrValue, Page},
    },
    deserialization::{
        traces::{
            TracesConfigWithSerde, TracesDecommitmentWithSerde, TracesWitnessWithSerde,
            TracesUnsentCommitmentWithSerde, TableCommitmentConfigWithSerde,
            TableCommitmentWitnessWithSerde, TableDecommitmentWithSerde
        },
        fri::{FriConfigWithSerde, FriUnsentCommitmentWithSerde, FriWitnessWithSerde},
        pow::{ProofOfWorkConfigWithSerde, ProofOfWorkUnsentCommitmentWithSerde},
    },
    stark::{StarkProof, StarkConfig, StarkUnsentCommitment, StarkWitness},
};

#[cfg(feature: 'dex')]
use cairo_verifier::air::layouts::dex::traces::TracesConfig;

#[cfg(feature: 'recursive')]
use cairo_verifier::air::layouts::recursive::traces::TracesConfig;

#[cfg(feature: 'recursive_with_poseidon')]
use cairo_verifier::air::layouts::recursive_with_poseidon::traces::TracesConfig;

#[cfg(feature: 'small')]
use cairo_verifier::air::layouts::small::traces::TracesConfig;

#[cfg(feature: 'starknet')]
use cairo_verifier::air::layouts::starknet::traces::TracesConfig;

#[cfg(feature: 'starknet_with_keccak')]
use cairo_verifier::air::layouts::starknet_with_keccak::traces::TracesConfig;


#[derive(Drop, Serde)]
struct StarkProofWithSerde {
    config: StarkConfigWithSerde,
    public_input: PublicInputWithSerde,
    unsent_commitment: StarkUnsentCommitmentWithSerde,
    witness: StarkWitnessWithSerde,
}
impl IntoStarkProof of Into<StarkProofWithSerde, StarkProof> {
    fn into(self: StarkProofWithSerde) -> StarkProof {
        StarkProof {
            config: self.config.into(),
            public_input: self.public_input.into(),
            unsent_commitment: self.unsent_commitment.into(),
            witness: self.witness.into(),
        }
    }
}

#[derive(Drop, Serde)]
struct StarkConfigWithSerde {
    traces: TracesConfigWithSerde,
    composition: TableCommitmentConfigWithSerde,
    fri: FriConfigWithSerde,
    proof_of_work: ProofOfWorkConfigWithSerde,
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
impl IntoStarkConfig of Into<StarkConfigWithSerde, StarkConfig> {
    fn into(self: StarkConfigWithSerde) -> StarkConfig {
        StarkConfig {
            traces: self.traces.into(),
            composition: self.composition.into(),
            fri: self.fri.into(),
            proof_of_work: self.proof_of_work.into(),
            log_trace_domain_size: self.log_trace_domain_size,
            n_queries: self.n_queries,
            log_n_cosets: self.log_n_cosets,
            n_verifier_friendly_commitment_layers: self.n_verifier_friendly_commitment_layers,
        }
    }
}

#[derive(Drop, Serde)]
struct PublicInputWithSerde {
    log_n_steps: felt252,
    range_check_min: felt252,
    range_check_max: felt252,
    layout: felt252,
    dynamic_params: Array<felt252>,
    n_segments: felt252,
    segments: Array<felt252>,
    padding_addr: felt252,
    padding_value: felt252,
    main_page_len: felt252,
    main_page: Array<felt252>,
    n_continuous_pages: felt252,
    continuous_page_headers: Array<felt252>,
}
impl IntoPublicInput of Into<PublicInputWithSerde, PublicInput> {
    fn into(self: PublicInputWithSerde) -> PublicInput {
        let mut segments = ArrayTrait::<SegmentInfo>::new();
        let mut i = 0;
        loop {
            if i == self.segments.len() {
                break;
            }

            segments
                .append(
                    SegmentInfo { begin_addr: *self.segments[i], stop_ptr: *self.segments[i + 1], }
                );
            i += 2;
        };

        let mut page = ArrayTrait::<AddrValue>::new();
        let mut i = 0;
        loop {
            if i == self.main_page.len() {
                break;
            }

            page.append(AddrValue { address: *self.main_page[i], value: *self.main_page[i + 1], });

            i += 2;
        };

        let mut continuous_page_headers = ArrayTrait::<ContinuousPageHeader>::new();
        let mut i = 0;
        loop {
            if i == self.continuous_page_headers.len() {
                break;
            }

            continuous_page_headers
                .append(
                    ContinuousPageHeader {
                        start_address: *self.continuous_page_headers[i],
                        size: *self.continuous_page_headers[i + 1],
                        hash: (*self.continuous_page_headers[i + 2]).into(),
                        prod: *self.continuous_page_headers[i + 3],
                    }
                );

            i += 4;
        };
        PublicInput {
            log_n_steps: self.log_n_steps,
            range_check_min: self.range_check_min,
            range_check_max: self.range_check_max,
            layout: self.layout,
            dynamic_params: self.dynamic_params,
            segments: segments,
            padding_addr: self.padding_addr,
            padding_value: self.padding_value,
            main_page: page.into(),
            continuous_page_headers: continuous_page_headers,
        }
    }
}

#[derive(Drop, Serde)]
struct StarkUnsentCommitmentWithSerde {
    traces: TracesUnsentCommitmentWithSerde,
    composition: felt252,
    oods_values: Array<felt252>,
    fri: FriUnsentCommitmentWithSerde,
    proof_of_work: ProofOfWorkUnsentCommitmentWithSerde,
}
impl IntoStarkUnsentCommitment of Into<StarkUnsentCommitmentWithSerde, StarkUnsentCommitment> {
    fn into(self: StarkUnsentCommitmentWithSerde) -> StarkUnsentCommitment {
        StarkUnsentCommitment {
            traces: self.traces.into(),
            composition: self.composition,
            oods_values: self.oods_values.span(),
            fri: self.fri.into(),
            proof_of_work: self.proof_of_work.into(),
        }
    }
}

#[derive(Drop, Serde)]
struct StarkWitnessWithSerde {
    traces_decommitment: TracesDecommitmentWithSerde,
    traces_witness: TracesWitnessWithSerde,
    composition_decommitment: TableDecommitmentWithSerde,
    composition_witness: TableCommitmentWitnessWithSerde,
    fri_witness: FriWitnessWithSerde,
}
impl IntoStarkWitness of Into<StarkWitnessWithSerde, StarkWitness> {
    fn into(self: StarkWitnessWithSerde) -> StarkWitness {
        StarkWitness {
            traces_decommitment: self.traces_decommitment.into(),
            traces_witness: self.traces_witness.into(),
            composition_decommitment: self.composition_decommitment.into(),
            composition_witness: self.composition_witness.into(),
            fri_witness: self.fri_witness.into(),
        }
    }
}
