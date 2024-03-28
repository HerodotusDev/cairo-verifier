use cairo_verifier::{
    deserialization::{
        vector::{
            VectorCommitmentConfig, VectorCommitmentWitness, VectorCommitmentConfigWithSerde,
            VectorCommitmentWitnessWithSerde
        },
        table::{
            TableCommitmentConfigWithSerde, TableDecommitmentWithSerde,
            TableCommitmentWitnessWithSerde,
        }
    },
    table_commitment::table_commitment::{
        TableCommitmentConfig, TableCommitmentWitness, TableDecommitment
    },
};

#[cfg(feature: 'dex')]
use cairo_verifier::air::layouts::dex::{
    traces::TracesConfig, traces::{TracesUnsentCommitment, TracesDecommitment, TracesWitness}
};

#[cfg(feature: 'recursive')]
use cairo_verifier::air::layouts::recursive::{
    traces::TracesConfig, traces::{TracesUnsentCommitment, TracesDecommitment, TracesWitness}
};

#[cfg(feature: 'recursive_with_poseidon')]
use cairo_verifier::air::layouts::recursive_with_poseidon::{
    traces::TracesConfig, traces::{TracesUnsentCommitment, TracesDecommitment, TracesWitness}
};

#[cfg(feature: 'small')]
use cairo_verifier::air::layouts::small::{
    traces::TracesConfig, traces::{TracesUnsentCommitment, TracesDecommitment, TracesWitness}
};

#[cfg(feature: 'starknet')]
use cairo_verifier::air::layouts::starknet::{
    traces::TracesConfig, traces::{TracesUnsentCommitment, TracesDecommitment, TracesWitness}
};

#[cfg(feature: 'starknet_with_keccak')]
use cairo_verifier::air::layouts::starknet_with_keccak::{
    traces::TracesConfig, traces::{TracesUnsentCommitment, TracesDecommitment, TracesWitness}
};

#[derive(Drop, Serde)]
struct TracesConfigWithSerde {
    original: TableCommitmentConfigWithSerde,
    interaction: TableCommitmentConfigWithSerde,
}
impl IntoTracesConfig of Into<TracesConfigWithSerde, TracesConfig> {
    fn into(self: TracesConfigWithSerde) -> TracesConfig {
        TracesConfig { original: self.original.into(), interaction: self.interaction.into() }
    }
}

#[derive(Drop, Serde)]
struct TracesDecommitmentWithSerde {
    original: TableDecommitmentWithSerde,
    interaction: TableDecommitmentWithSerde,
}
impl IntoTracesDecommitment of Into<TracesDecommitmentWithSerde, TracesDecommitment> {
    fn into(self: TracesDecommitmentWithSerde) -> TracesDecommitment {
        TracesDecommitment { original: self.original.into(), interaction: self.interaction.into() }
    }
}

#[derive(Drop, Serde)]
struct TracesUnsentCommitmentWithSerde {
    original: felt252,
    interaction: felt252,
}
impl IntoTracesUnsentCommitment of Into<TracesUnsentCommitmentWithSerde, TracesUnsentCommitment> {
    fn into(self: TracesUnsentCommitmentWithSerde) -> TracesUnsentCommitment {
        TracesUnsentCommitment { original: self.original, interaction: self.interaction }
    }
}

#[derive(Drop, Serde)]
struct TracesWitnessWithSerde {
    original: TableCommitmentWitnessWithSerde,
    interaction: TableCommitmentWitnessWithSerde,
}
impl IntoTracesWitness of Into<TracesWitnessWithSerde, TracesWitness> {
    fn into(self: TracesWitnessWithSerde) -> TracesWitness {
        TracesWitness { original: self.original.into(), interaction: self.interaction.into() }
    }
}
