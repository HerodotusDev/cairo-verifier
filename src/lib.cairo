mod air;

#[cfg(feature: 'recursive')]
mod benches;

mod channel;
mod common;
mod deserialization;
mod domains;
mod fri;
mod oods;
mod proof_of_work;
mod queries;
mod stark;
mod table_commitment;
mod vector_commitment;
mod split;

#[cfg(feature: 'recursive')]
mod tests;

use cairo_verifier::{
    deserialization::stark::StarkProofWithSerde, stark::{StarkProof, StarkProofImpl}
};

#[cfg(feature: 'dex')]
use cairo_verifier::air::layouts::dex::public_input::{DexPublicInputImpl as PublicInputImpl};

#[cfg(feature: 'recursive')]
use cairo_verifier::air::layouts::recursive::public_input::RecursivePublicInputImpl as PublicInputImpl;

#[cfg(feature: 'recursive_with_poseidon')]
use cairo_verifier::air::layouts::recursive_with_poseidon::public_input::RecursiveWithPoseidonPublicInputImpl as PublicInputImpl;

#[cfg(feature: 'small')]
use cairo_verifier::air::layouts::small::public_input::SmallPublicInputImpl as PublicInputImpl;

#[cfg(feature: 'starknet')]
use cairo_verifier::air::layouts::starknet::public_input::StarknetPublicInputImpl as PublicInputImpl;

#[cfg(feature: 'starknet_with_keccak')]
use cairo_verifier::air::layouts::starknet_with_keccak::public_input::StarknetWithKeccakPublicInputImpl as PublicInputImpl;


const SECURITY_BITS: felt252 = 50;

fn main(serialized_proof: Array<felt252>) -> (felt252, felt252) {
    let mut serialized_proof_span = serialized_proof.span();
    let stark_proof: StarkProof = Serde::<
        StarkProofWithSerde
    >::deserialize(ref serialized_proof_span)
        .unwrap()
        .into();

    stark_proof.verify(SECURITY_BITS);
    let (program_hash, output_hash) = stark_proof.public_input.verify();

    (program_hash, output_hash)
}
