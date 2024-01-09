mod air;
mod channel;
mod common;
mod fri;
mod structs;
mod oods;
mod queries;
mod proof_of_work;
mod table_commitment;
mod validation;
mod vector_commitment;

use cairo_verifier::{structs::stark_proof::StarkProof, validation::stark::verify_stark_proof};


fn main(x: Array<felt252>) {
    let mut x_span = x.span();
    let stark_proof: StarkProof = Serde::deserialize(ref x_span).unwrap();
    verify_stark_proof(stark_proof);
}
