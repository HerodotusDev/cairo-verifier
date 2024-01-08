mod channel;
mod common;
mod input_structs;
mod structs;
mod air;
mod oods;
mod fri;
mod table_commitment;
mod vector_commitment;
mod queries;
mod proof_of_work;

use cairo_verifier::input_structs::stark_proof::StarkProof;

fn main(x: Array<felt252>) {
    let mut x_span = x.span();
    let stark_proof: StarkProof = Serde::deserialize(ref x_span).unwrap();
}
