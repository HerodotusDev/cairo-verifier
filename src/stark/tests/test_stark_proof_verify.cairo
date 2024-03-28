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

    stark_proof.verify(security_bits);
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

    stark_proof.verify(security_bits);
}

