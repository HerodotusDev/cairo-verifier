use cairo_verifier::{
    stark::stark_commit::stark_commit, channel::channel::ChannelTrait,
    tests::{stone_proof_fibonacci, stone_proof_fibonacci_keccak}
};

#[cfg(feature: 'blake2s')]
#[test]
#[available_gas(9999999999)]
fn test_stark_commit() {
    let mut channel = ChannelTrait::new_with_counter(
        0xaf91f2c71f4a594b1575d258ce82464475c82d8fb244142d0db450491c1b52, 0x0
    );

    let public_input = stone_proof_fibonacci::public_input::get();
    let unsent_commitment = stone_proof_fibonacci::stark::unsent_commitment::get();
    let config = stone_proof_fibonacci::stark::config::get();
    let stark_domains = stone_proof_fibonacci::stark::domains::get();

    assert(
        stark_commit(
            ref channel, @public_input, @unsent_commitment, @config, @stark_domains
        ) == stone_proof_fibonacci::stark::commitment::get(),
        'Invalid value'
    );

    assert(
        channel.digest == 0x9c769c7e0797cf043b06b980072a798b141f2bc41b14e85ad93ba178b13de7,
        'Invalid value'
    );
    assert(channel.counter == 0x0, 'Invalid value');
}

#[cfg(feature: 'keccak')]
#[test]
#[available_gas(9999999999)]
fn test_stark_commit() {
    let mut channel = ChannelTrait::new_with_counter(
        0xaf91f2c71f4a594b1575d258ce82464475c82d8fb244142d0db450491c1b52, 0x0
    );

    let public_input = stone_proof_fibonacci_keccak::public_input::get();
    let unsent_commitment = stone_proof_fibonacci_keccak::stark::unsent_commitment::get();
    let config = stone_proof_fibonacci_keccak::stark::config::get();
    let stark_domains = stone_proof_fibonacci_keccak::stark::domains::get();

    assert(
        stark_commit(
            ref channel, @public_input, @unsent_commitment, @config, @stark_domains
        ) == stone_proof_fibonacci_keccak::stark::commitment::get(),
        'Invalid value'
    );

    assert(
        channel.digest == 0x28f12249c8cba51796d59e7573019ce2b4608c9a8cdeee26e821b0763c69229,
        'Invalid value'
    );
    assert(channel.counter == 0x0, 'Invalid value');
}

