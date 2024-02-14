use cairo_verifier::{
    channel::channel::ChannelImpl,
    air::{traces::{traces_commit, traces_decommit}, traces::TracesConfigTrait},
    tests::stone_proof_fibonacci,
};

// test data from cairo0-verifier run on stone-prover generated proof
#[test]
#[available_gas(9999999999)]
fn test_traces_config() {
    let traces_config = stone_proof_fibonacci::traces::config::get();

    traces_config.validate(0x16, 0x16);
}

// test data from cairo0-verifier run on stone-prover generated proof
#[test]
#[available_gas(9999999999)]
fn test_traces_commit() {
    let mut channel = ChannelImpl::new_with_counter(
        u256 { low: 0xba9d17a3ebd900899148b125421c118f, high: 0x87433b8dd90acbfe5abea8474d795191 },
        0x0,
    );
    let unsent_commitment = stone_proof_fibonacci::traces::unsent_commitment::get();
    let traces_config = stone_proof_fibonacci::traces::config::get();

    assert(
        traces_commit(
            ref channel, unsent_commitment, traces_config
        ) == stone_proof_fibonacci::traces::commitment::get(),
        'Invalid value'
    );

    assert(
        channel
            .digest == u256 {
                low: 0x8823a41f7994f81c6453f4bc3cad1c10, high: 0x75f85ae3fd3ff6b5f63029a51040037e
            },
        'Invalid value'
    );

    assert(channel.counter == 0x0, 'Invalid value')
}

// test data from cairo0-verifier run on stone-prover generated proof
#[test]
#[available_gas(9999999999)]
fn test_traces_decommit() {
    let queries = stone_proof_fibonacci::queries::get().span();
    let commitment = stone_proof_fibonacci::traces::commitment::get();
    let decommitment = stone_proof_fibonacci::traces::decommitment::get();
    let witness = stone_proof_fibonacci::traces::witness::get();

    traces_decommit(queries, commitment, decommitment, witness);
}
