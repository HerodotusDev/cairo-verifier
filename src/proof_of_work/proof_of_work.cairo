use core::traits::Into;
use cairo_verifier::{
    common::{
        flip_endianness::FlipEndiannessTrait, array_print::{SpanPrintTrait, ArrayPrintTrait},
        blake2s_u8::blake2s, array_append::ArrayAppendTrait, math::pow,
    },
    channel::channel::{Channel, ChannelTrait}, proof_of_work::config::{ProofOfWorkConfig}
};

const MAGIC: u64 = 0x0123456789abcded;

#[derive(Drop, Copy)]
struct ProofOfWorkUnsentCommitment {
    nonce: u64,
}

fn proof_of_work_commit(
    ref channel: Channel, unsent_commitment: ProofOfWorkUnsentCommitment, config: ProofOfWorkConfig
) {
    verify_proof_of_work(channel.digest, config.n_bits, unsent_commitment.nonce);
    channel.read_uint64_from_prover(unsent_commitment.nonce);
}

fn verify_proof_of_work(digest: u256, n_bits: u8, nonce: u64) {
    // Compute the initial hash.
    // Hash(0x0123456789abcded || digest   || n_bits )
    //      8 bytes            || 32 bytes || 1 byte
    // Total of 0x29 = 41 bytes.

    let mut init_hash_data = ArrayTrait::<u64>::new();
    init_hash_data.append(MAGIC.flip_endianness());
    init_hash_data.append_big_endian(digest);
    let init_hash = keccak::cairo_keccak(ref init_hash_data, n_bits.into(), 1).flip_endianness();

    // Compute Hash(init_hash || nonce   )
    //              32 bytes  || 8 bytes
    // Total of 0x28 = 40 bytes.

    let mut hash_data = ArrayTrait::<u64>::new();
    hash_data.append_big_endian(init_hash);
    hash_data.append(nonce.flip_endianness());
    let hash = keccak::cairo_keccak(ref hash_data, 0, 0).flip_endianness();

    let work_limit = pow(2, 128 - n_bits.into());
    assert(
        Into::<u128, u256>::into(hash.high) < Into::<felt252, u256>::into(work_limit),
        'proof of work failed'
    )
}
