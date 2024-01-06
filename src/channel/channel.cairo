use cairo_verifier::common::{
    flip_endianness::FlipEndiannessTrait, array_append::ArrayAppendTrait, blake2s::blake2s,
    consts::{
        C_PRIME_AS_UINT256_LOW, C_PRIME_AS_UINT256_HIGH, STARK_PRIME, MONTGOMERY_R,
        MONTGOMERY_R_INVERSE
    }
};
use poseidon::poseidon_hash_span;
use core::integer::BoundedU128;

#[derive(Drop)]
struct Channel {
    digest: u256,
    counter: u256,
}

#[generate_trait]
impl ChannelImpl of ChannelTrait {
    fn new(digest: u256) -> Channel {
        Channel { digest: digest, counter: 0 }
    }

    fn random_uint256_to_prover(ref self: Channel) -> u256 {
        let mut hash_data = ArrayTrait::<u8>::new();
        hash_data.append_big_endian(self.digest);
        hash_data.append_big_endian(self.counter);
        self.counter += 1;
        blake2s(hash_data).flip_endianness()
    }

    fn random_felt_to_prover(ref self: Channel) -> felt252 {
        let mut res: felt252 = 0;

        // To ensure a uniform distribution over field elements, if the generated 256-bit number x is in
        // range [0, C * PRIME), take x % PRIME. Otherwise, regenerate.
        // The maximal possible C is 2**256//PRIME = 31.        

        loop {
            let rand = self.random_uint256_to_prover();
            if (rand < u256 { low: C_PRIME_AS_UINT256_LOW, high: C_PRIME_AS_UINT256_HIGH }) {
                let to_append = (rand % STARK_PRIME).try_into().unwrap();
                res = to_append * MONTGOMERY_R_INVERSE;
                break;
            }
        };
        res
    }

    fn random_felts_to_prover(ref self: Channel, mut n: felt252) -> Array<felt252> {
        let mut res = ArrayTrait::<felt252>::new();
        loop {
            if n != 0 {
                res.append(self.random_felt_to_prover());
                n -= 1;
            } else {
                break;
            }
        };
        res
    }

    fn read_felt_from_prover(ref self: Channel, value: felt252) {
        let mut hash_data = ArrayTrait::<u8>::new();

        assert(self.digest.low != BoundedU128::max(), 'digest low is 2^128-1');
        hash_data.append_big_endian(self.digest + 1);
        hash_data.append_big_endian(value);

        self.digest = blake2s(hash_data).flip_endianness();
        self.counter = 0;
    }

    fn read_felts_from_prover(ref self: Channel, values: Span<felt252>) {
        let hashed = poseidon_hash_span(values);
        self.read_felt_from_prover(hashed);
    }

    fn read_felt_vector_from_prover(ref self: Channel, values: Span<felt252>) {
        let mut hash_data = ArrayTrait::<u8>::new();

        assert(self.digest.low != BoundedU128::max(), 'digest low is 2^128-1');
        hash_data.append_big_endian(self.digest + 1);

        let mut i = 0;
        loop {
            if i == values.len() {
                break;
            };
            hash_data.append_big_endian(*values[i] * MONTGOMERY_R);
            i += 1;
        };

        self.digest = blake2s(hash_data).flip_endianness();
        self.counter = 0;
    }

    fn read_uint64_from_prover(ref self: Channel, value: u64) {
        let mut hash_data = ArrayTrait::<u8>::new();

        assert(self.digest.low != BoundedU128::max(), 'digest low is 2^128-1');
        hash_data.append_big_endian(self.digest + 1);

        let low: u32 = (value % 0x100000000).try_into().unwrap();
        let high: u32 = (value / 0x100000000).try_into().unwrap();
        hash_data.append_big_endian(value);

        self.digest = blake2s(hash_data).flip_endianness();
        self.counter = 0;
    }
}
