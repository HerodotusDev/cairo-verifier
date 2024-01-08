use cairo_verifier::{
    channel::channel::{Channel, ChannelTrait},
    common::{
        merge_sort::merge_sort, math::pow, consts::FIELD_GENERATOR, bit_reverse::BitReverseTrait
    }
};

// 2^64 = 18446744073709551616
const U128maxU64: u128 = 18446744073709551616;

fn generate_queries(
    ref channel: Channel, n_samples: u32, query_upper_bound: u64
) -> Array<felt252> {
    let samples = sample_random_queries(ref channel, n_samples, query_upper_bound);
    usort(samples)
}

fn sample_random_queries(
    ref channel: Channel, n_samples: u32, query_upper_bound: u64
) -> Array<u64> {
    let mut result = ArrayTrait::<u64>::new();

    // Samples are generated in quadruplets. We generate ceil(n_samples / 4) samples
    let (mut n_quad, rem) = DivRem::div_rem(n_samples, 4_u32.try_into().unwrap());
    if rem != 0 {
        n_quad += 1;
    }

    let u64_modulus_nonzero: NonZero<u128> = U128maxU64.try_into().unwrap();
    let query_upper_bound_nonzero: NonZero<u64> = query_upper_bound.try_into().unwrap();

    loop {
        if n_quad == 0 {
            break;
        }

        let res = channel.random_uint256_to_prover();

        let (hh, hl) = DivRem::div_rem(res.high, u64_modulus_nonzero);
        let (lh, ll) = DivRem::div_rem(res.low, u64_modulus_nonzero);
        let (_, r0) = DivRem::div_rem(hh.try_into().unwrap(), query_upper_bound_nonzero);
        let (_, r1) = DivRem::div_rem(hl.try_into().unwrap(), query_upper_bound_nonzero);
        let (_, r2) = DivRem::div_rem(lh.try_into().unwrap(), query_upper_bound_nonzero);
        let (_, r3) = DivRem::div_rem(ll.try_into().unwrap(), query_upper_bound_nonzero);

        result.append(r0);
        result.append(r1);
        result.append(r2);
        result.append(r3);

        n_quad -= 1;
    };

    result
}

// Sorts an array of field elements and removes duplicates.
// Returns the sorted array.
fn usort(input: Array<u64>) -> Array<felt252> {
    let mut result = ArrayTrait::<felt252>::new();

    if input.len() == 0 {
        return result;
    }

    let sorted = merge_sort(input);

    let mut prev = *sorted.at(0);
    result.append(prev.into());

    let mut i: u32 = 1;
    loop {
        if i == sorted.len() {
            break;
        }

        let curr = *sorted.at(i);
        if curr != prev {
            result.append(curr.into());
            prev = curr;
        }

        i += 1;
    };

    result
}

fn queries_to_points(
    queries: Span<felt252>, log_eval_domain_size: u8, eval_generator: felt252
) -> Array<felt252> {
    let mut points = ArrayTrait::<felt252>::new();

    // Evaluation domains of size greater than 2**64 are not supported
    assert(log_eval_domain_size <= 64, 'Eval domain too big');

    // A 'log_eval_domain_size' bits index can be bit reversed using bit_reverse_u64 if it is
    // multiplied by 2**(64 - log_eval_domain_size) first.
    let shift = pow(2, 64 - log_eval_domain_size.into());

    let mut i: u32 = 0;
    loop {
        if i == queries.len() {
            break;
        }

        let index: u64 = (*queries.at(i) * shift).try_into().unwrap();

        // Compute the x value of the query in the evaluation domain coset:
        // FIELD_GENERATOR * eval_generator ^ reversed_index.
        points.append(FIELD_GENERATOR * pow(eval_generator, index.bit_reverse().into()));
    };
    points
}
