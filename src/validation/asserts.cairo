use cairo_verifier::common::math::Felt252PartialOrd;

fn assert_in_range(x: felt252, min: felt252, max: felt252) {
    assert(min <= x, 'Value too small');
    assert(x < max, 'Value too large');
}
