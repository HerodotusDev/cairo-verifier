use cairo_verifier::common::bit_reverse::BitReverseTrait;

#[test]
#[available_gas(9999999999)]
fn test_bit_reverse_0() {
    let num: u64 = 0x0000000000000001;
    assert(num.bit_reverse().bit_reverse() == 0x0000000000000001, 'Invalid value')
}

#[test]
#[available_gas(9999999999)]
fn test_bit_reverse_1() {
    let num: u64 = 0xf045000ca9ff9261;
    assert(num.bit_reverse() == 0x8649ff953000a20f, 'Invalid value')
}

#[test]
#[available_gas(9999999999)]
fn test_bit_reverse_2() {
    let num: u64 = 0xabf8194012840122;
    assert(num.bit_reverse() == 0x4480214802981fd5, 'Invalid value')
}

#[test]
#[available_gas(9999999999)]
fn test_bit_reverse_3() {
    let num: u64 = 0xacc8194ff2340f22;
    assert(num.bit_reverse().bit_reverse() == 0xacc8194ff2340f22, 'Invalid value')
}
