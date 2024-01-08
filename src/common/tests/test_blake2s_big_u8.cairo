use cairo_verifier::common::blake2s_u8::blake2s;
use cairo_verifier::common::tests::test_blake2s_u8::{get_arr_v1, get_arr_v2};


#[test]
#[available_gas(9999999999)]
fn test_blake2s_v1_big() {
    assert(
        blake2s(
            get_arr_v1(16)
        ) == 0xc7fa21bb08b0bd19600ad212c0fa0f7ff332f415ae1527282a939406413299aa,
        'invalid hash (16)'
    );
    assert(
        blake2s(
            get_arr_v1(17)
        ) == 0x6acb015d7514d821091ec780120b89ba4663f65e6ff6588d458ef333fe8c8a39,
        'invalid hash (17)'
    );
    assert(
        blake2s(
            get_arr_v1(32)
        ) == 0x5651036b64f7affbe498f0409950e06a352bcae03f5a79b78fec58a4cebe10d5,
        'invalid hash (32)'
    );
    assert(
        blake2s(
            get_arr_v1(33)
        ) == 0x42d5eeff1aa4972630bcca469f37bbe8c2f8014937e28cbedbc671571d3eb87c,
        'invalid hash (33)'
    );
    assert(
        blake2s(
            get_arr_v1(250)
        ) == 0x33fc848fc73514d8bc3f338b23ba684d945081da37e5a8e490db5032eac34630,
        'invalid hash (250)'
    );
    assert(
        blake2s(
            get_arr_v1(272)
        ) == 0x1b5ad0d1b82600127a6add8e1cf604a075843c3d35bbe31d636fa071674c9432,
        'invalid hash (272)'
    );
}

#[test]
#[available_gas(9999999999)]
fn test_blake2s_v2_big() {
    assert(
        blake2s(
            get_arr_v2(16)
        ) == 0xdfe91aa5523f1df5e6549d98121e9bdbac4cbba4375e93d812ef487d0fe562f6,
        'invalid hash (16)'
    );
    assert(
        blake2s(
            get_arr_v2(17)
        ) == 0x49f2c2bb269d275a111a04c459c847838a0cf7c488d6366577a21f75620243e6,
        'invalid hash (17)'
    );
    assert(
        blake2s(
            get_arr_v2(32)
        ) == 0x83e9b2b70274d9198b6b77a1760ebacfd1f0fe232a0ed78f1c722e154ee72362,
        'invalid hash (32)'
    );
    assert(
        blake2s(
            get_arr_v2(33)
        ) == 0x93a7f68b8ea17374c11e1da719885513b598c4e191825fb584e399206c05ae15,
        'invalid hash (33)'
    );
    assert(
        blake2s(
            get_arr_v2(250)
        ) == 0xe4e6bd453ba2eb5a378d7933576dbf697b6d31cf38061c550ea36f6843a9bf43,
        'invalid hash (250)'
    );
    assert(
        blake2s(
            get_arr_v2(272)
        ) == 0x5906fef89f21466142323029000040f6c25be2ff87d581a8f752b94ad3662762,
        'invalid hash (272)'
    );
}
