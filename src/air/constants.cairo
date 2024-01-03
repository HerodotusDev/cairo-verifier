// Recursive layout
const N_DYNAMIC_PARAMS: felt252 = 0;
const N_CONSTRAINTS: felt252 = 93;
const MASK_SIZE: felt252 = 133;
const PUBLIC_MEMORY_STEP: felt252 = 16;
const HAS_DILUTED_POOL: felt252 = 1;
const DILUTED_SPACING: felt252 = 4;
const DILUTED_N_BITS: felt252 = 16;
const PEDERSEN_BUILTIN_RATIO: felt252 = 128;
const PEDERSEN_BUILTIN_REPETITIONS: felt252 = 1;
const RC_BUILTIN_RATIO: felt252 = 8;
const RC_N_PARTS: felt252 = 8;
const BITWISE_RATIO: felt252 = 8;
const BITWISE_TOTAL_N_BITS: felt252 = 251;
const HAS_OUTPUT_BUILTIN: felt252 = 1;
const HAS_PEDERSEN_BUILTIN: felt252 = 1;
const HAS_RANGE_CHECK_BUILTIN: felt252 = 1;
const HAS_ECDSA_BUILTIN: felt252 = 0;
const HAS_BITWISE_BUILTIN: felt252 = 1;
const HAS_EC_OP_BUILTIN: felt252 = 0;
const HAS_KECCAK_BUILTIN: felt252 = 0;
const HAS_POSEIDON_BUILTIN: felt252 = 0;
const LAYOUT_CODE: felt252 = 0x726563757273697665;
const CONSTRAINT_DEGREE: felt252 = 2;
const CPU_COMPONENT_HEIGHT: felt252 = 16;
const LOG_CPU_COMPONENT_HEIGHT: felt252 = 4;
const MEMORY_STEP: felt252 = 2;
const NUM_COLUMNS_FIRST: felt252 = 7;
const NUM_COLUMNS_SECOND: felt252 = 3;
const IS_DYNAMIC_AIR: felt252 = 0;

mod segments {
    const PROGRAM: usize = 0;
    const EXECUTION: usize = 1;
    const OUTPUT: usize = 2;
    const PEDERSEN: usize = 3;
    const RANGE_CHECK: usize = 4;
    const BITWISE: usize = 5;
    const N_SEGMENTS: usize = 6;
}

// Pedersen builtin
const SHIFT_POINT_X: felt252 = 0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804;
const SHIFT_POINT_Y: felt252 = 0x3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a;

const SECURITY_BITS: felt252 = 128;
const MAX_ADDRESS: felt252 = 0xffffffffffffffff;
const INITIAL_PC: felt252 = 1;

fn get_builtins() -> Array<felt252> {
    array!['output', 'pedersen', 'range_check', 'bitwise']
}
