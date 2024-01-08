use cairo_verifier::common::blake2s_u8::{blake2s, truncated_blake2s, load32};

fn get_arr_v1(n: u32) -> Array<u8> {
    let mut arr = ArrayTrait::new();
    let mut i: u32 = 1;
    loop {
        arr.append((i % 256).try_into().unwrap());
        if i == 4 * n {
            break;
        }
        i += 1;
    };
    let mut out = ArrayTrait::new();
    i = 0;
    loop {
        out.append(*arr[4 * i]);
        out.append(*arr[4 * i + 1]);
        out.append(*arr[4 * i + 2]);
        out.append(*arr[4 * i + 3]);
        i += 1;
        if i == n {
            break;
        };
    };
    out
}

fn get_arr_v2(n: u32) -> Array<u8> {
    let mut arr = ArrayTrait::new();
    let mut s: u32 = 1;
    let mut i: u32 = 1;
    loop {
        s *= 17;
        s = s ^ i;
        s %= 256;
        arr.append(s.try_into().unwrap());
        if i == 4 * n {
            break;
        }
        i += 1;
    };
    let mut out = ArrayTrait::new();
    i = 0;
    loop {
        out.append(*arr[4 * i]);
        out.append(*arr[4 * i + 1]);
        out.append(*arr[4 * i + 2]);
        out.append(*arr[4 * i + 3]);
        i += 1;
        if i == n {
            break;
        };
    };
    out
}

#[test]
#[available_gas(9999999999)]
fn test_blake2s_v1() {
    assert(
        blake2s(
            get_arr_v1(1)
        ) == 0x035c8c55b225b3cad27dec93997fb528978127b9aa3c145c4308b8b6a4b0c7d4,
        'invalid hash (1)'
    );
    assert(
        blake2s(
            get_arr_v1(2)
        ) == 0x676da142c9e15751cf6c94e96ebc05925408612bbcf56437adf6fb21822fca4b,
        'invalid hash (2)'
    );
}

#[test]
#[available_gas(9999999999)]
fn test_blake2s_v2() {
    assert(
        blake2s(
            get_arr_v2(1)
        ) == 0x3becbdec8344113fbee53542a4ef696e97db25efb96cef60d2919bb4dd00ed3e,
        'invalid hash (1)'
    );
    assert(
        blake2s(
            get_arr_v2(2)
        ) == 0x5229f5d506302edae36f9cac3f5d176cd9b6aa8420da6d74d7956789099faf70,
        'invalid hash (2)'
    );
}

#[test]
#[available_gas(9999999999)]
fn test_truncated_blake2s() {
    let x = 1157029198022238202306346125123666191662554108005;
    let y = 129252051435949032402481343903845417193011527432;
    let out = truncated_blake2s(x, y);
    assert(out == 642191007116032514313255519742888271333651019057, 'invalid truncated_blake2s');
}
