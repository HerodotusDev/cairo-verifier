use core::integer::u32_wrapping_add;
use cairo_verifier::common::array_append::ArrayAppendTrait;
use cairo_verifier::common::flip_endianness::FlipEndiannessTrait;


fn blake2s(data: Array<u8>) -> u256 {
    let mut state = blake2s_init();
    state = blake2s_update(state, data);
    blake2s_final(state)
}

// A 160 LSB truncated version of blake2s.
// hash:
//   blake2s(x, y) & ~((1<<96) - 1).
fn truncated_blake2s(x: felt252, y: felt252) -> felt252 {
    let mut data = ArrayTrait::<u8>::new();
    data.append_big_endian(x);
    data.append_big_endian(y);

    // Truncate hash - convert value to felt, by taking the least significant 160 bits.
    let hash = blake2s(data).flip_endianness() % 0x10000000000000000000000000000000000000000;
    hash.try_into().unwrap()
}

// internals:

fn load32(p0: u8, p1: u8, p2: u8, p3: u8) -> u32 {
    let mut x: u32 = p3.into();
    x = x * 256 + p2.into();
    x = x * 256 + p1.into();
    x = x * 256 + p0.into();
    x
}

fn get_sigma(r: u32) -> Array<u32> {
    if r == 0 {
        array![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    } else if r == 1 {
        array![14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
    } else if r == 2 {
        array![11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4]
    } else if r == 3 {
        array![7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8]
    } else if r == 4 {
        array![9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13]
    } else if r == 5 {
        array![2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9]
    } else if r == 6 {
        array![12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11]
    } else if r == 7 {
        array![13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10]
    } else if r == 8 {
        array![6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5]
    } else { // r == 9
        array![10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
    }
}

fn rotr16(n: u32) -> u32 {
    n / 65536 + (n % 65536) * 65536
}

fn rotr12(n: u32) -> u32 {
    n / 4096 + (n % 4096) * 1048576
}

fn rotr8(n: u32) -> u32 {
    n / 256 + (n % 256) * 16777216
}

fn rotr7(n: u32) -> u32 {
    n / 128 + (n % 128) * 33554432
}

#[derive(Drop, Clone)]
struct blake2s_state {
    h: Array<u32>, // length: 8
    t0: u32,
    t1: u32,
    f0: u32,
    buf: Array<u8>, // length: 64
    buflen: u32,
}

fn blake2s_init() -> blake2s_state {
    let blake2s_IV = array![
        0x6A09E667 ^ 0x01010020, // xor (depth, fanout, digest_length)
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19
    ];
    let mut buf = ArrayTrait::new();
    let mut i = 0;
    loop {
        if i == 64 {
            break;
        }
        buf.append(0);
        i += 1;
    };

    blake2s_state { h: blake2s_IV, t0: 0, t1: 0, f0: 0, buf: buf, buflen: 0 }
}

fn blake2s_compress(mut s: blake2s_state, in: Array<u8>) -> blake2s_state {
    assert(in.len() == 64, 'in array must have length 64');

    let mut m: Array<u32> = ArrayTrait::new();

    let mut i: u32 = 0;
    loop {
        if i == 16 {
            break;
        }
        m.append(load32(*in[4 * i + 0], *in[4 * i + 1], *in[4 * i + 2], *in[4 * i + 3]));
        i += 1;
    };

    let mut v0: u32 = *s.h[0];
    let mut v1: u32 = *s.h[1];
    let mut v2: u32 = *s.h[2];
    let mut v3: u32 = *s.h[3];
    let mut v4: u32 = *s.h[4];
    let mut v5: u32 = *s.h[5];
    let mut v6: u32 = *s.h[6];
    let mut v7: u32 = *s.h[7];
    let mut v8: u32 = 0x6A09E667;
    let mut v9: u32 = 0xBB67AE85;
    let mut v10: u32 = 0x3C6EF372;
    let mut v11: u32 = 0xA54FF53A;
    let mut v12: u32 = s.t0 ^ 0x510E527F;
    let mut v13: u32 = s.t1 ^ 0x9B05688C;
    let mut v14: u32 = s.f0 ^ 0x1F83D9AB;
    let mut v15: u32 = 0x5BE0CD19; // f1 is always 0

    let m_span = m.span();

    let mut r = 0;
    loop {
        if r == 10 {
            break;
        }

        let sigma = get_sigma(r);

        // ROUND function begin

        let mut a = 0;
        let mut b = 0;
        let mut c = 0;
        let mut d = 0;
        let mut i = 0;
        loop {
            if i == 8 {
                break;
            }
            if i == 0 {
                a = v0;
                b = v4;
                c = v8;
                d = v12;
            } else if i == 1 {
                a = v1;
                b = v5;
                c = v9;
                d = v13;
            } else if i == 2 {
                a = v2;
                b = v6;
                c = v10;
                d = v14;
            } else if i == 3 {
                a = v3;
                b = v7;
                c = v11;
                d = v15;
            } else if i == 4 {
                a = v0;
                b = v5;
                c = v10;
                d = v15;
            } else if i == 5 {
                a = v1;
                b = v6;
                c = v11;
                d = v12;
            } else if i == 6 {
                a = v2;
                b = v7;
                c = v8;
                d = v13;
            } else if i == 7 {
                a = v3;
                b = v4;
                c = v9;
                d = v14;
            };

            // G function begin

            // a = a + b + m[sigma[r][2*i]]
            a = u32_wrapping_add(u32_wrapping_add(a, b), *m_span.at(*sigma[2 * i]));

            d = rotr16(d ^ a);

            // c = c + d
            c = u32_wrapping_add(c, d);

            b = rotr12(b ^ c);

            // a = a + b + m[sigma[r][2*i+1]]
            a = u32_wrapping_add(u32_wrapping_add(a, b), *m_span.at(*sigma[2 * i + 1]));

            d = rotr8(d ^ a);

            // c = c + d
            c = u32_wrapping_add(c, d);

            b = rotr7(b ^ c);

            // G function end

            if i == 0 {
                v0 = a;
                v4 = b;
                v8 = c;
                v12 = d;
            } else if i == 1 {
                v1 = a;
                v5 = b;
                v9 = c;
                v13 = d;
            } else if i == 2 {
                v2 = a;
                v6 = b;
                v10 = c;
                v14 = d;
            } else if i == 3 {
                v3 = a;
                v7 = b;
                v11 = c;
                v15 = d;
            } else if i == 4 {
                v0 = a;
                v5 = b;
                v10 = c;
                v15 = d;
            } else if i == 5 {
                v1 = a;
                v6 = b;
                v11 = c;
                v12 = d;
            } else if i == 6 {
                v2 = a;
                v7 = b;
                v8 = c;
                v13 = d;
            } else if i == 7 {
                v3 = a;
                v4 = b;
                v9 = c;
                v14 = d;
            };

            i += 1;
        };

        // ROUND function end

        r += 1;
    };

    let mut new_h = ArrayTrait::new();
    new_h.append((*s.h[0]) ^ v0 ^ v8);
    new_h.append((*s.h[1]) ^ v1 ^ v9);
    new_h.append((*s.h[2]) ^ v2 ^ v10);
    new_h.append((*s.h[3]) ^ v3 ^ v11);
    new_h.append((*s.h[4]) ^ v4 ^ v12);
    new_h.append((*s.h[5]) ^ v5 ^ v13);
    new_h.append((*s.h[6]) ^ v6 ^ v14);
    new_h.append((*s.h[7]) ^ v7 ^ v15);
    s.h = new_h;

    s
}

fn blake2s_update(mut s: blake2s_state, in: Array<u8>) -> blake2s_state {
    let mut in_len = in.len();
    let mut in_shift = 0;
    let in_span = in.span();
    if in_len != 0 {
        let left = s.buflen;
        let fill = 64 - left;
        if in_len > fill {
            s.buflen = 0;

            let mut new_buf = ArrayTrait::new();
            let buf_span = s.buf.span();
            let mut i: u32 = 0;
            loop {
                if i == left {
                    break;
                }
                new_buf.append(*buf_span.at(i));
                i += 1;
            };

            i = 0;
            loop {
                if i == fill {
                    break;
                }
                new_buf.append(*in_span[i]);
                i += 1;
            };

            // blake2s_increment_counter
            s.t0 = u32_wrapping_add(s.t0, 64_u32);
            if s.t0 < 64_u32 {
                s.t1 = u32_wrapping_add(s.t1, 1);
            }

            s = blake2s_compress(s, new_buf);

            in_shift += fill;
            in_len -= fill;

            loop {
                if in_len <= 64 {
                    break;
                }

                // blake2s_increment_counter
                s.t0 = u32_wrapping_add(s.t0, 64_u32);
                if s.t0 < 64_u32 {
                    s.t1 = u32_wrapping_add(s.t1, 1);
                }

                let mut compress_in = ArrayTrait::new();
                i = 0;
                loop {
                    if i == 64 {
                        break;
                    }
                    compress_in.append(*in_span[in_shift + i]);
                    i += 1;
                };

                s = blake2s_compress(s, compress_in);

                in_shift += 64;
                in_len -= 64;
            };
        }

        let mut new_buf = ArrayTrait::new();
        let buf_span = s.buf.span();
        let mut i = 0;
        loop {
            if i == s.buflen {
                break;
            }
            new_buf.append(*buf_span[i]);
            i += 1;
        };
        i = 0;
        loop {
            if i == in_len {
                break;
            }
            new_buf.append(*in_span[in_shift + i]);
            i += 1;
        };
        loop {
            if new_buf.len() == 64 {
                break;
            }
            new_buf.append(0);
        };
        s.buf = new_buf;
        s.buflen += in_len;
    }

    s
}

fn blake2s_final(mut s: blake2s_state) -> u256 {
    assert(s.f0 == 0, 'blake2s_is_lastblock');

    // blake2s_increment_counter 
    s.t0 = u32_wrapping_add(s.t0, s.buflen);
    if s.t0 < s.buflen {
        s.t1 = u32_wrapping_add(s.t1, 1);
    }

    s.f0 = 0xffffffff;

    let mut i = 0;
    let buf_span = s.buf.span();
    let mut buf = ArrayTrait::new();
    loop {
        if i == s.buflen {
            break;
        }
        buf.append(*buf_span[i]);
        i += 1;
    };
    loop {
        if i == 64 {
            break;
        }
        buf.append(0);
        i += 1;
    };

    s = blake2s_compress(s, buf);

    let mut result: u256 = 0;
    let mut multiplier: u256 = 1;
    i = 0;
    loop {
        result += (*s.h[i]).into() * multiplier;
        i += 1;
        if i == 8 {
            break;
        }
        multiplier *= 0x100000000;
    };

    result
}
