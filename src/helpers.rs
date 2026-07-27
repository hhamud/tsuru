use std::ops::{Add, Mul};

const POW10: [u32; 7] = [1, 10, 100, 1000, 10_000, 100_000, 1_000_000];

#[inline]
pub fn push_n<const N: usize>(buf: &mut Vec<u8>, n: u32) {
    let mut rem = n;
    let mut div = POW10[N - 1];
    let mut i = 0;

    while i < N {
        let digit = rem / div;
        buf.push(b'0' + digit as u8);
        rem %= div;
        div /= 10;
        i += 1;
    }
}

#[inline]
pub fn parse_decimals<T>(bytes: &[u8]) -> T
where
    T: From<u8> + Mul<Output = T> + Add<Output = T> + Copy,
{
    let mut val = T::from(0);
    for &b in bytes {
        val = val * T::from(10) + T::from(b - b'0');
    }
    val
}

#[inline]
pub fn push_u32(buf: &mut Vec<u8>, mut n: u32) {
    if n == 0 {
        buf.push(b'0');
        return;
    }

    let mut tmp = [0u8; 10];
    let mut len = 0;

    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }

    // Append digits in correct order (without leading zeros)
    for i in (0..len).rev() {
        buf.push(tmp[i]);
    }
}
