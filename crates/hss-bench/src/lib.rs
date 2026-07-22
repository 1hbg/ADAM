//! A measurement-only implementation of the MORSE algorithms from
//! arXiv:2410.06514. It has not been audited and must not protect real data.

use anyhow::{anyhow, ensure, Result};
use rand::{thread_rng, RngCore};
use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};

pub const N_BITS: u32 = 3072;
pub const ALPHA_BITS: u32 = 512;
pub const STATISTICAL_BITS: u32 = 128;
pub const CIPHERTEXT_BYTES: usize = (N_BITS as usize / 8) * 2;
pub const INTEGER_BYTES: usize = N_BITS as usize / 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub n: Integer,
    pub n2: Integer,
    pub h: Integer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMaterial {
    pub public: PublicKey,
    pub alpha: Integer,
}

fn random_exact_bits(bits: u32) -> Integer {
    let mut bytes = vec![0_u8; bits.div_ceil(8) as usize];
    thread_rng().fill_bytes(&mut bytes);
    if let Some(last) = bytes.last_mut() {
        *last |= 1 << ((bits - 1) % 8);
    }
    Integer::from_digits(&bytes, Order::Lsf)
}

fn random_bitstring(bits: u32) -> Integer {
    let mut bytes = vec![0_u8; bits.div_ceil(8) as usize];
    thread_rng().fill_bytes(&mut bytes);
    Integer::from_digits(&bytes, Order::Lsf)
}

fn random_below(bound: &Integer) -> Integer {
    let bits = bound.significant_bits();
    loop {
        let mut bytes = vec![0_u8; bits.div_ceil(8) as usize];
        thread_rng().fill_bytes(&mut bytes);
        if !bits.is_multiple_of(8) {
            *bytes.last_mut().expect("nonempty bound") &= (1 << (bits % 8)) - 1;
        }
        let candidate = Integer::from_digits(&bytes, Order::Lsf);
        if candidate > 0 && &candidate < bound {
            return candidate;
        }
    }
}

fn structured_prime(small: &Integer) -> Integer {
    loop {
        let mut cofactor = random_exact_bits((N_BITS / 2) - ALPHA_BITS / 2 - 1);
        cofactor.set_bit(0, true);
        let candidate: Integer = Integer::from(2) * small * cofactor + 1;
        if candidate.significant_bits() == N_BITS / 2
            && candidate.is_probably_prime(25) != rug::integer::IsPrime::No
        {
            return candidate;
        }
    }
}

/// Generates the structured FastPaillier modulus from MORSE §III-A.
/// This is deliberately outside timed regions and can take several minutes.
pub fn keygen() -> KeyMaterial {
    loop {
        let mut p = random_exact_bits(ALPHA_BITS / 2);
        p.set_bit(0, true);
        p.next_prime_mut();
        let mut q = random_exact_bits(ALPHA_BITS / 2);
        q.set_bit(0, true);
        q.next_prime_mut();
        let big_p = structured_prime(&p);
        let big_q = structured_prime(&q);
        if Integer::from(&big_p - 1).gcd(&Integer::from(&big_q - 1)) != 2 {
            continue;
        }
        let n = Integer::from(&big_p * &big_q);
        if n.significant_bits() != N_BITS {
            continue;
        }
        let alpha = Integer::from(&p * &q);
        let p_minus_one = Integer::from(&big_p - 1);
        let q_minus_one = Integer::from(&big_q - 1);
        let denominator = Integer::from(4 * &alpha);
        let beta: Integer = (p_minus_one * q_minus_one) / denominator;
        if alpha.clone().gcd(&beta) != 1 {
            continue;
        }
        let y = loop {
            let candidate = random_below(&n);
            if candidate.clone().gcd(&n) == 1 {
                break candidate;
            }
        };
        let two_beta: Integer = 2 * beta;
        let y_term = y.pow_mod(&two_beta, &n).expect("positive modulus");
        let h = (-y_term).modulo(&n);
        let n2 = Integer::from(&n * &n);
        return KeyMaterial {
            public: PublicKey { n, n2, h },
            alpha,
        };
    }
}

pub fn encrypt(pk: &PublicKey, message: &Integer) -> Integer {
    let r = random_bitstring(ALPHA_BITS);
    encrypt_with_randomizer(pk, message, &r)
}

pub fn encrypt_with_randomizer(pk: &PublicKey, message: &Integer, r: &Integer) -> Integer {
    let randomizer =
        pk.h.clone()
            .pow_mod(r, &pk.n)
            .expect("positive modulus")
            .pow_mod(&pk.n, &pk.n2)
            .expect("positive modulus");
    let gm = Integer::from(1 + &pk.n)
        .pow_mod(&message.clone().modulo(&pk.n), &pk.n2)
        .expect("positive modulus");
    (gm * randomizer).modulo(&pk.n2)
}

pub fn decrypt(keys: &KeyMaterial, ciphertext: &Integer) -> Integer {
    let two_alpha = Integer::from(2 * &keys.alpha);
    let u = ciphertext
        .clone()
        .pow_mod(&two_alpha, &keys.public.n2)
        .expect("positive modulus");
    let l: Integer = (u - 1) / &keys.public.n;
    let inverse = two_alpha.invert(&keys.public.n).expect("invertible key");
    (l * inverse).modulo(&keys.public.n)
}

/// OSY21/MORSE perfectly-correct distributed discrete-log conversion.
pub fn ddlog(n: &Integer, g: &Integer) -> Integer {
    let h = Integer::from(g % n);
    let h_prime = Integer::from(g / n);
    let inverse = h.clone().invert(n).expect("ciphertext is in Z*_N");
    (h_prime * inverse).modulo(n)
}

pub fn pow_signed(base: &Integer, exponent: &Integer, modulus: &Integer) -> Integer {
    if exponent >= &Integer::from(0) {
        base.clone()
            .pow_mod(exponent, modulus)
            .expect("positive modulus")
    } else {
        let inverse = base.clone().invert(modulus).expect("invertible base");
        inverse
            .pow_mod(&Integer::from(-exponent), modulus)
            .expect("positive modulus")
    }
}

pub fn split(value: &Integer, extra_bits: u32) -> (Integer, Integer) {
    let share1 = random_exact_bits(value.significant_bits() + extra_bits);
    let share0 = Integer::from(&share1 - value);
    (share0, share1)
}

pub fn smul_party(pk: &PublicKey, ciphertext: &Integer, share: &Integer) -> Integer {
    let divisive = pow_signed(ciphertext, share, &pk.n2);
    ddlog(&pk.n, &divisive)
}

pub fn encode_fixed(value: &Integer, width: usize) -> Result<Vec<u8>> {
    let mut bytes = value.to_digits::<u8>(Order::MsfBe);
    ensure!(
        bytes.len() <= width,
        "integer does not fit fixed-width encoding"
    );
    let mut output = vec![0; width - bytes.len()];
    output.append(&mut bytes);
    Ok(output)
}

pub fn decode_fixed(bytes: &[u8]) -> Integer {
    Integer::from_digits(bytes, Order::MsfBe)
}

pub fn validate(keys: &KeyMaterial) -> Result<()> {
    ensure!(
        keys.public.n.significant_bits() == N_BITS,
        "N is not 3072 bits"
    );
    for value in [0_u32, 1, 42, 65_537] {
        let message = Integer::from(value);
        let recovered = decrypt(keys, &encrypt(&keys.public, &message));
        if recovered != message {
            return Err(anyhow!("FastPaillier round trip failed for {value}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddlog_recovers_difference() {
        let n = Integer::from(143);
        let n2 = Integer::from(&n * &n);
        let g0 = Integer::from(7);
        let x = Integer::from(12);
        let g1 = (&g0 * Integer::from(1 + &n).pow_mod(&x, &n2).unwrap()).modulo(&n2);
        assert_eq!((ddlog(&n, &g1) - ddlog(&n, &g0)).modulo(&n), x);
    }

    #[test]
    fn fixed_width_round_trip() {
        let value = Integer::from(123_456);
        let encoded = encode_fixed(&value, 384).unwrap();
        assert_eq!(encoded.len(), 384);
        assert_eq!(decode_fixed(&encoded), value);
    }
}
