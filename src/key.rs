use openssl::rsa::RsaPrivateKeyBuilder;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use rug::{
    integer::{IsPrime, Order},
    ops::Pow,
    Integer,
};

use crate::{factors::Factors, ntheory::crt};

/// Attack error
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Factors are not prime numbers
    #[error("factors are not prime numbers: {0:?}")]
    FactorsAreNotPrimeNumbers(Factors),
    /// Private exponent computation failed
    #[error("private exponent computation failed")]
    PrivateExponentComputationFailed,
}

/// RSA private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    /// Modulus.
    pub n: Integer,
    /// Public exponent.
    pub e: Integer,
    /// Factors.
    pub factors: Factors,
    /// Private exponent.
    pub d: Integer,
}

impl PrivateKey {
    /// Create private key from p and q
    pub fn from_p_q(
        p: impl Into<Integer>,
        q: impl Into<Integer>,
        e: impl Into<Integer>,
    ) -> Result<Self, KeyError> {
        Self::from_factors([Into::<Integer>::into(p), Into::<Integer>::into(q)], e)
    }

    /// Create private key from multiple factors
    pub fn from_factors(
        factors: impl Into<Factors>,
        e: impl Into<Integer>,
    ) -> Result<Self, KeyError> {
        let factors = Into::<Factors>::into(factors);
        let e = Into::<Integer>::into(e);

        // Check if factors are prime numbers
        if factors
            .factors()
            .iter()
            .any(|f| f.is_probably_prime(100) == IsPrime::No)
        {
            return Err(KeyError::FactorsAreNotPrimeNumbers(factors));
        }

        let n: Integer = factors.product();
        let d = e
            .clone()
            .invert(&factors.phi())
            .or(Err(KeyError::PrivateExponentComputationFailed))?;

        Ok(Self { n, e, factors, d })
    }

    /// Decrypt cipher message
    pub fn decrypt(&self, c: &Integer) -> Integer {
        // Fast decryption using CRT
        // See <https://exploringnumbertheory.wordpress.com/2015/11/16/speeding-up-modular-exponentiation-using-crt>

        let phis = self.factors.phis();
        // Calculate associated factors for all phis
        let factors = self
            .factors
            .0
            .iter()
            .map(|(f, p)| f.clone().pow(*p as u32))
            .collect::<Vec<_>>();

        // Calculate residues c^(d mod phi) mod p for all factors
        // This can take a while for large factors, so we parallelize it
        let p = factors
            .par_iter()
            .zip(phis.into_par_iter())
            .map(|(f, phi)| c.clone().pow_mod(&(&self.d % phi), f).unwrap())
            .collect::<Vec<_>>();

        crt(&p, &factors).unwrap()
    }

    /// Returns P factor
    pub fn p(&self) -> Integer {
        self.factors[0].clone()
    }

    /// Returns Q factor
    pub fn q(&self) -> Integer {
        self.factors[1].clone()
    }

    /// Returns phi(n) or totient
    pub fn phi(&self) -> Integer {
        self.factors.phi()
    }

    /// Returns dP or dmp1 CRT exponent. (d mod p-1)
    pub fn dp(&self) -> Integer {
        self.d.clone() % (self.p() - 1)
    }

    /// Returns dQ or dmq1 CRT exponent. (d mod q-1)
    pub fn dq(&self) -> Integer {
        self.d.clone() % (self.q() - 1)
    }

    /// Returns qInv or iqmp CRT exponent. (q^-1 mod p)
    pub fn qinv(&self) -> Integer {
        self.q().invert(&self.p()).unwrap()
    }

    /// Returns pInv or ipmq CRT exponent. (p^-1 mod q)
    pub fn pinv(&self) -> Integer {
        self.p().invert(&self.q()).unwrap()
    }

    /// Convert to PEM format
    pub fn to_pem(&self, passphrase: &Option<String>) -> Option<String> {
        if self.factors.len() != 2 {
            panic!("Only keys with two factors can be converted to PEM format");
        }

        let rsa = RsaPrivateKeyBuilder::new(
            openssl::bn::BigNum::from_slice(&self.n.to_digits(Order::Msf)).unwrap(),
            openssl::bn::BigNum::from_slice(&self.e.to_digits(Order::Msf)).unwrap(),
            openssl::bn::BigNum::from_slice(&self.d.to_digits(Order::Msf)).unwrap(),
        )
        .ok()?
        .set_factors(
            openssl::bn::BigNum::from_slice(&self.p().to_digits(Order::Msf)).unwrap(),
            openssl::bn::BigNum::from_slice(&self.q().to_digits(Order::Msf)).unwrap(),
        )
        .ok()?
        .set_crt_params(
            openssl::bn::BigNum::from_slice(&self.dp().to_digits(Order::Msf)).unwrap(),
            openssl::bn::BigNum::from_slice(&self.dq().to_digits(Order::Msf)).unwrap(),
            openssl::bn::BigNum::from_slice(&self.qinv().to_digits(Order::Msf)).unwrap(),
        )
        .ok()?
        .build();

        if let Some(passphrase) = passphrase {
            rsa.private_key_to_pem_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                passphrase.as_bytes(),
            )
            .ok()
            .map(|pem| String::from_utf8(pem).unwrap())
        } else {
            rsa.private_key_to_pem()
                .ok()
                .map(|pem| String::from_utf8(pem).unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{bytes_to_integer, Factors};

    use super::*;

    #[test]
    fn decrypt_from_two_factors() {
        let m = bytes_to_integer(b"RsaCracker!");
        let e = Integer::from(65537);
        let factors = Factors::from([
            Integer::from_str(
                "112219243609243706223486619551298085362360091408633161457003404046681540344297",
            )
            .unwrap(),
            Integer::from_str(
                "64052533192509995760322742160163582601357132095571262796409705234000154367147",
            )
            .unwrap(),
        ]);
        let c = m.clone().pow_mod(&e, &factors.product()).unwrap();

        let pk = PrivateKey::from_factors(factors, e).unwrap();
        assert_eq!(m, pk.decrypt(&c));
    }

    #[test]
    fn decrypt_from_many_factors() {
        let m = bytes_to_integer(b"RsaCracker!");
        let e = Integer::from(65537);
        // First 30 primes
        let factors = Factors::from([
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109,
        ]);
        let c = m.clone().pow_mod(&e, &factors.product()).unwrap();

        let pk = PrivateKey::from_factors(factors, e).unwrap();
        assert_eq!(m, pk.decrypt(&c));
    }

    #[test]
    fn decrypt_from_many_duplicated_factors() {
        let m = bytes_to_integer(b"RsaCracker!");
        let e = Integer::from(65537);
        // 50 random primes between the 50th and 100th prime numbers, including duplicates
        let factors = Factors::from([
            229, 229, 229, 233, 233, 233, 233, 239, 239, 239, 241, 251, 257, 263, 263, 269, 269,
            269, 277, 277, 281, 283, 293, 293, 307, 307, 307, 317, 317, 331, 331, 331, 337, 347,
            347, 347, 349, 349, 353, 353, 367, 373, 379, 383, 389, 401, 409, 409, 409, 409,
        ]);
        let c = m.clone().pow_mod(&e, &factors.product()).unwrap();

        let pk = PrivateKey::from_factors(factors, e).unwrap();
        assert_eq!(m, pk.decrypt(&c));
    }

    #[test]
    fn decrypt_from_single_duplicated_factors() {
        let m = bytes_to_integer(b"RsaCracker!");
        let e = Integer::from(65537);
        let factors = Factors::from([409; 50]);
        let c = m.clone().pow_mod(&e, &factors.product()).unwrap();

        let pk = PrivateKey::from_factors(factors, e).unwrap();
        assert_eq!(m, pk.decrypt(&c));
    }
}
