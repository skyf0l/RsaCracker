use std::ops::{Add, AddAssign};

use rug::Integer;

/// Known parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    /// Cipher message.
    pub c: Option<Integer>,
    /// Modulus.
    pub n: Option<Integer>,
    /// Public exponent.
    pub e: Integer,
    /// Prime number p.
    pub p: Option<Integer>,
    /// Prime number q.
    pub q: Option<Integer>,
    /// dP or dmp1 CRT exponent. (d mod p-1)
    pub dp: Option<Integer>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    pub dq: Option<Integer>,
    /// Phi or Euler's totient function of n. (p-1)(q-1)
    pub phi: Option<Integer>,
    /// The sum of the two primes p and q.
    pub sum_pq: Option<Integer>,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            n: None,
            e: 65537.into(),
            c: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            phi: None,
            sum_pq: None,
        }
    }
}

impl Parameters {
    /// Create parameters from public key
    pub fn from_public_key(key: &[u8]) -> Option<Self> {
        Self::from_rsa_public_pem(key).or_else(|| Self::from_x509_public_pem(key))
    }

    /// Create parameters from rsa public key
    pub fn from_rsa_public_pem(key: &[u8]) -> Option<Self> {
        let public_key = openssl::rsa::Rsa::public_key_from_pem(key)
            .or_else(|_| openssl::rsa::Rsa::public_key_from_pem_pkcs1(key))
            .ok()?;

        Some(Self {
            n: Some(public_key.n().to_string().parse().unwrap()),
            e: public_key.e().to_string().parse().unwrap(),
            ..Default::default()
        })
    }

    /// Create parameters from x509 public key
    pub fn from_x509_public_pem(key: &[u8]) -> Option<Self> {
        let public_key = openssl::x509::X509::from_pem(key).unwrap();
        let rsa = public_key.public_key().ok()?.rsa().ok()?;

        Some(Self {
            n: Some(rsa.n().to_string().parse().unwrap()),
            e: rsa.e().to_string().parse().unwrap(),
            ..Default::default()
        })
    }

    /// Create parameters from private key
    pub fn from_private_key(key: &[u8], passphrase: &Option<String>) -> Option<Self> {
        Self::from_rsa_private_pem(key, passphrase).or_else(|| Self::from_x509_private_pem(key))
    }

    /// Create parameters from rsa private key
    pub fn from_rsa_private_pem(key: &[u8], passphrase: &Option<String>) -> Option<Self> {
        let private_key = openssl::rsa::Rsa::private_key_from_pem(key)
            .ok()
            .or_else(|| {
                openssl::rsa::Rsa::private_key_from_pem_passphrase(
                    key,
                    passphrase.as_ref()?.as_bytes(),
                )
                .ok()
            })?;

        Some(Self {
            n: Some(private_key.n().to_string().parse().unwrap()),
            e: private_key.e().to_string().parse().unwrap(),
            ..Default::default()
        })
    }

    /// Create parameters from x509 private key
    pub fn from_x509_private_pem(key: &[u8]) -> Option<Self> {
        let private_key = openssl::x509::X509::from_pem(key).unwrap();
        let rsa = private_key.public_key().ok()?.rsa().ok()?;

        Some(Self {
            n: Some(rsa.n().to_string().parse().unwrap()),
            e: rsa.e().to_string().parse().unwrap(),
            ..Default::default()
        })
    }
}

impl Add for Parameters {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out += rhs;
        out
    }
}

impl AddAssign for Parameters {
    fn add_assign(&mut self, rhs: Self) {
        if self.n.is_none() {
            self.n = rhs.n;
        }
        if self.e == 65537 {
            self.e = rhs.e;
        }
        if self.c.is_none() {
            self.c = rhs.c;
        }
        if self.p.is_none() {
            self.p = rhs.p;
        }
        if self.q.is_none() {
            self.q = rhs.q;
        }
        if self.dp.is_none() {
            self.dp = rhs.dp;
        }
        if self.dq.is_none() {
            self.dq = rhs.dq;
        }
        if self.phi.is_none() {
            self.phi = rhs.phi;
        }
        if self.sum_pq.is_none() {
            self.sum_pq = rhs.sum_pq;
        }
    }
}
