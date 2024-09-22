use base64::{engine::general_purpose, Engine};
use rug::Integer;
use std::{
    fmt::Display,
    ops::{Add, AddAssign},
    str::FromStr,
};

#[derive(Debug, Clone)]
/// Struct used to parse integers from different bases and formats
pub struct IntegerArg(pub Integer);

impl std::str::FromStr for IntegerArg {
    type Err = String;

    fn from_str(n: &str) -> Result<Self, Self::Err> {
        if let Some(n) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
            Ok(Self(
                Integer::from_str_radix(n, 16).or(Err("Invalid hex number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("0b").or_else(|| n.strip_prefix("0B")) {
            Ok(Self(
                Integer::from_str_radix(n, 2).or(Err("Invalid binary number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("0o").or_else(|| n.strip_prefix("0O")) {
            Ok(Self(
                Integer::from_str_radix(n, 8).or(Err("Invalid octal number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("b64").or_else(|| n.strip_prefix("B64")) {
            let bytes = general_purpose::STANDARD
                .decode(n.as_bytes())
                .or(Err("Invalid base64 number".to_string()))?;
            Ok(Self(Integer::from_digits(&bytes, rug::integer::Order::Msf)))
        } else {
            Ok(Self(
                Integer::from_str(n).or(Err("Invalid number".to_string()))?,
            ))
        }
    }
}

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
    /// Private exponent.
    pub d: Option<Integer>,
    /// Phi or Euler's totient function of n. (p-1)(q-1)
    pub phi: Option<Integer>,
    /// dP or dmp1 CRT exponent. (d mod p-1)
    pub dp: Option<Integer>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    pub dq: Option<Integer>,
    /// qInv or iqmp CRT coefficient. (q^-1 mod p)
    pub qinv: Option<Integer>,
    /// pInv or ipmq CRT coefficient. (p^-1 mod q)
    pub pinv: Option<Integer>,
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
            d: None,
            phi: None,
            dp: None,
            dq: None,
            qinv: None,
            pinv: None,
            sum_pq: None,
        }
    }
}

impl Display for Parameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();

        if let Some(n) = &self.n {
            s += &format!("n = {}\n", n);
        }
        s += &format!("e = {}\n", self.e);
        if let Some(c) = &self.c {
            s += &format!("c = {}\n", c);
        }
        if let Some(p) = &self.p {
            s += &format!("p = {}\n", p);
        }
        if let Some(q) = &self.q {
            s += &format!("q = {}\n", q);
        }
        if let Some(d) = &self.d {
            s += &format!("d = {}\n", d);
        }
        if let Some(phi) = &self.phi {
            s += &format!("phi = {}\n", phi);
        }
        if let Some(dp) = &self.dp {
            s += &format!("dp = {}\n", dp);
        }
        if let Some(dq) = &self.dq {
            s += &format!("dq = {}\n", dq);
        }
        if let Some(qinv) = &self.qinv {
            s += &format!("qinv = {}\n", qinv);
        }
        if let Some(pinv) = &self.pinv {
            s += &format!("pinv = {}\n", pinv);
        }
        if let Some(sum_pq) = &self.sum_pq {
            s += &format!("sum_pq = {}\n", sum_pq);
        }

        // Remove trailing newline
        if s.ends_with('\n') {
            s.pop();
        }

        write!(f, "{}", s)
    }
}

impl Parameters {
    /// Create parameters from raw file
    ///
    /// # Example
    ///
    /// ```
    /// // Example of a raw file
    /// n = 1
    /// # This is a comment
    /// e: 0x1
    /// C 0x00
    /// phi: 0x1
    /// ```
    pub fn from_raw(raw: &str) -> Self {
        let mut params = Self::default();

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            let (key, value) = if let Some(idx) = line.find(':') {
                let (key, value) = line.split_at(idx);
                (key.trim(), value[1..].trim())
            } else if let Some(idx) = line.find('=') {
                let (key, value) = line.split_at(idx);
                (key.trim(), value[1..].trim())
            } else {
                continue;
            };

            // Clean up key
            let key = key.replace("_", "").replace("-", "");

            let value = if let Ok(value) = IntegerArg::from_str(value) {
                value.0
            } else {
                eprintln!("Warning: Failed to parse {} value: {}", key, value);
                continue;
            };

            match key.to_lowercase().as_str() {
                "n" => params.n = Some(value),
                "e" => params.e = value,
                "c" => params.c = Some(value),
                "p" => params.p = Some(value),
                "q" => params.q = Some(value),
                "d" => params.d = Some(value),
                "phi" => params.phi = Some(value),
                "dp" | "dmp1" => params.dp = Some(value),
                "dq" | "dmq1" => params.dq = Some(value),
                "qinv" | "iqmp" => params.qinv = Some(value),
                "pinv" | "ipmq" => params.pinv = Some(value),
                "sumpq" => params.sum_pq = Some(value),
                _ => {}
            }
        }

        params
    }

    /// Create parameters from public key
    pub fn from_public_key(key: &[u8]) -> Option<Self> {
        Self::from_rsa_public_key(key)
            .or_else(|| Self::from_x509_cert(key))
            .or_else(|| Self::from_openssh_public_key(key))
    }

    /// Create parameters from rsa public key
    pub fn from_rsa_public_key(key: &[u8]) -> Option<Self> {
        let public_key = openssl::pkey::PKey::public_key_from_pem(key)
            .or_else(|_| openssl::pkey::PKey::public_key_from_der(key))
            .or_else(|_| {
                // RSA der pkcs1 are not decoded by the `PKey::public_key_from_der` function
                openssl::rsa::Rsa::public_key_from_der_pkcs1(key)
                    .map(|rsa| openssl::pkey::PKey::from_rsa(rsa).unwrap())
            })
            .ok()?;
        let rsa = public_key.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from x509 certificate
    pub fn from_x509_cert(key: &[u8]) -> Option<Self> {
        let cert = openssl::x509::X509::from_pem(key)
            .or_else(|_| openssl::x509::X509::from_der(key))
            .ok()?;
        let rsa = cert.public_key().ok()?.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from openssh public key
    pub fn from_openssh_public_key(key: &[u8]) -> Option<Self> {
        let public_key = ssh_key::public::PublicKey::from_bytes(key)
            .ok()
            .or_else(|| {
                if let Ok(key) = String::from_utf8(key.to_vec()) {
                    ssh_key::public::PublicKey::from_openssh(&key).ok()
                } else {
                    None
                }
            })?;
        let rsa = public_key.key_data().rsa()?;

        Some(Self {
            n: Some(Integer::from_digits(
                rsa.n.as_bytes(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(rsa.e.as_bytes(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from private key
    pub fn from_private_key(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        Self::from_rsa_private_key(key, passphrase)
            .or_else(|| Self::from_openssh_private_key(key, passphrase))
    }

    /// Create parameters from rsa private key
    pub fn from_rsa_private_key(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        let private_key = openssl::pkey::PKey::private_key_from_der(key)
            .or_else(|_| {
                if let Some(passphrase) = passphrase {
                    openssl::pkey::PKey::private_key_from_pkcs8_passphrase(
                        key,
                        passphrase.as_bytes(),
                    )
                    .or_else(|_| {
                        openssl::pkey::PKey::private_key_from_pem_passphrase(
                            key,
                            passphrase.as_bytes(),
                        )
                    })
                } else {
                    openssl::pkey::PKey::private_key_from_pkcs8(key)
                        .or_else(|_| openssl::pkey::PKey::private_key_from_pem(key))
                }
            })
            .map_err(|e| {
                e.errors().first().map(|e| {
                    if e.reason() == Some("bad decrypt") {
                        panic!("Failed to decrypt private key")
                    }
                })
            })
            .ok()?;
        let rsa = private_key.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            p: rsa
                .p()
                .map(|n| Integer::from_digits(&n.to_vec(), rug::integer::Order::Msf)),
            q: rsa
                .q()
                .map(|n| Integer::from_digits(&n.to_vec(), rug::integer::Order::Msf)),
            ..Default::default()
        })
    }

    /// Create parameters from openssh private key
    pub fn from_openssh_private_key(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        let mut private_key = ssh_key::private::PrivateKey::from_openssh(key)
            .or_else(|_| ssh_key::private::PrivateKey::from_bytes(key))
            .ok()?;
        let rsa = if private_key.key_data().is_encrypted() {
            if let Some(passphrase) = passphrase {
                private_key = private_key
                    .decrypt(passphrase)
                    .expect("Failed to decrypt private key");
                private_key.key_data().rsa()?
            } else {
                eprintln!("Warning: Private key is encrypted, but no passphrase was provided, only n and e will be extracted");
                let public_rsa = private_key.public_key().key_data().rsa()?;
                return Some(Self {
                    n: Some(Integer::from_digits(
                        public_rsa.n.as_bytes(),
                        rug::integer::Order::Msf,
                    )),
                    e: Integer::from_digits(public_rsa.e.as_bytes(), rug::integer::Order::Msf),
                    ..Default::default()
                });
            }
        } else {
            private_key.key_data().rsa()?
        };

        Some(Self {
            n: Some(Integer::from_digits(
                rsa.public.n.as_bytes(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(rsa.public.e.as_bytes(), rug::integer::Order::Msf),
            p: Some(Integer::from_digits(
                rsa.private.p.as_bytes(),
                rug::integer::Order::Msf,
            )),
            q: Some(Integer::from_digits(
                rsa.private.q.as_bytes(),
                rug::integer::Order::Msf,
            )),
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

impl<'a> Add<&'a Parameters> for Parameters {
    type Output = Self;

    fn add(mut self, rhs: &'a Parameters) -> Self::Output {
        self += rhs.clone();
        self
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
        if self.d.is_none() {
            self.d = rhs.d;
        }
        if self.phi.is_none() {
            self.phi = rhs.phi;
        }
        if self.dp.is_none() {
            self.dp = rhs.dp;
        }
        if self.dq.is_none() {
            self.dq = rhs.dq;
        }
        if self.qinv.is_none() {
            self.qinv = rhs.qinv;
        }
        if self.pinv.is_none() {
            self.pinv = rhs.pinv;
        }
        if self.sum_pq.is_none() {
            self.sum_pq = rhs.sum_pq;
        }
    }
}
