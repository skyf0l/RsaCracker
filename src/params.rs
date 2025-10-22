use base64::{engine::general_purpose, Engine};
use rug::Integer;
use std::{
    fmt::Display,
    ops::{Add, AddAssign},
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Orientation of the known digits (where the ? run sits)
pub enum Orientation {
    /// MSB known (trailing wildcards): ???? appears at the end
    MsbKnown,
    /// LSB known (leading wildcards): ???? appears at the start
    LsbKnown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents a partial prime with known and unknown digits
pub enum PartialPrime {
    /// Full prime value is known
    Full(Integer),
    /// Partial prime with wildcards (? or ...)
    Partial {
        /// The radix/base: 2 (0b), 8 (0o), 10 (default), 16 (0x)
        radix: u32,
        /// Count of ? digits in that radix (None for ellipsis, inferred from N)
        k: Option<usize>,
        /// Where the wildcard run sits (start = LsbKnown, end = MsbKnown)
        orient: Orientation,
        /// The known digit run parsed in that radix
        known: Integer,
    },
}

impl PartialPrime {
    /// Returns the known value if this is a full prime
    pub fn full(&self) -> Option<&Integer> {
        match self {
            PartialPrime::Full(n) => Some(n),
            _ => None,
        }
    }

    /// Returns true if this is a partial prime
    pub fn is_partial(&self) -> bool {
        !matches!(self, PartialPrime::Full(_))
    }
}

#[derive(Debug, Clone)]
/// Struct used to parse integers from different bases and formats
pub struct IntegerArg(pub Integer);

impl std::str::FromStr for IntegerArg {
    type Err = String;

    fn from_str(n: &str) -> Result<Self, Self::Err> {
        if let Some(n) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
            // Check for wildcards in hex numbers
            if n.contains('?') {
                return Err("Use PartialPrimeArg for wildcard numbers".to_string());
            }
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

#[derive(Debug, Clone)]
/// Struct used to parse partial primes with wildcards
pub struct PartialPrimeArg(pub PartialPrime);

impl std::str::FromStr for PartialPrimeArg {
    type Err = String;

    fn from_str(n: &str) -> Result<Self, Self::Err> {
        // Check for wildcards and ellipsis
        let has_wildcards = n.contains('?');
        let has_ellipsis = n.contains("...");

        if has_wildcards && has_ellipsis {
            return Err("Cannot mix ? wildcards and ellipsis (...)".to_string());
        }

        if !has_wildcards && !has_ellipsis {
            // No wildcards - try parsing as regular integer
            if let Ok(IntegerArg(num)) = IntegerArg::from_str(n) {
                return Ok(Self(PartialPrime::Full(num)));
            }
            return Err("Invalid number".to_string());
        }

        if has_ellipsis {
            // Has ellipsis - parse ellipsis-based partial
            if let Some(s) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                Self::parse_with_ellipsis(s, 16)
            } else if let Some(s) = n.strip_prefix("0b").or_else(|| n.strip_prefix("0B")) {
                Self::parse_with_ellipsis(s, 2)
            } else if let Some(s) = n.strip_prefix("0o").or_else(|| n.strip_prefix("0O")) {
                Self::parse_with_ellipsis(s, 8)
            } else {
                // Default to decimal (radix 10)
                Self::parse_with_ellipsis(n, 10)
            }
        } else {
            // Has wildcards - determine radix based on prefix
            // Bases: 0b→2, 0o→8, 0x→16; otherwise 10
            if let Some(s) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                Self::parse_with_wildcards(s, 16)
            } else if let Some(s) = n.strip_prefix("0b").or_else(|| n.strip_prefix("0B")) {
                Self::parse_with_wildcards(s, 2)
            } else if let Some(s) = n.strip_prefix("0o").or_else(|| n.strip_prefix("0O")) {
                Self::parse_with_wildcards(s, 8)
            } else {
                // Default to decimal (radix 10)
                Self::parse_with_wildcards(n, 10)
            }
        }
    }
}

impl PartialPrimeArg {
    fn parse_with_ellipsis(s: &str, radix: u32) -> Result<Self, String> {
        // Check if ellipsis is at start or end
        let starts_with_ellipsis = s.starts_with("...");
        let ends_with_ellipsis = s.ends_with("...");

        if starts_with_ellipsis && ends_with_ellipsis {
            return Err("Ellipsis must be either at start or end, not both".to_string());
        }

        if !starts_with_ellipsis && !ends_with_ellipsis {
            return Err("Ellipsis not found".to_string());
        }

        // Count ellipsis occurrences - should be exactly one run
        let ellipsis_count = s.matches("...").count();
        if ellipsis_count > 1 {
            return Err("Only one ellipsis run is allowed".to_string());
        }

        if starts_with_ellipsis {
            // LSB known (ellipsis at start means MSB is unknown)
            let known_part = &s[3..]; // "..." is 3 bytes
            if known_part.is_empty() {
                return Err("Must have some known digits after ellipsis".to_string());
            }
            let known = Integer::from_str_radix(known_part, radix as i32).or(Err(format!(
                "Invalid number in known part (radix {})",
                radix
            )))?;
            Ok(Self(PartialPrime::Partial {
                radix,
                k: None,
                orient: Orientation::LsbKnown,
                known,
            }))
        } else {
            // MSB known (ellipsis at end means LSB is unknown)
            let known_part = &s[..s.len() - 3]; // "..." is 3 bytes
            if known_part.is_empty() {
                return Err("Must have some known digits before ellipsis".to_string());
            }
            let known = Integer::from_str_radix(known_part, radix as i32).or(Err(format!(
                "Invalid number in known part (radix {})",
                radix
            )))?;
            Ok(Self(PartialPrime::Partial {
                radix,
                k: None,
                orient: Orientation::MsbKnown,
                known,
            }))
        }
    }

    fn parse_with_wildcards(s: &str, radix: u32) -> Result<Self, String> {
        // Count leading wildcards (LSB unknown)
        let leading_wildcards = s.chars().take_while(|&c| c == '?').count();
        // Count trailing wildcards (MSB unknown)
        let trailing_wildcards = s.chars().rev().take_while(|&c| c == '?').count();

        if leading_wildcards > 0 && trailing_wildcards > 0 {
            return Err("Wildcards must be either leading or trailing, not both".to_string());
        }

        if leading_wildcards > 0 {
            // LSB known: leading wildcards mean high digits are unknown
            let known_part = &s[leading_wildcards..];
            if known_part.is_empty() {
                return Err("Must have some known digits".to_string());
            }
            if known_part.contains('?') {
                return Err("Wildcards must be contiguous (leading or trailing only)".to_string());
            }
            let known = Integer::from_str_radix(known_part, radix as i32).or(Err(format!(
                "Invalid number in known part (radix {})",
                radix
            )))?;
            Ok(Self(PartialPrime::Partial {
                radix,
                k: Some(leading_wildcards),
                orient: Orientation::LsbKnown,
                known,
            }))
        } else if trailing_wildcards > 0 {
            // MSB known: trailing wildcards mean low digits are unknown
            let known_part = &s[..s.len() - trailing_wildcards];
            if known_part.is_empty() {
                return Err("Must have some known digits".to_string());
            }
            if known_part.contains('?') {
                return Err("Wildcards must be contiguous (leading or trailing only)".to_string());
            }
            let known = Integer::from_str_radix(known_part, radix as i32).or(Err(format!(
                "Invalid number in known part (radix {})",
                radix
            )))?;
            Ok(Self(PartialPrime::Partial {
                radix,
                k: Some(trailing_wildcards),
                orient: Orientation::MsbKnown,
                known,
            }))
        } else {
            // Both are 0 but string contains wildcards - must be non-contiguous
            Err("Wildcards must be contiguous (leading or trailing only)".to_string())
        }
    }
}

/// A single key entry for multi-key attacks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// Cipher message for this key.
    pub c: Option<Integer>,
    /// Modulus.
    pub n: Option<Integer>,
    /// Public exponent.
    pub e: Integer,
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
    /// The difference of the two primes p and q.
    pub diff_pq: Option<Integer>,
    /// Partial prime p (with wildcards).
    pub partial_p: Option<PartialPrime>,
    /// Partial prime q (with wildcards).
    pub partial_q: Option<PartialPrime>,
    /// Additional keys for multi-key attacks.
    pub keys: Vec<KeyEntry>,
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
            diff_pq: None,
            partial_p: None,
            partial_q: None,
            keys: Vec::new(),
        }
    }
}

impl Display for Parameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();

        if let Some(n) = &self.n {
            s += &format!("n = {n}\n");
        }
        s += &format!("e = {}\n", self.e);
        if let Some(c) = &self.c {
            s += &format!("c = {c}\n");
        }
        if let Some(p) = &self.p {
            s += &format!("p = {p}\n");
        }
        if let Some(q) = &self.q {
            s += &format!("q = {q}\n");
        }
        if let Some(d) = &self.d {
            s += &format!("d = {d}\n");
        }
        if let Some(phi) = &self.phi {
            s += &format!("phi = {phi}\n");
        }
        if let Some(dp) = &self.dp {
            s += &format!("dp = {dp}\n");
        }
        if let Some(dq) = &self.dq {
            s += &format!("dq = {dq}\n");
        }
        if let Some(qinv) = &self.qinv {
            s += &format!("qinv = {qinv}\n");
        }
        if let Some(pinv) = &self.pinv {
            s += &format!("pinv = {pinv}\n");
        }
        if let Some(sum_pq) = &self.sum_pq {
            s += &format!("sum_pq = {sum_pq}\n");
        }
        if let Some(diff_pq) = &self.diff_pq {
            s += &format!("diff_pq = {diff_pq}\n");
        }
        if let Some(partial_p) = &self.partial_p {
            s += &format!("partial_p = {:?}\n", partial_p);
        }
        if let Some(partial_q) = &self.partial_q {
            s += &format!("partial_q = {:?}\n", partial_q);
        }
        if !self.keys.is_empty() {
            s += &format!("keys = {} entries\n", self.keys.len());
            for (i, key) in self.keys.iter().enumerate() {
                s += &format!("  key[{}]: ", i);
                if let Some(n) = &key.n {
                    s += &format!("n={}, ", n);
                }
                s += &format!("e={}", key.e);
                if let Some(c) = &key.c {
                    s += &format!(", c={}", c);
                }
                s += "\n";
            }
        }

        // Remove trailing newline
        if s.ends_with('\n') {
            s.pop();
        }

        write!(f, "{s}")
    }
}

impl Parameters {
    /// Create parameters from raw file
    ///
    /// # Example
    ///
    /// ```text
    /// // Example of a raw file
    /// n = 1
    /// # This is a comment
    /// e: 0x1
    /// C 0x00
    /// phi: 0x1
    ///
    /// // Multi-key support
    /// n1 = 123
    /// e1 = 65537
    /// c1 = 456
    /// n2 = 789
    /// e2 = 3
    /// c2 = 101112
    /// ```
    pub fn from_raw(raw: &str) -> Self {
        let mut params = Self::default();
        let mut key_entries: std::collections::HashMap<usize, KeyEntry> =
            std::collections::HashMap::new();

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

            // Clean up key and check for index suffix (e.g., n1, e2, c10)
            let key_cleaned = key.replace(['_', '-'], "");
            // Parse full numeric suffix at the end of the key
            let mut chars = key_cleaned.chars().rev().peekable();
            let mut digit_str = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() {
                    digit_str.push(c);
                    chars.next();
                } else {
                    break;
                }
            }

            let (base_key, index) = if !digit_str.is_empty() {
                // digit_str is reversed, so reverse it back
                let index_str: String = digit_str.chars().rev().collect();
                let base: String = chars.rev().collect();
                if let Ok(idx) = index_str.parse::<usize>() {
                    (base, Some(idx))
                } else {
                    (key_cleaned, None)
                }
            } else {
                (key_cleaned, None)
            };

            let value = if let Ok(value) = IntegerArg::from_str(value) {
                value.0
            } else {
                eprintln!("Warning: Failed to parse {key} value: {value}");
                continue;
            };

            if let Some(idx) = index {
                // This is an indexed key (n1, e1, c1, etc.)
                let entry = key_entries.entry(idx).or_insert_with(|| KeyEntry {
                    n: None,
                    e: 65537.into(),
                    c: None,
                });

                match base_key.to_lowercase().as_str() {
                    "n" => entry.n = Some(value),
                    "e" => entry.e = value,
                    "c" => entry.c = Some(value),
                    _ => {}
                }
            } else {
                // This is a regular parameter (n, e, c, etc.)
                match base_key.to_lowercase().as_str() {
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
                    "diffpq" => params.diff_pq = Some(value),
                    _ => {}
                }
            }
        }

        // Convert the HashMap to a sorted Vec
        if !key_entries.is_empty() {
            let mut indices: Vec<_> = key_entries.keys().copied().collect();
            indices.sort();
            params.keys = indices
                .into_iter()
                .filter_map(|i| key_entries.remove(&i))
                .collect();
        }

        params
    }

    /// Create parameters from public key
    pub fn from_public_key(key: &[u8]) -> Option<Self> {
        Self::from_rsa_public_key(key)
            .or_else(|| Self::from_x509_cert(key))
            .or_else(|| Self::from_openssh_public_key(key))
            .or_else(|| Self::from_x509_csr(key))
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

    /// Create parameters from x509 certificate signing request (CSR)
    pub fn from_x509_csr(key: &[u8]) -> Option<Self> {
        let req = openssl::x509::X509Req::from_pem(key)
            .or_else(|_| openssl::x509::X509Req::from_der(key))
            .ok()?;
        let rsa = req.public_key().ok()?.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from private key
    pub fn from_private_key(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        Self::from_rsa_private_key(key, passphrase)
            .or_else(|| Self::from_openssh_private_key(key, passphrase))
            .or_else(|| Self::from_pkcs12(key, passphrase))
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

    /// Create parameters from pkcs12 (.p12, .pfx) format
    pub fn from_pkcs12(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(key).ok()?;
        let parsed = pkcs12
            .parse2(passphrase.unwrap_or(""))
            .map_err(|e| {
                e.errors().first().map(|e| {
                    if e.reason() == Some("bad decrypt") || e.reason() == Some("mac verify failure")
                    {
                        panic!("Failed to decrypt PKCS#12: incorrect password")
                    }
                })
            })
            .ok()?;

        // Try to extract RSA key from private key
        if let Some(pkey) = parsed.pkey {
            if let Ok(rsa) = pkey.rsa() {
                return Some(Self {
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
                });
            }
        }

        // If private key is not available, try to extract public key from certificate
        if let Some(cert) = parsed.cert {
            if let Ok(pkey) = cert.public_key() {
                if let Ok(rsa) = pkey.rsa() {
                    return Some(Self {
                        n: Some(Integer::from_digits(
                            &rsa.n().to_vec(),
                            rug::integer::Order::Msf,
                        )),
                        e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
                        ..Default::default()
                    });
                }
            }
        }

        None
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
        if self.diff_pq.is_none() {
            self.diff_pq = rhs.diff_pq;
        }
        if self.partial_p.is_none() {
            self.partial_p = rhs.partial_p;
        }
        if self.partial_q.is_none() {
            self.partial_q = rhs.partial_q;
        }
        // Extend keys vector with new keys
        self.keys.extend(rhs.keys);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_prime() {
        let arg = PartialPrimeArg::from_str("0xDEADBEEF").unwrap();
        match arg.0 {
            PartialPrime::Full(n) => {
                assert_eq!(n, Integer::from(0xDEADBEEFu64));
            }
            _ => panic!("Expected Full"),
        }
    }

    #[test]
    fn parse_msb_known_question_marks() {
        let arg = PartialPrimeArg::from_str("0xDEADBEEF????").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 16);
                assert_eq!(k, Some(4)); // 4 hex digits
                assert!(matches!(orient, Orientation::MsbKnown));
                assert_eq!(known, Integer::from(0xDEADBEEFu64));
            }
            _ => panic!("Expected Partial with MsbKnown"),
        }
    }

    #[test]
    fn parse_lsb_known_question_marks() {
        let arg = PartialPrimeArg::from_str("0x????C0FFEE").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 16);
                assert_eq!(k, Some(4)); // 4 hex digits
                assert!(matches!(orient, Orientation::LsbKnown));
                assert_eq!(known, Integer::from(0xC0FFEEu64));
            }
            _ => panic!("Expected Partial with LsbKnown"),
        }
    }

    #[test]
    fn parse_decimal_msb_known() {
        let arg = PartialPrimeArg::from_str("12345????").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 10);
                assert_eq!(k, Some(4)); // 4 decimal digits
                assert!(matches!(orient, Orientation::MsbKnown));
                assert_eq!(known, Integer::from(12345));
            }
            _ => panic!("Expected Partial with MsbKnown"),
        }
    }

    #[test]
    fn parse_decimal_lsb_known() {
        let arg = PartialPrimeArg::from_str("????6789").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 10);
                assert_eq!(k, Some(4)); // 4 decimal digits
                assert!(matches!(orient, Orientation::LsbKnown));
                assert_eq!(known, Integer::from(6789));
            }
            _ => panic!("Expected Partial with LsbKnown"),
        }
    }

    #[test]
    fn parse_both_wildcards_error() {
        let result = PartialPrimeArg::from_str("0x????DEAD????");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("both"));
    }

    #[test]
    fn parse_non_contiguous_wildcards_error() {
        let result = PartialPrimeArg::from_str("0xDE??AD??EF");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("contiguous"));
    }

    #[test]
    fn parse_ellipsis_lsb_known() {
        // Test ASCII ellipsis
        let arg = PartialPrimeArg::from_str("0x...C0FFEE").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 16);
                assert_eq!(k, None);
                assert!(matches!(orient, Orientation::LsbKnown));
                assert_eq!(known, Integer::from(0xC0FFEEu64));
            }
            _ => panic!("Expected Partial with LsbKnown and k=None"),
        }
    }

    #[test]
    fn parse_ellipsis_msb_known() {
        // Test ASCII ellipsis
        let arg = PartialPrimeArg::from_str("0xDEADBEEF...").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 16);
                assert_eq!(k, None);
                assert!(matches!(orient, Orientation::MsbKnown));
                assert_eq!(known, Integer::from(0xDEADBEEFu64));
            }
            _ => panic!("Expected Partial with MsbKnown and k=None"),
        }
    }

    #[test]
    fn parse_ellipsis_both_error() {
        let result = PartialPrimeArg::from_str("0x...DEAD...");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("both"));
    }

    #[test]
    fn parse_mixed_wildcards_ellipsis_error() {
        let result = PartialPrimeArg::from_str("0x...C0FF??");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mix"));
    }
}
