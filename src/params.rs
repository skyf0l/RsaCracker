use base64::{engine::general_purpose, Engine};
use rug::Integer;
use std::{
    fmt::Display,
    ops::{Add, AddAssign},
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents a partial prime with known and unknown bits
pub enum PartialPrime {
    /// Full prime value is known
    Full(Integer),
    /// MSB known (trailing wildcards): value contains known bits shifted left, unknown_bits is count
    MsbKnown { 
        /// Known most significant bits
        known_msb: Integer, 
        /// Number of unknown bits
        unknown_bits: u32,
        /// Whether this was parsed from decimal (affects recovery strategy)
        is_decimal: bool,
    },
    /// LSB known (leading wildcards): value contains known bits, unknown_bits is count
    LsbKnown { 
        /// Known least significant bits
        known_lsb: Integer, 
        /// Number of unknown bits
        unknown_bits: u32,
        /// Whether this was parsed from decimal (affects recovery strategy)
        is_decimal: bool,
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
            if n.contains('?') || n.contains("...") {
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
        // Check for wildcards first
        let has_wildcards = n.contains('?') || n.contains("...");
        
        if !has_wildcards {
            // No wildcards - try parsing as regular integer
            if let Ok(IntegerArg(num)) = IntegerArg::from_str(n) {
                return Ok(Self(PartialPrime::Full(num)));
            }
            return Err("Invalid number".to_string());
        }

        // Has wildcards - determine if it's hex or decimal
        if let Some(hex) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
            // Hexadecimal with wildcards
            Self::parse_hex_with_wildcards(hex)
        } else {
            // Decimal with wildcards
            Self::parse_decimal_with_wildcards(n)
        }
    }
}

impl PartialPrimeArg {
    fn parse_hex_with_wildcards(hex: &str) -> Result<Self, String> {
        // Normalize wildcards: replace ... with ????
        let normalized = hex.replace("...", "????");
        
        // Count leading wildcards (LSB unknown)
        let leading_wildcards = normalized.chars().take_while(|&c| c == '?').count();
        // Count trailing wildcards (MSB unknown)
        let trailing_wildcards = normalized.chars().rev().take_while(|&c| c == '?').count();
        
        if leading_wildcards > 0 && trailing_wildcards > 0 {
            return Err("Wildcards must be either leading or trailing, not both".to_string());
        }
        
        if leading_wildcards > 0 {
            // LSB known: leading wildcards mean high bits are unknown
            let known_part = &normalized[leading_wildcards..];
            if known_part.is_empty() {
                return Err("Must have some known bits".to_string());
            }
            if known_part.contains('?') {
                return Err("Wildcards must be contiguous (leading or trailing only)".to_string());
            }
            let known_lsb = Integer::from_str_radix(known_part, 16)
                .or(Err("Invalid hex number in known part".to_string()))?;
            Ok(Self(PartialPrime::LsbKnown {
                known_lsb,
                unknown_bits: (leading_wildcards * 4) as u32,
                is_decimal: false,
            }))
        } else if trailing_wildcards > 0 {
            // MSB known: trailing wildcards mean low bits are unknown
            let known_part = &normalized[..normalized.len() - trailing_wildcards];
            if known_part.is_empty() {
                return Err("Must have some known bits".to_string());
            }
            if known_part.contains('?') {
                return Err("Wildcards must be contiguous (leading or trailing only)".to_string());
            }
            let known_msb = Integer::from_str_radix(known_part, 16)
                .or(Err("Invalid hex number in known part".to_string()))?;
            Ok(Self(PartialPrime::MsbKnown {
                known_msb,
                unknown_bits: (trailing_wildcards * 4) as u32,
                is_decimal: false,
            }))
        } else {
            // Both are 0 but string contains wildcards - must be non-contiguous
            Err("Wildcards must be contiguous (leading or trailing only)".to_string())
        }
    }

    fn parse_decimal_with_wildcards(s: &str) -> Result<Self, String> {
        // Normalize wildcards: replace ... with ?
        let normalized = s.replace("...", "?");
        
        // Count leading wildcards
        let leading_wildcards = normalized.chars().take_while(|&c| c == '?').count();
        // Count trailing wildcards
        let trailing_wildcards = normalized.chars().rev().take_while(|&c| c == '?').count();
        
        if leading_wildcards > 0 && trailing_wildcards > 0 {
            return Err("Wildcards must be either leading or trailing, not both".to_string());
        }
        
        if leading_wildcards > 0 {
            // LSB known: leading wildcards mean high digits are unknown
            let known_part = &normalized[leading_wildcards..];
            if known_part.is_empty() {
                return Err("Must have some known digits".to_string());
            }
            if known_part.contains('?') {
                return Err("Wildcards must be contiguous (leading or trailing only)".to_string());
            }
            let known_lsb = Integer::from_str(known_part)
                .or(Err("Invalid decimal number in known part".to_string()))?;
            
            // For decimal, we store the number of decimal digits as "unknown_bits"
            // (even though it's not technically bits - it's the count we'll use)
            let unknown_bits = leading_wildcards as u32;
            
            Ok(Self(PartialPrime::LsbKnown {
                known_lsb,
                unknown_bits,
                is_decimal: true,
            }))
        } else if trailing_wildcards > 0 {
            // MSB known: trailing wildcards mean low digits are unknown
            let known_part = &normalized[..normalized.len() - trailing_wildcards];
            if known_part.is_empty() {
                return Err("Must have some known digits".to_string());
            }
            if known_part.contains('?') {
                return Err("Wildcards must be contiguous (leading or trailing only)".to_string());
            }
            let known_msb = Integer::from_str(known_part)
                .or(Err("Invalid decimal number in known part".to_string()))?;
            
            // For decimal, we store the number of decimal digits as "unknown_bits"
            let unknown_bits = trailing_wildcards as u32;
            
            Ok(Self(PartialPrime::MsbKnown {
                known_msb,
                unknown_bits,
                is_decimal: true,
            }))
        } else {
            // Both are 0 but string contains wildcards - must be non-contiguous
            Err("Wildcards must be contiguous (leading or trailing only)".to_string())
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
    /// Partial prime p (with wildcards).
    pub partial_p: Option<PartialPrime>,
    /// Partial prime q (with wildcards).
    pub partial_q: Option<PartialPrime>,
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
            partial_p: None,
            partial_q: None,
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
        if let Some(partial_p) = &self.partial_p {
            s += &format!("partial_p = {:?}\n", partial_p);
        }
        if let Some(partial_q) = &self.partial_q {
            s += &format!("partial_q = {:?}\n", partial_q);
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
                eprintln!("Warning: Failed to parse {key} value: {value}");
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
        if self.partial_p.is_none() {
            self.partial_p = rhs.partial_p;
        }
        if self.partial_q.is_none() {
            self.partial_q = rhs.partial_q;
        }
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
            PartialPrime::MsbKnown { known_msb, unknown_bits, is_decimal } => {
                assert_eq!(known_msb, Integer::from(0xDEADBEEFu64));
                assert_eq!(unknown_bits, 16); // 4 hex digits = 16 bits
                assert_eq!(is_decimal, false);
            }
            _ => panic!("Expected MsbKnown"),
        }
    }

    #[test]
    fn parse_msb_known_ellipsis() {
        let arg = PartialPrimeArg::from_str("0xDEADBEEF...").unwrap();
        match arg.0 {
            PartialPrime::MsbKnown { known_msb, unknown_bits, is_decimal } => {
                assert_eq!(known_msb, Integer::from(0xDEADBEEFu64));
                assert_eq!(unknown_bits, 16); // ... is replaced with ????
                assert_eq!(is_decimal, false);
            }
            _ => panic!("Expected MsbKnown"),
        }
    }

    #[test]
    fn parse_lsb_known_question_marks() {
        let arg = PartialPrimeArg::from_str("0x????C0FFEE").unwrap();
        match arg.0 {
            PartialPrime::LsbKnown { known_lsb, unknown_bits, is_decimal } => {
                assert_eq!(known_lsb, Integer::from(0xC0FFEEu64));
                assert_eq!(unknown_bits, 16); // 4 hex digits = 16 bits
                assert_eq!(is_decimal, false);
            }
            _ => panic!("Expected LsbKnown"),
        }
    }

    #[test]
    fn parse_lsb_known_ellipsis() {
        let arg = PartialPrimeArg::from_str("0x...C0FFEE").unwrap();
        match arg.0 {
            PartialPrime::LsbKnown { known_lsb, unknown_bits, is_decimal } => {
                assert_eq!(known_lsb, Integer::from(0xC0FFEEu64));
                assert_eq!(unknown_bits, 16); // ... is replaced with ????
                assert_eq!(is_decimal, false);
            }
            _ => panic!("Expected LsbKnown"),
        }
    }

    #[test]
    fn parse_decimal_msb_known() {
        let arg = PartialPrimeArg::from_str("12345????").unwrap();
        match arg.0 {
            PartialPrime::MsbKnown { known_msb, unknown_bits, is_decimal } => {
                assert_eq!(known_msb, Integer::from(12345));
                assert_eq!(unknown_bits, 4); // 4 decimal digits
                assert_eq!(is_decimal, true);
            }
            _ => panic!("Expected MsbKnown"),
        }
    }

    #[test]
    fn parse_decimal_lsb_known() {
        let arg = PartialPrimeArg::from_str("????6789").unwrap();
        match arg.0 {
            PartialPrime::LsbKnown { known_lsb, unknown_bits, is_decimal } => {
                assert_eq!(known_lsb, Integer::from(6789));
                assert_eq!(unknown_bits, 4); // 4 decimal digits
                assert_eq!(is_decimal, true);
            }
            _ => panic!("Expected LsbKnown"),
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
}
