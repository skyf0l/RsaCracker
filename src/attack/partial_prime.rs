use indicatif::ProgressBar;
use rug::ops::Pow;
use rug::{Complete, Integer};

use crate::{
    key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Orientation, Parameters, PartialPrime,
    Solution,
};

/// Partial prime attack (MSB or LSB of prime known)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialPrimeAttack;

impl PartialPrimeAttack {
    /// Recover prime from partial information
    /// Generic algorithm: p = known ± radix^k * x (depending on orientation)
    fn recover(
        known: &Integer,
        radix: u32,
        k: usize,
        orient: &Orientation,
        n: &Integer,
        _e: &Integer,
        _pb: Option<&ProgressBar>,
    ) -> Result<Integer, Error> {
        // Calculate radix^k
        let radix_k = Integer::from(radix).pow(k as u32);

        // Determine max iterations based on radix and k
        let max_iterations = match radix {
            2 => {
                // Binary: allow up to 24 bits (2^24 = ~16 million)
                if k <= 24 {
                    1u64 << k
                } else {
                    return Err(Error::NotFound);
                }
            }
            8 => {
                // Octal: allow up to 8 digits (8^8 = ~16 million)
                if k <= 8 {
                    let max_x: Integer = Integer::from(radix).pow(k as u32);
                    max_x.to_u64().unwrap_or(u64::MAX)
                } else {
                    return Err(Error::NotFound);
                }
            }
            10 => {
                // Decimal: allow up to 7 digits (10^7 = 10 million)
                if k <= 7 {
                    let max_x: Integer = Integer::from(radix).pow(k as u32);
                    max_x.to_u64().unwrap_or(u64::MAX)
                } else {
                    return Err(Error::NotFound);
                }
            }
            16 => {
                // Hexadecimal: allow up to 6 digits (16^6 = ~16 million)
                if k <= 6 {
                    let max_x: Integer = Integer::from(radix).pow(k as u32);
                    max_x.to_u64().unwrap_or(u64::MAX)
                } else {
                    return Err(Error::NotFound);
                }
            }
            _ => return Err(Error::NotFound),
        };

        // Brute force search
        for x in 0..max_iterations {
            let p_candidate = match orient {
                // LSB known (leading wildcards): p = known + radix^k * x
                Orientation::LsbKnown => Integer::from(known + &radix_k * x),
                // MSB known (trailing wildcards): p = known * radix^k + x
                Orientation::MsbKnown => (known * &radix_k).complete() + x,
            };

            if &p_candidate > n {
                break;
            }

            let (q, rem) = n.div_rem_ref(&p_candidate).complete();
            if rem == 0 && q > 1 {
                return Ok(p_candidate);
            }
        }

        Err(Error::NotFound)
    }
}

impl Attack for PartialPrimeAttack {
    fn name(&self) -> &'static str {
        "partial_prime"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let partial_p = params.partial_p.as_ref();
        let partial_q = params.partial_q.as_ref();

        // Try to recover p from partial_p
        let p = if let Some(partial_p) = partial_p {
            match partial_p {
                PartialPrime::Full(p) => Some(p.clone()),
                PartialPrime::Partial {
                    radix,
                    k,
                    orient,
                    known,
                } => Some(Self::recover(known, *radix, *k, orient, n, e, pb)?),
            }
        } else {
            None
        };

        // Try to recover q from partial_q
        let q = if let Some(partial_q) = partial_q {
            match partial_q {
                PartialPrime::Full(q) => Some(q.clone()),
                PartialPrime::Partial {
                    radix,
                    k,
                    orient,
                    known,
                } => Some(Self::recover(known, *radix, *k, orient, n, e, pb)?),
            }
        } else {
            None
        };

        // If we recovered both p and q, create a private key
        match (p, q) {
            (Some(p), Some(q)) => Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(&p, &q, e)?,
            )),
            (Some(p), None) => {
                // If we only have p, try to compute q from n
                let (q, rem) = n.div_rem_ref(&p).complete();
                if rem == 0 {
                    Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(&p, &q, e)?,
                    ))
                } else {
                    Err(Error::NotFound)
                }
            }
            (None, Some(q)) => {
                // If we only have q, try to compute p from n
                let (p, rem) = n.div_rem_ref(&q).complete();
                if rem == 0 {
                    Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(&p, &q, e)?,
                    ))
                } else {
                    Err(Error::NotFound)
                }
            }
            (None, None) => Err(Error::MissingParameters),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Attack, Parameters, PartialPrime};

    use super::*;

    #[test]
    fn lsb_known() {
        // Use actual primes for testing
        // p = 1073741827 (next prime after 2^30)
        // q = 2147483659 (next prime after 2^31)
        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Extract LSB (lower 20 bits known, upper bits unknown)
        let unknown_count = 20;
        let mask = (Integer::from(1) << (p.significant_bits() - unknown_count as u32)) - 1;
        let known_lsb = p.clone() & mask;

        let params = Parameters {
            n: Some(n),
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: unknown_count,
                orient: Orientation::LsbKnown,
                known: known_lsb,
            }),
            ..Default::default()
        };

        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn msb_known() {
        // Use actual primes for testing
        // p = 1073741827 (next prime after 2^30)
        // q = 2147483659 (next prime after 2^31)
        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Extract MSB (upper bits known, lower 20 bits unknown)
        let unknown_count = 20;
        let known_msb = p.clone() >> unknown_count;

        let params = Parameters {
            n: Some(n),
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: unknown_count,
                orient: Orientation::MsbKnown,
                known: known_msb,
            }),
            ..Default::default()
        };

        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn decimal_msb_known() {
        // Test with decimal wildcards parsing
        // Test the actual parsing path to ensure it works end-to-end
        use crate::PartialPrimeArg;
        use std::str::FromStr;

        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Parse "10737418??" which represents p with 2 unknown digits
        let arg = PartialPrimeArg::from_str("10737418??").unwrap();

        let params = Parameters {
            n: Some(n),
            partial_p: Some(arg.0),
            ..Default::default()
        };

        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
