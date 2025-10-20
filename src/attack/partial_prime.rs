use indicatif::ProgressBar;
use rug::{Complete, Integer};
use rug::ops::Pow;

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, PartialPrime, Solution};

/// Partial prime attack (MSB or LSB of prime known)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialPrimeAttack;

impl PartialPrimeAttack {
    /// Recover prime when LSB is known
    fn recover_lsb_known(
        known_lsb: &Integer,
        unknown_bits: u32,
        is_decimal: bool,
        n: &Integer,
        _e: &Integer,
        _pb: Option<&ProgressBar>,
    ) -> Result<Integer, Error> {
        // When LSB is known, we have: p = known_lsb + base^k * x
        // For hex: base = 2, k = unknown_bits
        // For decimal: base = 10, k = number of unknown digits
        
        if is_decimal {
            // Decimal case: p = known_lsb + 10^k * x
            // For decimal, unknown_bits directly represents the digit count
            let unknown_digits = unknown_bits;
            let ten_k = Integer::from(10).pow(unknown_digits);
            
            // Brute force search for small unknown_digits
            if unknown_digits <= 7 {  // 10^7 = 10 million iterations max
                let max_x: Integer = Integer::from(10).pow(unknown_digits) - 1;
                for x in 0..=max_x.to_u64().unwrap_or(u64::MAX) {
                    let p_candidate = Integer::from(known_lsb + &ten_k * x);
                    if &p_candidate > n {
                        break;
                    }
                    
                    let (q, rem) = n.div_rem_ref(&p_candidate).complete();
                    if rem == 0 && q > 1 {
                        return Ok(p_candidate);
                    }
                }
            } else {
                return Err(Error::NotFound);
            }
        } else {
            // Binary case: p = known_lsb + 2^k * x
            let two_k = Integer::from(2).pow(unknown_bits);
            
            // Brute force search for small unknown_bits
            if unknown_bits <= 24 {
                let max_x = (1u64 << unknown_bits) - 1;
                for x in 0..=max_x {
                    let p_candidate = Integer::from(known_lsb + &two_k * x);
                    if &p_candidate > n {
                        break;
                    }
                    
                    let (q, rem) = n.div_rem_ref(&p_candidate).complete();
                    if rem == 0 && q > 1 {
                        return Ok(p_candidate);
                    }
                }
            } else {
                return Err(Error::NotFound);
            }
        }
        
        Err(Error::NotFound)
    }
    
    /// Recover prime when MSB is known
    fn recover_msb_known(
        known_msb: &Integer,
        unknown_bits: u32,
        is_decimal: bool,
        n: &Integer,
        _e: &Integer,
        _pb: Option<&ProgressBar>,
    ) -> Result<Integer, Error> {
        // When MSB is known, we have: p = known_msb * base^k + x
        // For hex: base = 2, k = unknown_bits
        // For decimal: base = 10, k = number of unknown digits
        
        if is_decimal {
            // Decimal case: p = known_msb * 10^k + x
            // For decimal, unknown_bits directly represents the digit count
            let unknown_digits = unknown_bits;
            let ten_k = Integer::from(10).pow(unknown_digits);
            let base = Integer::from(known_msb * &ten_k);
            
            // Brute force search for small unknown_digits
            if unknown_digits <= 7 {  // 10^7 = 10 million iterations max
                let max_x: Integer = Integer::from(10).pow(unknown_digits) - 1;
                for x in 0..=max_x.to_u64().unwrap_or(u64::MAX) {
                    let p_candidate = Integer::from(&base + x);
                    if &p_candidate > n {
                        break;
                    }
                    
                    let (q, rem) = n.div_rem_ref(&p_candidate).complete();
                    if rem == 0 && q > 1 {
                        return Ok(p_candidate);
                    }
                }
            } else {
                return Err(Error::NotFound);
            }
        } else {
            // Binary case: p = known_msb * 2^k + x
            let two_k = Integer::from(2).pow(unknown_bits);
            let base = Integer::from(known_msb * &two_k);
            
            // Brute force search for small unknown_bits
            if unknown_bits <= 24 {
                let max_x = (1u64 << unknown_bits) - 1;
                for x in 0..=max_x {
                    let p_candidate = Integer::from(&base + x);
                    if &p_candidate > n {
                        break;
                    }
                    
                    let (q, rem) = n.div_rem_ref(&p_candidate).complete();
                    if rem == 0 && q > 1 {
                        return Ok(p_candidate);
                    }
                }
            } else {
                return Err(Error::NotFound);
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
                PartialPrime::LsbKnown { known_lsb, unknown_bits, is_decimal } => {
                    Some(Self::recover_lsb_known(known_lsb, *unknown_bits, *is_decimal, n, e, pb)?)
                }
                PartialPrime::MsbKnown { known_msb, unknown_bits, is_decimal } => {
                    Some(Self::recover_msb_known(known_msb, *unknown_bits, *is_decimal, n, e, pb)?)
                }
            }
        } else {
            None
        };
        
        // Try to recover q from partial_q
        let q = if let Some(partial_q) = partial_q {
            match partial_q {
                PartialPrime::Full(q) => Some(q.clone()),
                PartialPrime::LsbKnown { known_lsb, unknown_bits, is_decimal } => {
                    Some(Self::recover_lsb_known(known_lsb, *unknown_bits, *is_decimal, n, e, pb)?)
                }
                PartialPrime::MsbKnown { known_msb, unknown_bits, is_decimal } => {
                    Some(Self::recover_msb_known(known_msb, *unknown_bits, *is_decimal, n, e, pb)?)
                }
            }
        } else {
            None
        };
        
        // If we recovered both p and q, create a private key
        match (p, q) {
            (Some(p), Some(q)) => {
                Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(&p, &q, e)?,
                ))
            }
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
            (None, None) => Err(Error::MissingParameters)
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
        let unknown_bits = 20u32;
        let mask = (Integer::from(1) << (p.significant_bits() - unknown_bits)) - 1;
        let known_lsb = p.clone() & mask;
        
        let params = Parameters {
            n: Some(n),
            partial_p: Some(PartialPrime::LsbKnown {
                known_lsb,
                unknown_bits,
                is_decimal: false,
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
        let unknown_bits = 20u32;
        let known_msb = p.clone() >> unknown_bits;
        
        let params = Parameters {
            n: Some(n),
            partial_p: Some(PartialPrime::MsbKnown {
                known_msb,
                unknown_bits,
                is_decimal: false,
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
