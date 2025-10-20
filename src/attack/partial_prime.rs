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
        pb: Option<&ProgressBar>,
    ) -> Result<Integer, Error> {
        // Calculate radix^k
        let radix_k = Integer::from(radix).pow(k as u32);

        // Determine max iterations based on unknown bit count
        let unknown_bits = (k as f64 * (radix as f64).log2()).ceil() as u32;
        let n_bits = n.significant_bits();
        let known_bits_approx = (n_bits / 2).saturating_sub(unknown_bits);

        // Log info about the search space
        if let Some(pb) = pb {
            pb.println(format!(
                "Partial prime recovery: ~{} unknown bits, ~{} known bits (n has {} bits)",
                unknown_bits, known_bits_approx, n_bits
            ));

            // Warn if below the n/4 threshold
            if known_bits_approx < n_bits / 4 {
                pb.println(format!(
                    "Warning: Known bits ({}) < n/4 ({}). Success not guaranteed (trying heuristically).",
                    known_bits_approx, n_bits / 4
                ));
            }
        }

        // We limit to approximately 2^28 (~268 million) iterations for practical brute force
        // This allows us to handle cases near the n/4 threshold
        if unknown_bits > 28 {
            if let Some(pb) = pb {
                pb.println(format!(
                    "Search space too large (~2^{} iterations). For cases with > n/4 unknown bits, \
                     Coppersmith's lattice-based methods would be needed.",
                    unknown_bits
                ));
            }
            return Err(Error::NotFound);
        }

        let max_iterations = if let Some(val) = radix_k.to_u64() {
            val
        } else {
            // radix^k is too large for u64
            if let Some(pb) = pb {
                pb.println("Search space too large for brute force.");
            }
            return Err(Error::NotFound);
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
                if let Some(pb) = pb {
                    pb.println(format!("Found prime factor after {} iterations!", x + 1));
                }
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

        // Helper function to recover prime from partial information
        let recover_prime = |partial: &PartialPrime| -> Result<Integer, Error> {
            match partial {
                PartialPrime::Full(value) => Ok(value.clone()),
                PartialPrime::Partial {
                    radix,
                    k,
                    orient,
                    known,
                } => {
                    if let Some(k_val) = k {
                        // Fixed k value (from ? wildcards)
                        Self::recover(known, *radix, *k_val, orient, n, e, pb)
                    } else {
                        // Ellipsis - infer k from N
                        let n_bits = n.significant_bits();
                        let p_bits = n_bits / 2; // Approximate p size (could be off by 1)

                        // known.significant_bits() tells us how many bits are in the known value
                        let known_bits = known.significant_bits();

                        // Calculate unknown bits based on orientation
                        let unknown_bits = match orient {
                            Orientation::LsbKnown => {
                                // LSB known: p = known + radix^k * x
                                // The unknown part is in the MSB, so we subtract known bits from total
                                p_bits.saturating_sub(known_bits)
                            }
                            Orientation::MsbKnown => {
                                // MSB known: p = known * radix^k + x
                                // The unknown part is in the LSB
                                // We need to figure out how many bits the unknown LSB part has
                                p_bits.saturating_sub(known_bits)
                            }
                        };

                        // Convert unknown bits to radix digits
                        let k_base = (unknown_bits as f64 / (*radix as f64).log2()).ceil() as usize;

                        // Try a small range of k values around the calculated k_base
                        // This handles rounding issues and edge cases
                        for k_offset in &[0, -1, 1, -2] {
                            let k_try = ((k_base as i32) + k_offset).max(1) as usize;
                            if k_try > 7 {
                                continue; // Skip if too large
                            }

                            if let Ok(result) =
                                Self::recover(known, *radix, k_try, orient, n, e, None)
                            {
                                return Ok(result);
                            }
                        }

                        // If none worked, return error
                        Err(Error::NotFound)
                    }
                }
            }
        };

        // Try to recover p from partial_p
        let p = params.partial_p.as_ref().map(recover_prime).transpose()?;

        // Try to recover q from partial_q
        let q = params.partial_q.as_ref().map(recover_prime).transpose()?;

        // Helper to compute the other prime from n given one prime
        let compute_other_prime = |known: &Integer| -> Result<Integer, Error> {
            let (other, rem) = n.div_rem_ref(known).complete();
            if rem == 0 {
                Ok(other)
            } else {
                Err(Error::NotFound)
            }
        };

        // If we recovered both p and q, create a private key
        match (p, q) {
            (Some(p), Some(q)) => Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(&p, &q, e)?,
            )),
            (Some(p), None) => {
                let q = compute_other_prime(&p)?;
                Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(&p, &q, e)?,
                ))
            }
            (None, Some(q)) => {
                let p = compute_other_prime(&q)?;
                Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(&p, &q, e)?,
                ))
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
                k: Some(unknown_count),
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
                k: Some(unknown_count),
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

    #[test]
    fn ellipsis_lsb_known() {
        // Test ellipsis with LSB known
        use crate::PartialPrimeArg;
        use std::str::FromStr;

        let p = Integer::from(1073741827u64); // 0x40000003
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Use ellipsis to indicate unknown MSB
        // p = 0x40000003, so LSB (lower 24 bits) is 0x000003
        // We'll use a smaller known part: just the lowest byte 0x03
        let arg = PartialPrimeArg::from_str("0x...03").unwrap();

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

    #[test]
    fn ellipsis_msb_known() {
        // Test ellipsis with MSB known
        use crate::PartialPrimeArg;
        use std::str::FromStr;

        let p = Integer::from(1073741827u64); // 0x40000003
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Use ellipsis to indicate unknown LSB
        // p = 0x40000003, so MSB (upper bits) after shifting right by 24 is 0x40
        // We'll use upper 2 bytes: 0x4000
        let arg = PartialPrimeArg::from_str("0x4000...").unwrap();

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
