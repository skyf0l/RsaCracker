use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Twin prime factorization attack
///
/// This attack works when the two prime factors p and q are close to each other,
/// forming a twin prime pair or being near-twin primes. The algorithm searches
/// for factors by starting from the square root of n and checking nearby values.
///
/// Twin primes are pairs of primes that differ by 2 (e.g., 11 and 13, or 17 and 19).
/// This attack is effective when n = p * q where |p - q| is small.
///
/// The attack computes `base = sqrt(n + 1)` and then iteratively checks candidates
/// of the form (base ± i ± 1) for small values of i, skipping combinations that
/// would result in even numbers (which cannot be prime except for 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwinPrimeAttack;

impl Attack for TwinPrimeAttack {
    fn name(&self) -> &'static str {
        "twin_prime"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }

        let base = Integer::from(n + 1).sqrt();
        let base_is_even = base.is_even();

        for i in 1..MAX_ITERATIONS {
            let i_is_even = i % 2 == 0;

            // Skip cases where p or q would be even (and thus not prime, except for 2)
            // Cases 1 and 3 are valid when base and i have the same parity
            // Case 2 is valid when base and i have different parity
            if base_is_even == i_is_even {
                // Case 1: p = base + i - 1, q = base - i - 1
                let p = base.clone() + i - Integer::from(1);
                let q = base.clone() - i - Integer::from(1);
                if p.clone() * &q == *n {
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }

                // Case 3: p = base + i + 1, q = base - i + 1
                let p = base.clone() + i + Integer::from(1);
                let q = base.clone() - i + Integer::from(1);
                if p.clone() * &q == *n {
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }
            } else {
                // Case 2: p = base + i, q = base - i
                let p = base.clone() + i;
                let q = base.clone() - i;
                if p.clone() * &q == *n {
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }
            }

            if i % TICK_SIZE == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn twin_primes() {
        let p = Integer::from_str("10000000000000000000000000000000000871").unwrap();
        let q = Integer::from_str("10000000000000000000000000000000000873").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };

        let solution = TwinPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn prime_144_tuplet() {
        let p = Integer::from_str("906221570911489301636384763697004429481232108093850153898915679568268366399251241698885449094199888897014274842573473962574006524191993327586996093067").unwrap();
        let q = Integer::from_str("906221570911489301636384763697004429481232108093850153898915679568268366399251241698885449094199888897014274842573473962574006524191993327586996093211").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };

        let solution = TwinPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
