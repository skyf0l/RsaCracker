use indicatif::ProgressBar;
use rug::{integer::IsPrime, Integer};

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

/// Recover modulus and primes from CRT exponents dP, dQ and qInv
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedCrtExponentsAttack;

impl Attack for LeakedCrtExponentsAttack {
    fn name(&self) -> &'static str {
        "leaked_crt_exponents"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = match params.e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };
        let dp = params.dp.as_ref().ok_or(Error::MissingParameters)?;
        let dq = params.dq.as_ref().ok_or(Error::MissingParameters)?;
        let qinv = params.qinv.as_ref().ok_or(Error::MissingParameters)?;
        let one = Integer::from(1);

        let d1p = dp.clone() * e - &one;

        // Brute force p
        for k in 3..e {
            if d1p.clone() % k == 0 {
                let p = d1p.clone() / k + &one;

                // If p is prime, p may be the modulus
                if p.is_probably_prime(25) != IsPrime::No {
                    let d1q = dq.clone() * e - &one;

                    // Brute force q
                    for m in 3..e {
                        if d1q.clone() % m == 0 {
                            let q = d1q.clone() / m + &one;

                            // If q is prime, q may be the modulus
                            if q.is_probably_prime(25) != IsPrime::No {
                                // If p and q satisfy the CRT, we have found the modulus
                                if (qinv * q.clone()) % p.clone() == 1
                                    || (qinv * p.clone()) % q.clone() == 1
                                {
                                    return Ok(Solution::new_pk(
                                        self.name(),
                                        PrivateKey::from_p_q(p, q, e.into())?,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(Error::NotFound)
    }
}
