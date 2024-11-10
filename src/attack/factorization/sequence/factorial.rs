use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 25_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Factorial GCD attack (try to find a common factor with Factorial (+ or - 1) numbers)
/// E.g. 1, 1, 2, 6, 24, 120, 720, 5040, 40320, 362880, 3628800, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorialGcdAttack;

impl Attack for FactorialGcdAttack {
    fn name(&self) -> &'static str {
        "factorial_gcd"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS)
        }

        let mut f = Integer::from(1);
        for i in 2..MAX_ITERATIONS {
            f *= i;

            // Factorial - 1
            let p = Integer::from(&f - 1).gcd(n);
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
            }

            // Factorial + 1
            let p = Integer::from(&f + 1).gcd(n);
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
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
