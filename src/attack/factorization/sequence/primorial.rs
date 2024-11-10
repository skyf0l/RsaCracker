use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 25_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Primorial GCD attack (try to find a common factor with Primorial (+ or - 1) numbers)
/// E.g 1, 3, 5, 7, 29, 31, 209, 211, 2309, 2311, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimorialGcdAttack;

impl Attack for PrimorialGcdAttack {
    fn name(&self) -> &'static str {
        "primorial_gcd"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS)
        }

        let mut primorial = Integer::from(1);
        for (i, prime) in primal::Primes::all()
            .take(MAX_ITERATIONS as usize)
            .enumerate()
        {
            primorial *= prime;

            // Primorial - 1
            let p = Integer::from(&primorial - 1).gcd(n);
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
            }

            // Primorial + 1
            let p = Integer::from(&primorial + 1).gcd(n);
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
            }

            if i as u64 % TICK_SIZE == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }
        }
        Err(Error::NotFound)
    }
}
