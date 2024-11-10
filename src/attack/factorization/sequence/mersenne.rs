use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 50_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Mersenne GCD attack (try to find a common factor with Mersenne (+ or - 1) numbers)
/// E.g. 3, 5, 7, 9, 15, 17, 31, 33, 63, 65, 127, 129, 255, 257, 511, 513, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MersenneGcdAttack;

impl Attack for MersenneGcdAttack {
    fn name(&self) -> &'static str {
        "mersenne_gcd"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS)
        }

        for i in 2..MAX_ITERATIONS {
            let f = Integer::from(1) << i as u32;

            // Mersenne - 1
            let p = Integer::from(&f - 1).gcd(n);
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
            }

            // Mersenne + 1
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
