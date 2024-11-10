use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 100_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Jacobsthal GCD attack (try to find a common factor with Jacobsthal numbers)
/// E.g. 0, 1, 1, 3, 5, 11, 21, 43, 85, 171, 341, 683, 1365, 2731, 5461, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JacobsthalGcdAttack;

impl Attack for JacobsthalGcdAttack {
    fn name(&self) -> &'static str {
        "jacobsthal_gcd"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS)
        }

        let mut n1 = Integer::from(0);
        let mut n2 = Integer::from(1);
        for i in 1..MAX_ITERATIONS {
            let n3 = Integer::from(&n1 * 2) + &n2;
            let p = Integer::from(n3.gcd_ref(n));
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
            }

            n1 = n2;
            n2 = n3;

            if i % TICK_SIZE == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }
        }
        Err(Error::NotFound)
    }
}
