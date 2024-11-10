use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 100_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Lucas GCD attack (try to find a common factor with Lucas numbers)
/// E.g. 1, 3, 4, 7, 11, 18, 29, 47, 76, 123, 199, 322, 521, 843, 1364, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LucasGcdAttack;

impl Attack for LucasGcdAttack {
    fn name(&self) -> &'static str {
        "lucas_gcd"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS)
        }

        let mut n1 = Integer::from(1);
        let mut n2 = Integer::from(3);
        for i in 1..MAX_ITERATIONS {
            let f = Integer::from(&n1 + &n2);

            if f.is_odd() {
                // Lucas
                let p = Integer::from(f.gcd_ref(n));
                if 1 < p && &p < n {
                    let q = Integer::from(n / &p);
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }
            } else {
                // Lucas - 1
                let p = Integer::from(&f - 1).gcd(n);
                if 1 < p && &p < n {
                    let q = Integer::from(n / &p);
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }

                // Lucas + 1
                let p = Integer::from(&f + 1).gcd(n);
                if 1 < p && &p < n {
                    let q = Integer::from(n / &p);
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }
            }

            n1 = n2;
            n2 = f;

            if i % TICK_SIZE == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }
        }
        Err(Error::NotFound)
    }
}
