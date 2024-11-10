use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 100_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Fibonacci GCD attack (try to find a common factor with Fibonacci numbers)
/// E.g. 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibonacciGcdAttack;

impl Attack for FibonacciGcdAttack {
    fn name(&self) -> &'static str {
        "fibonacci_gcd"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS)
        }

        let mut n1 = Integer::from(1);
        let mut n2 = Integer::from(2);
        for i in 1..MAX_ITERATIONS {
            let f = Integer::from(&n1 + &n2);

            if f.is_odd() {
                // Fibonacci
                let p = Integer::from(f.gcd_ref(n));
                if 1 < p && &p < n {
                    let q = Integer::from(n / &p);
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }
            } else {
                // Fibonacci - 1
                let p = Integer::from(&f - 1).gcd(n);
                if 1 < p && &p < n {
                    let q = Integer::from(n / &p);
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }

                // Fibonacci + 1
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
