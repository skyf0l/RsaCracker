use indicatif::ProgressBar;
use primal::Primes;
use rug::{ops::Pow, Integer};

use crate::{key::PrivateKey, utils::log_base_ceil, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 100_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

fn factor_xy(n: &Integer, base: usize) -> Option<(Integer, Integer)> {
    let max_power = log_base_ceil(n, base) >> 1;

    for power in 1..=max_power as u32 {
        let xy = Integer::from(base).pow(power);

        if xy.is_odd() {
            // Xy
            let p = Integer::from(xy.gcd_ref(n));
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Some((p, q));
            }
        } else {
            // Xy - 1
            let p = Integer::from(&xy - 1).gcd(n);
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Some((p, q));
            }

            // Xy + 1
            let p = Integer::from(&xy + 1).gcd(n);
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Some((p, q));
            }
        }
    }

    None
}

/// XYXZ attack (p = next_prime(x^y) with x prime)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XYGcdAttack;

impl Attack for XYGcdAttack {
    fn name(&self) -> &'static str {
        "xy"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }

        for (i, base) in Primes::all().take(MAX_ITERATIONS as usize).enumerate() {
            if let Some((p, q)) = factor_xy(n, base) {
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
