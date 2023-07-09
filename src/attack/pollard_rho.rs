use indicatif::ProgressBar;
use rug::{ops::Pow, Complete, Integer};

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

/// Pollard rho factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollardRhoAttack;

impl Attack for PollardRhoAttack {
    fn name(&self) -> &'static str {
        "pollard_rho"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(1000000);
        }

        let mut x = Integer::from(2);
        let mut y = Integer::from(2);
        let mut p = Integer::from(1);
        let g = |x: Integer| (x.pow(2) + 1) % n;

        let mut i = 0;
        while p == 1 {
            x = g(x);
            y = g(g(y));
            p = Integer::from(&x - &y).abs().gcd(n);

            i += 1;
            if i % 10000 == 0 {
                if let Some(pb) = pb {
                    pb.inc(10000);
                }
                if i == 1000000 {
                    return Err(Error::NotFound);
                }
            }
        }
        let q = match n.div_rem_ref(&p).complete() {
            (q, rem) if (rem) == Integer::ZERO => q,
            _ => return Err(Error::NotFound),
        };
        Ok(Solution::new_pk(PrivateKey::from_p_q(p, q, e.clone())?))
    }
}
