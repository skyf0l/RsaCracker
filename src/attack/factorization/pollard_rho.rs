use indicatif::ProgressBar;
use rug::{ops::Pow, Complete, Integer};

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Pollard rho factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollardRhoAttack;

impl Attack for PollardRhoAttack {
    fn name(&self) -> &'static str {
        "pollard_rho"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Slow
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
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
            if i % TICK_SIZE == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
                if i == MAX_ITERATIONS {
                    return Err(Error::NotFound);
                }
            }
        }
        let q = match n.div_rem_ref(&p).complete() {
            (q, rem) if (rem) == Integer::ZERO => q,
            _ => return Err(Error::NotFound),
        };
        Ok(Solution::new_pk(
            self.name(),
            PrivateKey::from_p_q(p, q, e)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let p = Integer::from(1779681653);
        let q = Integer::from(1903643191);

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };
        let solution = PollardRhoAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
