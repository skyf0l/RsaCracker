use indicatif::ProgressBar;
use rug::{integer::IsPrime, Complete, Integer};

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

fn pollard_p_1(n: &Integer, pb: Option<&ProgressBar>) -> Option<Vec<Integer>> {
    let mut a = Integer::from(2);
    let mut b = 2;

    if let Some(pb) = pb {
        pb.set_position(0);
        pb.set_length(MAX_ITERATIONS);
    }
    loop {
        a = a.pow_mod(&b.into(), n).unwrap();
        let p = Integer::from(&a - 1).gcd(n);
        if p > 1 && &p < n {
            let (q, rem) = n.div_rem_ref(&p).complete();
            if rem != Integer::ZERO {
                return None;
            }

            let mut res = vec![];
            if p.is_probably_prime(100) == IsPrime::No {
                res.extend(pollard_p_1(&p, pb)?);
            } else {
                res.push(p);
            }
            if q.is_probably_prime(100) == IsPrime::No {
                res.extend(pollard_p_1(&q, pb)?);
            } else {
                res.push(q);
            }
            return Some(res);
        }
        b += 1;

        if b % TICK_SIZE == 0 {
            if let Some(pb) = pb {
                pb.inc(TICK_SIZE);
            }
        }
        if b > MAX_ITERATIONS {
            break;
        }
    }
    None
}

/// Pollard p-1 factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollardPM1Attack;

impl Attack for PollardPM1Attack {
    fn name(&self) -> &'static str {
        "pollard_pm1"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Slow
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let factors = pollard_p_1(n, pb).ok_or(Error::NotFound)?;
        Ok(Solution::new_pk(
            self.name(),
            PrivateKey::from_factors(factors, e)?,
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
        let solution = PollardPM1Attack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
