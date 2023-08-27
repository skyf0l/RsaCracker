use indicatif::ProgressBar;
use primal::Primes;
use rug::Integer;

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Small prime attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallPrimeAttack;

impl Attack for SmallPrimeAttack {
    fn name(&self) -> &'static str {
        "small_prime"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }
        for (i, p) in Primes::all().take(MAX_ITERATIONS as usize).enumerate() {
            if p.ge(n) {
                break;
            }
            if n.is_divisible(&Integer::from(p)) {
                let q = n.clone() / p;
                let p: Integer = p.into();

                let _d = e
                    .clone()
                    .invert(&((p.clone() - 1) * (q.clone() - 1)))
                    .map_err(|_| Error::NotFound)?;

                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e.clone())?,
                ));
            }
            if i % TICK_SIZE as usize == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn test_small_prime() {
        let params = Parameters {
            n: Some(Integer::from(5051846941u64)),
            ..Default::default()
        };

        let solution = SmallPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), Integer::from(54269));
        assert_eq!(pk.q(), Integer::from(93089));
    }
}
