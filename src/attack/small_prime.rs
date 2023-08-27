use std::collections::HashMap;

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

        let mut factors: HashMap<Integer, usize> = HashMap::new();
        let mut tmp_n: Integer = n.clone();
        for (i, prime) in Primes::all().take(MAX_ITERATIONS as usize).enumerate() {
            if prime > tmp_n {
                break;
            }

            let prime = Integer::from(prime);
            if tmp_n.clone().div_rem(prime.clone()).1 == 0 {
                while tmp_n.clone().div_rem(prime.clone()).1 == 0 {
                    tmp_n /= &prime;
                    *factors.entry(prime.clone()).or_insert(0) += 1;
                }
            }

            if i % TICK_SIZE as usize == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }
        }

        if n != &tmp_n {
            if tmp_n != 1 {
                factors.insert(tmp_n, 1);
            }

            return Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_factors(factors, e.clone())?,
            ));
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
