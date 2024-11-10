use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Twin prime factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwinPrimeAttack;

impl Attack for TwinPrimeAttack {
    fn name(&self) -> &'static str {
        "twin_prime"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }

        let base = Integer::from(n + 1).sqrt();

        for i in 1..MAX_ITERATIONS {
            // TODO: Remove useless tries when p or q is even
            let p = base.clone() + i - Integer::from(1);
            let q = base.clone() - i - Integer::from(1);
            if p.clone() * &q == *n {
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
            }

            let p = base.clone() + i;
            let q = base.clone() - i;
            if p.clone() * &q == *n {
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
            }

            let p = base.clone() + i + Integer::from(1);
            let q = base.clone() - i + Integer::from(1);
            if p.clone() * &q == *n {
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn twin_primes() {
        let p = Integer::from_str("10000000000000000000000000000000000871").unwrap();
        let q = Integer::from_str("10000000000000000000000000000000000873").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };

        let solution = TwinPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn prime_144_tuplet() {
        let p = Integer::from_str("906221570911489301636384763697004429481232108093850153898915679568268366399251241698885449094199888897014274842573473962574006524191993327586996093067").unwrap();
        let q = Integer::from_str("906221570911489301636384763697004429481232108093850153898915679568268366399251241698885449094199888897014274842573473962574006524191993327586996093211").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };

        let solution = TwinPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
