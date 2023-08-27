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
                    PrivateKey::from_p_q(p, q, e.clone()).unwrap(),
                ));
            }

            let p = base.clone() + i;
            let q = base.clone() - i;
            if p.clone() * &q == *n {
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e.clone()).unwrap(),
                ));
            }

            let p = base.clone() + i + Integer::from(1);
            let q = base.clone() - i + Integer::from(1);
            if p.clone() * &q == *n {
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e.clone()).unwrap(),
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
        let params = Parameters {
            n: Some(
                Integer::from_str(
                    "100000000000000000000000000000000017440000000000000000000000000000000760383",
                )
                .unwrap(),
            ),
            ..Default::default()
        };

        let solution = TwinPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(
            pk.p(),
            Integer::from_str("10000000000000000000000000000000000871").unwrap()
        );
        assert_eq!(
            pk.q(),
            Integer::from_str("10000000000000000000000000000000000873").unwrap()
        );
    }

    #[test]
    fn prime_144_tuplet() {
        let params = Parameters {
            n: Some(Integer::from_str("821237535585287432765069086360741125026323946971633448089017206055124603775946157411233266354232225674420821633465892827008077734287430208281663668073518690780282157011978105143184989556600682551795790580387074977041369857898789637342335773780391190647083537733558001322522872732081380266449562868137").unwrap()),
            ..Default::default()
        };

        let solution = TwinPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), Integer::from_str("906221570911489301636384763697004429481232108093850153898915679568268366399251241698885449094199888897014274842573473962574006524191993327586996093067").unwrap());
        assert_eq!(pk.q(), Integer::from_str("906221570911489301636384763697004429481232108093850153898915679568268366399251241698885449094199888897014274842573473962574006524191993327586996093211").unwrap());
    }
}
