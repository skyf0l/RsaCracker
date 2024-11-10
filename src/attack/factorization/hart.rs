use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 2_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Hart factorization method attack
///
/// See <https://programmingpraxis.com/2014/01/28/harts-one-line-factoring-algorithm/>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HartAttack;

impl Attack for HartAttack {
    fn name(&self) -> &'static str {
        "hart"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let two = Integer::from(2);

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }

        for i in 1..MAX_ITERATIONS {
            let s = Integer::from(n * i).sqrt() + 1u64;
            let m = s.clone().pow_mod(&two, n).unwrap();

            if m.is_perfect_square() {
                let t = m.sqrt();
                let p = (s - &t).gcd(n);
                let q = Integer::from(n / &p);

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
        let solution = HartAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
