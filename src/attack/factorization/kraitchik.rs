use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 10_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Kraitchi factorization attack
///
/// See <https://github.com/daedalus/integer_factorization_algorithms/blob/main/kraitchik.py>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KraitchikAttack;

impl Attack for KraitchikAttack {
    fn name(&self) -> &'static str {
        "kraitchik"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }

        let mut x = n.clone().sqrt();
        for i in 1..MAX_ITERATIONS {
            let mut k = 1;
            let mut s = x.clone().pow(2) - Integer::from(k * n);
            while s >= 0 {
                if s.is_perfect_square() {
                    let y = s.sqrt();
                    let z = x.clone() + y.clone();
                    let w = x.clone() - y.clone();
                    if z.clone() % n != 0 && w.clone() % n != 0 {
                        return Ok(Solution::new_pk(
                            self.name(),
                            PrivateKey::from_p_q(z.gcd(n), w.gcd(n), e)?,
                        ));
                    }
                }
                k += 1;
                s = x.clone().pow(2) - k * n;
            }
            x += 1;

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
        let solution = KraitchikAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
