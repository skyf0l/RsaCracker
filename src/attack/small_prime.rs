use indicatif::ProgressBar;
use primal::Primes;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

/// Small prime attack
pub struct SmallPrimeAttack;

impl Attack for SmallPrimeAttack {
    fn name(&self) -> &'static str {
        "small_prime"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(1000000);
        }
        for (i, p) in Primes::all().take(1000000).enumerate() {
            if p.ge(n) {
                break;
            }
            if n.is_divisible(&Integer::from(p)) {
                println!("find p = {}", p);
                let q = n.clone() / p;
                let p: Integer = p.into();

                let _d = e
                    .clone()
                    .invert(&((p.clone() - 1) * (q.clone() - 1)))
                    .map_err(|_| Error::NotFound)?;

                return Ok(Solution::new_pk(self.name(), PrivateKey::from_p_q(p, q, e.clone())?));
            }
            if i % 10000 == 0 {
                if let Some(pb) = pb {
                    pb.inc(10000);
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

        assert_eq!(pk.p, Integer::from(54269));
        assert_eq!(pk.q, Integer::from(93089));
    }
}
