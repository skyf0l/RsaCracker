use primal::Primes;
use rug::{integer::IntegerExt64, Integer};

use crate::{Attack, AttackResult, Error, Parameters, PrivateKey};

/// Small prime attack
pub struct SmallPrimeAttack;

impl Attack for SmallPrimeAttack {
    fn name(&self) -> &'static str {
        "small_prime"
    }

    fn run(&self, params: &Parameters) -> AttackResult {
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let e = params.e.clone();

        for p in Primes::all().take(250000000) {
            if p.ge(n) {
                break;
            }
            if n.is_divisible_u64(p as u64) {
                println!("find p = {}", p);
                let q = n.clone() / p;
                let p: Integer = p.into();

                let d = e
                    .clone()
                    .invert(&((p.clone() - 1) * (q.clone() - 1)))
                    .map_err(|_| Error::NotFound)?;

                return Ok((
                    Some(PrivateKey {
                        n: n.clone(),
                        p,
                        q,
                        e,
                        d,
                    }),
                    None,
                ));
            }
        }

        Err(Error::NotFound)
    }
}
