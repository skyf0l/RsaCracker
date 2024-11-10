use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 10_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Fermat factorization attack
///
/// See <https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/fermat.py>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FermatAttack;

impl Attack for FermatAttack {
    fn name(&self) -> &'static str {
        "fermat"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if n.is_congruent(&Integer::from(2), &Integer::from(4)) {
            return Err(Error::NotFound);
        }

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }

        let (a, rem) = n.sqrt_rem_ref().into();
        let mut b2 = -rem;
        let mut c = (a << 1) + 1;
        let mut tries = 0;
        while !b2.is_perfect_square() {
            b2 += &c;
            c += 2;

            tries += 1;
            if tries % TICK_SIZE == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }
            if tries > MAX_ITERATIONS {
                return Err(Error::NotFound);
            }
        }

        let a = (c - 1) >> 1;
        let b = Integer::from(b2.sqrt_ref());
        let p = Integer::from(&a - &b);
        let q = a + b;
        Ok(Solution::new_pk(
            self.name(),
            PrivateKey::from_p_q(p, q, e)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn small_primes() {
        let p = Integer::from(59);
        let q = Integer::from(101);

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };
        let solution = FermatAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn big_primes() {
        let p = Integer::from_str("383885088537555147258860631363598239852683844948508219667734507794290658581818891369581578137796842442514517285109997827646844102293746572763236141308451").unwrap();
        let q = Integer::from_str("383885088537555147258860631363598239852683844948508219667734507794290658581818891369581578137796842442514517285109997827646844102293746572763236141308659").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };
        let solution = FermatAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
