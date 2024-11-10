#![allow(non_snake_case)]

use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 500_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

const MULTIPLIER: [usize; 32] = [
    1,
    3,
    5,
    7,
    11,
    13,
    3 * 5,
    3 * 7,
    3 * 11,
    3 * 13,
    5 * 7,
    5 * 11,
    5 * 13,
    7 * 11,
    7 * 13,
    11 * 13,
    3 * 5 * 7,
    3 * 5 * 11,
    3 * 5 * 13,
    3 * 7 * 11,
    3 * 7 * 13,
    3 * 11 * 13,
    5 * 7 * 11,
    5 * 7 * 13,
    5 * 11 * 13,
    7 * 11 * 13,
    3 * 5 * 7 * 11,
    3 * 5 * 7 * 13,
    3 * 5 * 11 * 13,
    3 * 7 * 11 * 13,
    5 * 7 * 11 * 13,
    3 * 5 * 7 * 11 * 13,
];

/// Shank's square forms factorization attack
///
/// See <https://en.wikipedia.org/wiki/Shanks%27s_square_forms_factorization>
/// See <https://github.com/daedalus/integer_factorization_algorithms/blob/main/SQUFOF.py>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqufofAttack;

impl Attack for SqufofAttack {
    fn name(&self) -> &'static str {
        "squfof"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Slow
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if n.is_congruent(&Integer::from(2), &Integer::from(4)) {
            return Err(Error::NotFound);
        }

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS * 2 * MULTIPLIER.len() as u64);
        }
        for (index, m) in MULTIPLIER.iter().enumerate() {
            if let Some(pb) = pb {
                pb.set_position(MAX_ITERATIONS * 2 * index as u64);
            }

            let D = n.clone() * m;
            let Po = Integer::from(D.sqrt_ref());
            let mut Pprev = Po.clone();
            let mut P = Po.clone();
            let mut Qprev = Integer::from(1);
            let mut Q = &D - (Po.clone() * &Po);

            let mut r = Integer::from(Q.sqrt_ref());
            for i in 2..MAX_ITERATIONS {
                // Prevent division by zero
                if Q == 0 {
                    return Err(Error::NotFound);
                }

                let b = (Po.clone() + &P) / &Q;
                P = b.clone() * &Q - &P;
                let q = Q.clone();
                Q = Qprev + b * (Pprev - &P);
                r = Integer::from(Q.sqrt_ref());

                if i & 1 == 0 && r.clone().pow(2) == Q {
                    break;
                }
                Pprev = P.clone();
                Qprev = q;

                if i % TICK_SIZE == 0 {
                    if let Some(pb) = pb {
                        pb.inc(TICK_SIZE);
                    }
                }
            }
            // Check if we found a solution
            if r.clone().pow(2) != Q {
                continue;
            }

            Pprev = (Po.clone() - &P) / &r * &r + &P;
            P = Pprev.clone();
            Qprev = r.clone();
            Q = (D - (Pprev.clone().pow(2))) / &Qprev;

            for i in 2..MAX_ITERATIONS {
                // Prevent division by zero
                if Q == 0 {
                    return Err(Error::NotFound);
                }

                let b = (Po.clone() + &P) / &Q;
                Pprev = P.clone();
                P = b.clone() * &Q - &P;
                let q = Q.clone();
                Q = Qprev + b * (Pprev.clone() - &P);
                Qprev = q;

                if P == Pprev {
                    // Solution found
                    let r = Integer::from(n.gcd_ref(&Qprev));
                    if 1 < r && r < *n {
                        return Ok(Solution::new_pk(
                            self.name(),
                            PrivateKey::from_p_q(&r, n / &r, e)?,
                        ));
                    }
                }

                if i % TICK_SIZE == 0 {
                    if let Some(pb) = pb {
                        pb.inc(TICK_SIZE);
                    }
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
        let p = Integer::from(2071723);
        let q = Integer::from(5363222357u64);
        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };

        let solution = SqufofAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
