use rug::{integer::IsPrime, Complete, Integer};

use crate::{Attack, Error, Parameters, PrivateKey, SolvedRsa};

fn pollard_p_1(n: &Integer) -> Option<Vec<Integer>> {
    let mut a = Integer::from(2);
    let mut b = Integer::from(2);

    loop {
        a = a.pow_mod_ref(&b, n).unwrap().into();
        let p = Integer::from(&a - 1).gcd_ref(n).complete();
        if p > 1 && &p < n {
            let (q, rem) = n.div_rem_ref(&p).complete();
            if rem != Integer::ZERO {
                return None;
            }

            let mut res = vec![];
            if p.is_probably_prime(30) == IsPrime::No {
                res.extend(pollard_p_1(&p)?);
            } else {
                res.push(p);
            }
            if q.is_probably_prime(30) == IsPrime::No {
                res.extend(pollard_p_1(&q)?);
            } else {
                res.push(q);
            }
            return Some(res);
        }
        b += 1;

        if b > 100000 {
            break;
        }
    }
    None
}

/// Pollard p-1 factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollardP1Attack;

impl Attack for PollardP1Attack {
    fn name(&self) -> &'static str {
        "pollard_p_1"
    }

    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let factors = pollard_p_1(n).ok_or(Error::NotFound)?;
        Ok((Some(PrivateKey::from_factors(&factors, e.clone())?), None))
    }
}
