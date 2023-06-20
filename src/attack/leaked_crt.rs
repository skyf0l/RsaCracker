use rug::{Complete, Integer};

use crate::{Attack, Error, Parameters, PrivateKey, SolvedRsa};

/// Leaked CRT attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedCrtAttack;

impl Attack for LeakedCrtAttack {
    fn name(&self) -> &'static str {
        "leaked_crt"
    }

    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let dp = params
            .dp
            .as_ref()
            .or(params.dq.as_ref())
            .ok_or(Error::MissingParameters)?;

        let p = (Integer::from(2).pow_mod(&(e.clone() * dp), n).unwrap() - Integer::from(2)).gcd(n);
        let q = match n.div_rem_ref(&p).complete() {
            (q, rem) if (rem) == Integer::ZERO => q,
            _ => return Err(Error::NotFound),
        };

        Ok((Some(PrivateKey::from_p_q(p, q, e.clone())), None))
    }
}
