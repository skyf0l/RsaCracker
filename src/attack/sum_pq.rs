use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{key::PrivateKey, Attack, Error, Parameters, SolvedRsa};

/// Leaked sum of p and q attack (0 = x^2 - xsum + n)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumPQAttack;

impl Attack for SumPQAttack {
    fn name(&self) -> &'static str {
        "sum_pq"
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let sum_pq = params.sum_pq.as_ref().ok_or(Error::MissingParameters)?;

        let theta =
            match (Integer::from(sum_pq.pow(2)) - (n * Integer::from(4))).sqrt_rem(Integer::ZERO) {
                (theta, rem) if rem == Integer::ZERO => theta,
                _ => return Err(Error::NotFound),
            };
        let p = (Integer::from(sum_pq) + &theta) / Integer::from(2);
        let q = (Integer::from(sum_pq) - theta) / Integer::from(2);
        Ok((Some(PrivateKey::from_p_q(p, q, e.clone())?), None))
    }
}
