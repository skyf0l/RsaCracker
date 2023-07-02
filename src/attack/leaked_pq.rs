use indicatif::ProgressBar;
use rug::{Complete, Integer};

use crate::{key::PrivateKey, Attack, Error, Parameters, SolvedRsa};

/// Leaked p and/or q attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedPQAttack;

impl Attack for LeakedPQAttack {
    fn name(&self) -> &'static str {
        "leaked_pq"
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let p = params.p.as_ref();
        let q = params.q.as_ref();
        let n = params.n.as_ref();

        if let (Some(p), Some(q)) = (p, q) {
            Ok((
                Some(PrivateKey::from_p_q(p.clone(), q.clone(), e.clone())?),
                None,
            ))
        } else if let (Some(p), Some(n)) = (p, n) {
            let q = match n.div_rem_ref(p).complete() {
                (q, rem) if (rem) == Integer::ZERO => q,
                _ => return Err(Error::NotFound),
            };
            Ok((Some(PrivateKey::from_p_q(p.clone(), q, e.clone())?), None))
        } else if let (Some(q), Some(n)) = (q, n) {
            let p = match n.div_rem_ref(q).complete() {
                (p, rem) if (rem) == Integer::ZERO => p,
                _ => return Err(Error::NotFound),
            };
            Ok((Some(PrivateKey::from_p_q(p, q.clone(), e.clone())?), None))
        } else {
            Err(Error::MissingParameters)
        }
    }
}
