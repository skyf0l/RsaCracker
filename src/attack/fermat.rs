use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, SolvedRsa};

/// Fermat factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FermatAttack;

impl Attack for FermatAttack {
    fn name(&self) -> &'static str {
        "fermat"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if n.is_congruent(&Integer::from(2), &Integer::from(4)) {
            return Err(Error::NotFound);
        }

        if let Some(pb) = pb {
            pb.set_length(10000000);
        }

        let (a, rem) = n.sqrt_rem_ref().into();
        let mut b2 = -rem;
        let mut c = (a << 1) + 1;
        let mut tries = 0;
        while !b2.is_perfect_square() {
            b2 += &c;
            c += 2;

            tries += 1;
            if tries % 10000 == 0 {
                if let Some(pb) = pb {
                    pb.inc(10000);
                }
            }
            if tries > 10000000 {
                return Err(Error::NotFound);
            }
        }

        let a = (c - 1) >> 1;
        let b = Integer::from(b2.sqrt_ref());
        let p = Integer::from(&a - &b);
        let q = a + b;
        Ok((Some(PrivateKey::from_p_q(p, q, e.clone())?), None))
    }
}
