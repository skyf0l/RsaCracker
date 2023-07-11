use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

/// Lucas GCD attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LucasGcdAttack;

impl Attack for LucasGcdAttack {
    fn name(&self) -> &'static str {
        "lucas"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(100000)
        }

        let mut n1 = Integer::from(1);
        let mut n2 = Integer::from(3);
        for i in 1..100000 {
            let n3 = Integer::from(&n1 + &n2);
            let f = Integer::from(n3.gcd_ref(n));
            if 1 < f && &f < n {
                let p = Integer::from(n / &f);
                return Ok(Solution::new_pk(PrivateKey::from_p_q(p, f, e.clone())?));
            }

            n1 = n2;
            n2 = n3;

            if i % 1000 == 0 {
                if let Some(pb) = pb {
                    pb.inc(1000);
                }
            }
        }
        Err(Error::NotFound)
    }
}
