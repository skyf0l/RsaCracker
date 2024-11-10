use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

/// Fermat GCD attack (try to find a common factor with Fermat numbers)
/// E.g. 3, 5, 17, 257, 65537, 4294967297, 18446744073709551617, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FermatGcdAttack;

impl Attack for FermatGcdAttack {
    fn name(&self) -> &'static str {
        "fermat_gcd"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(30)
        }

        for i in 0..30 {
            let f = (Integer::from(1) << (1u32 << i)) + 1u64; // (1 << (1 << x)) + 1
            let p = f.gcd(n);
            if 1 < p && &p < n {
                let q = Integer::from(n / &p);
                return Ok(Solution::new_pk(
                    self.name(),
                    PrivateKey::from_p_q(p, q, e)?,
                ));
            }

            if let Some(pb) = pb {
                pb.inc(1);
            }
        }
        Err(Error::NotFound)
    }
}
