use indicatif::ProgressBar;

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

/// Common factor shared in plaintext / ciphertext attack
///
/// See <https://crypto.stackexchange.com/a/99221>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfactCnAttack;

impl Attack for ComfactCnAttack {
    fn name(&self) -> &'static str {
        "comfact_cn"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        let p = c.gcd_ref(n).into();

        if p != 1 {
            let q = n.clone() / &p;

            Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_factors(&[p, q], e.clone())?,
            ))
        } else {
            Err(Error::NotFound)
        }
    }
}
