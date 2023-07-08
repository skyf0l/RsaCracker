use indicatif::ProgressBar;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

/// Lenstra's ECM factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmAttack;

impl Attack for EcmAttack {
    fn name(&self) -> &'static str {
        "ecm"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let factors = ecm::ecm(n, pb)
            .or(Err(Error::NotFound))?
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        if factors.len() < 2 {
            return Err(Error::NotFound);
        }

        Ok(Solution::new_pk(PrivateKey::from_factors(
            &factors,
            e.clone(),
        )?))
    }
}
