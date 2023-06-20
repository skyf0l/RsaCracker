use crate::{Attack, Error, Parameters, PrivateKey, SolvedRsa};

/// Lenstra's ECM factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmAttack;

impl Attack for EcmAttack {
    fn name(&self) -> &'static str {
        "ecm"
    }

    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let factors = ecm::ecm(n).iter().cloned().collect::<Vec<_>>();
        if factors.len() < 2 {
            return Err(Error::NotFound);
        }

        Ok((Some(PrivateKey::from_factors(&factors, e.clone())), None))
    }
}
