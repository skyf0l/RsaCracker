use std::str::FromStr;

use factordb::FactorDbBlockingClient;
use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

/// Factordb attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorDbAttack;

impl Attack for FactorDbAttack {
    fn name(&self) -> &'static str {
        "factordb"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        // If `NO_FACTORDB` is set, ignore the factordb attack
        // This is useful for testing
        if std::env::var("NO_FACTORDB").is_ok() {
            return Err(Error::NotFound);
        }

        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let factors = tokio::task::block_in_place(|| FactorDbBlockingClient::new().get(n))
            .map_err(|_| Error::NotFound)?
            .into_factors_flattened()
            .iter()
            .map(|f| Integer::from_str(&f.to_string()))
            .collect::<Result<Vec<Integer>, _>>()
            .map_err(|_| Error::NotFound)?;

        if factors.len() < 2 {
            return Err(Error::NotFound);
        }

        Ok(Solution::new_pk(
            self.name(),
            PrivateKey::from_factors(factors, e)?,
        ))
    }
}
