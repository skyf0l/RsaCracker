use indicatif::ProgressBar;
use rug::Integer;

use crate::{
    key::PrivateKey, utils::solve_quadratic, Attack, AttackKind, AttackSpeed, Error, Parameters,
    Solution,
};

/// Leaked sum of p and q attack (0 = x^2 - xsum + n)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumPQAttack;

impl Attack for SumPQAttack {
    fn name(&self) -> &'static str {
        "sum_pq"
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let sum_pq = params.sum_pq.as_ref().ok_or(Error::MissingParameters)?;

        // Solve: x^2 - sum_pq * x + n = 0
        let roots = solve_quadratic(&Integer::from(1), &-(sum_pq.clone()), n);
        let (p, q) = match roots.len() {
            1 => (roots[0].clone(), roots[0].clone()),
            2 => (roots[0].clone(), roots[1].clone()),
            _ => return Err(Error::NotFound),
        };

        Ok(Solution::new_pk(
            self.name(),
            PrivateKey::from_p_q(p, q, e)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let p = Integer::from_str("9680013379709450894240896318618061284105559659947313368392185471991345885186021740399175810163138239351083996692031751120232675301366868879251239724616281").unwrap();
        let q = Integer::from_str("8648015025408335181758712092667722045493734511644452769085082668804450076445917118092786133629868326002982629135152287590451302935304608656309477470314237").unwrap();
        let sum_pq = Integer::from(&p + &q);
        let factors = Factors::from([p, q]);

        let params = Parameters {
            n: Some(factors.product()),
            sum_pq: Some(sum_pq),
            ..Default::default()
        };

        let solution = SumPQAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }
}
