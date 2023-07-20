use indicatif::ProgressBar;
use rug::Integer;

use crate::{
    key::PrivateKey, utils::solve_quadratic, Attack, AttackSpeed, Error, Parameters, Solution,
};

/// Leaked sum of p and q attack (0 = x^2 - xsum + n)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumPQAttack;

impl Attack for SumPQAttack {
    fn name(&self) -> &'static str {
        "sum_pq"
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
            PrivateKey::from_p_q(p, q, e.clone())?,
        ))
    }
}
