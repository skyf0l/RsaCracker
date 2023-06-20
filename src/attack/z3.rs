use std::str::FromStr;

use rug::Integer;
use z3::ast::Ast;

use crate::{Attack, Error, Parameters, PrivateKey, SolvedRsa};

/// Z3 attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Z3Attack;

impl Attack for Z3Attack {
    fn name(&self) -> &'static str {
        "z3"
    }

    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let i = Integer::from(n.sqrt_ref());

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);

        // Z3 variables
        let n = &z3::ast::Int::from_str(&ctx, &n.to_string()).unwrap();
        let i = &z3::ast::Int::from_str(&ctx, &i.to_string()).unwrap();
        let p = &z3::ast::Int::new_const(&ctx, "p");
        let q = &z3::ast::Int::new_const(&ctx, "q");
        let one = &z3::ast::Int::from_i64(&ctx, 1);
        let two = &z3::ast::Int::from_i64(&ctx, 2);

        // Z3 constraints
        let solver = z3::Solver::new(&ctx);
        solver.assert(&(p * q)._eq(n));
        solver.assert(&n.gt(p));
        solver.assert(&n.gt(q));
        solver.assert(&p.ge(i));
        solver.assert(&q.lt(i));
        solver.assert(&p.gt(one));
        solver.assert(&q.gt(one));
        solver.assert(&q.modulo(two)._eq(one));
        solver.assert(&p.modulo(two)._eq(one));

        if solver.check() != z3::SatResult::Sat {
            return Err(Error::NotFound);
        }

        // Z3 solution
        let model = solver.get_model().unwrap();
        let p = model.eval(p, true).ok_or(Error::NotFound)?;
        let q = model.eval(q, true).ok_or(Error::NotFound)?;

        let p = Integer::from_str(&p.to_string()).unwrap();
        let q = Integer::from_str(&q.to_string()).unwrap();
        Ok((Some(PrivateKey::from_p_q(p, q, e.clone())?), None))
    }
}
