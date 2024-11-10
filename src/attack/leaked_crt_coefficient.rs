use indicatif::ProgressBar;
use rug::{integer::IsPrime, Integer};

use crate::{
    key::PrivateKey, utils::solve_quadratic, Attack, AttackKind, Error, Parameters, Solution,
};

fn find_phi(e: &Integer, d: &Integer) -> impl Iterator<Item = Integer> {
    let e = e.clone();
    let d = d.clone();
    let kfi: Integer = e.clone() * &d - 1;
    let mut k = &kfi / (d.clone() * 3) - 1;

    std::iter::from_fn(move || loop {
        k += 1;
        let fi = kfi.clone() / &k;
        if let Some(d0) = e.invert_ref(&fi) {
            if d == Integer::from(d0) {
                return Some(fi);
            }
        };
    })
}

fn find_p_q_from_phi(phi: &Integer, qinv: &Integer, pinv: &Integer) -> Option<(Integer, Integer)> {
    // Solve: (qinv - 1) * x^2 + (pinv + qinv - 2 - phi) * x + (pinv - 1) * phi = 0
    let a: Integer = qinv.clone() - 1;
    let b: Integer = pinv.clone() + qinv - 2 - phi;
    let c: Integer = pinv.clone() * phi - phi;

    for x in solve_quadratic(&a, &b, &c) {
        if Integer::from(&x + 1).is_probably_prime(100) != IsPrime::No {
            let q = x.clone() + 1;
            let p = phi / x + 1;
            return Some((p, q));
        }
    }

    None
}

/// Leaked CRT coefficient attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedCrtCoefficientAttack;

impl Attack for LeakedCrtCoefficientAttack {
    fn name(&self) -> &'static str {
        "leaked_crt_coefficient"
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let qinv = params.qinv.as_ref().ok_or(Error::MissingParameters)?;
        let pinv = params.pinv.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(phi) = params.phi.as_ref() {
            let (p, q) = find_p_q_from_phi(phi, qinv, pinv).ok_or(Error::NotFound)?;
            return Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(p, q, e)?,
            ));
        } else if let Some(d) = params.d.as_ref() {
            for phi in find_phi(e, d) {
                if let Some((p, q)) = find_p_q_from_phi(&phi, qinv, pinv) {
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }
            }
        }

        Err(Error::MissingParameters)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let p = Integer::from(217253114806235174978217256796277054007u128);
        let q = Integer::from(238353090381011156342038246368844285763u128);
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();
        let qinv = q.clone().invert(&p).unwrap();
        let pinv = p.invert(&q).unwrap();

        let params = Parameters {
            n: Some(factors.product()),
            d: Some(d),
            qinv: Some(qinv),
            pinv: Some(pinv),
            ..Default::default()
        };

        let solution = LeakedCrtCoefficientAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }

    #[test]
    fn attack_with_phi() {
        let p = Integer::from_str("11286119233962956683847970955583547174126900576068955140812043138251144612210018366118655904338805742839011152429444711548116674258401336770787886116950097").unwrap();
        let q = Integer::from_str("11302579647033191873453051127960044798790362539734320254569985404000484550069720648924774572271794748850598385675421697300363187043630337638706364489536157").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let qinv = q.clone().invert(&p).unwrap();
        let pinv = p.invert(&q).unwrap();

        let params = Parameters {
            n: Some(factors.product()),
            phi: Some(factors.phi()),
            qinv: Some(qinv),
            pinv: Some(pinv),
            ..Default::default()
        };

        let solution = LeakedCrtCoefficientAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }
}
