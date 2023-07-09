use indicatif::ProgressBar;
use rug::{integer::IsPrime, Integer};

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

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
    let a: Integer = qinv.clone() - 1;
    let b: Integer = pinv.clone() + qinv - 2 - phi;
    let c: Integer = pinv.clone() * phi - phi;
    let delta: Integer = b.clone() * &b - Integer::from(4) * &a * &c;

    if delta > 0 {
        let (root, rem) = delta.sqrt_rem(Integer::ZERO);
        if rem == Integer::ZERO {
            let x1: Integer = (root.clone() - &b) / (a.clone() * 2);
            let x2: Integer = (-root - &b) / (a * 2);
            if Integer::from(&x1 + 1).is_probably_prime(300) != IsPrime::No {
                let q = x1.clone() + 1;
                let p = phi / x1 + 1;
                return Some((p, q));
            }
            if Integer::from(&x2 + 1).is_probably_prime(300) != IsPrime::No {
                let q = x2.clone() + 1;
                let p = phi / x2 + 1;
                return Some((p, q));
            }
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

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let qinv = params.qinv.as_ref().ok_or(Error::MissingParameters)?;
        let pinv = params.pinv.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(phi) = params.phi.as_ref() {
            let (p, q) = find_p_q_from_phi(phi, qinv, pinv).ok_or(Error::NotFound)?;
            return Ok(Solution::new_pk(PrivateKey::from_p_q(p, q, e.clone())?));
        } else if let Some(d) = params.d.as_ref() {
            for phi in find_phi(e, d) {
                if let Some((p, q)) = find_p_q_from_phi(&phi, qinv, pinv) {
                    return Ok(Solution::new_pk(PrivateKey::from_p_q(p, q, e.clone())?));
                }
            }
        }

        Err(Error::MissingParameters)
    }
}
