use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{
    key::PrivateKey,
    ntheory::{contfrac_to_rational, rational_to_contfrac, trivial_factorization_with_n_phi},
    Attack, Error, Parameters, Solution,
};

/// Wiener's attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WienerAttack;

impl Attack for WienerAttack {
    fn name(&self) -> &'static str {
        "wiener"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let frac = rational_to_contfrac(e, n);
        if let Some(pb) = pb {
            pb.set_length(frac.len() as u64);
        }
        let mut convergents = Vec::new();
        for i in 0..frac.len() {
            convergents.push(contfrac_to_rational(&frac[0..i].to_vec()));
            if let Some(pb) = pb {
                pb.inc(1);
            }
        }
        for (k, d) in convergents {
            if k != 0 {
                let (phi, q) = (e.clone() * &d - Integer::from(1)).div_rem_floor(k);
                if phi.is_even() && q == 0 {
                    let s = Integer::from(1) + n - &phi;
                    let discr = s.clone().pow(2) - n * Integer::from(4);
                    let t = if discr > 0 && discr.is_perfect_square() {
                        discr.sqrt()
                    } else {
                        Integer::ZERO
                    };

                    if (s + t).is_even() {
                        if let Some((p, q)) = trivial_factorization_with_n_phi(n, &phi) {
                            return Ok(Solution::new_pk(PrivateKey::from_p_q(p, q, e.clone())?));
                        }
                    }
                }
            }
        }
        Err(Error::NotFound)
    }
}
