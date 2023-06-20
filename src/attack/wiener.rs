use rug::{ops::Pow, Integer};

use crate::{
    ntheory::{convergents_from_contfrac, rational_to_contfrac, trivial_factorization_with_n_phi},
    Attack, Error, Parameters, PrivateKey, SolvedRsa,
};

/// Wiener's attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WienerAttack;

impl Attack for WienerAttack {
    fn name(&self) -> &'static str {
        "wiener"
    }

    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let convergents = convergents_from_contfrac(&rational_to_contfrac(e, n));
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
                            return Ok((Some(PrivateKey::from_p_q(p, q, e.clone())), None));
                        }
                    }
                }
            }
        }
        Err(Error::NotFound)
    }
}
