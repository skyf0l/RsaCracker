use rug::{ops::Pow, Integer};

use crate::{
    utils::{convergents_from_contfrac, rational_to_contfrac, trivial_factorization_with_n_phi},
    Attack, AttackResult, Error, Parameters, PrivateKey,
};

/// Wiener's attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WienerAttack;

impl Attack for WienerAttack {
    fn name(&self) -> &'static str {
        "wiener"
    }

    fn run(&self, params: &Parameters) -> AttackResult {
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn picoctf_2019_b00tl3grsa2() {
        // From picoCTF 2019 / b00tl3gRSA2
        // https://play.picoctf.org/practice/challenge/2

        let params = Parameters {
            e: Integer::from_str("4708503942244531610412322050538380910464733587871346275242432482284172101654236392984351984736443874878619953997560462921684047223032295966275936840295028523100178681588438643078390223940196199462888217663017181144875784696389582284452463871005887179492829406998155699758511305944828728291175254965579734641").unwrap(),
            n: Some(Integer::from_str("97007614857868553332786026477879242291457794765270173165848254508474626540746208892491504565756781586897238580678440760295003899043026589356122625810253174167582254002039074288705601809994964567448726499789901382169786422460213679785185749261959865537609841120269032153551390379219708186340703132361021118307").unwrap()),
            ..Default::default()
        };
        let (priv_key, m) = WienerAttack.run(&params).unwrap();

        let priv_key = priv_key.unwrap();
        assert_eq!(priv_key.factors[0].to_string(), "9472090416832180505222839110776048392526166787348746842452446085500515696125957623544939387999897705237887376448494288653148060344989742295261565644606969");
        assert_eq!(priv_key.factors[1].to_string(), "10241415631493888275651396682764104183382306992555324367637459719689109785062731629753925177075296483804475760194443584159595916911022433443178975445964603");
        assert!(m.is_none());
    }
}
