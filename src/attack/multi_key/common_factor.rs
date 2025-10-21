use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// Common factor attack for multiple RSA keys
///
/// When multiple RSA moduli share a common prime factor, their GCD reveals that factor.
/// This attack computes GCD of all pairs of moduli to find common factors.
///
/// See <https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Practical_attacks>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonFactorAttack;

impl Attack for CommonFactorAttack {
    fn name(&self) -> &'static str {
        "common_factor"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        // Need at least 2 keys (including the main one if n is present)
        let mut moduli = Vec::new();

        // Add the main modulus if present
        if let Some(n) = &params.n {
            moduli.push(n.clone());
        }

        // Add all additional key moduli
        for key in &params.keys {
            if let Some(n) = &key.n {
                moduli.push(n.clone());
            }
        }

        if moduli.len() < 2 {
            return Err(Error::MissingParameters);
        }

        // Try all pairs of moduli
        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                let p = Integer::from(moduli[i].gcd_ref(&moduli[j]));

                if p > 1 && p != moduli[i] && p != moduli[j] {
                    // Found a common factor!
                    // Use the first modulus (could be the main one or from keys)
                    let n = if i == 0 && params.n.is_some() {
                        params.n.as_ref().unwrap()
                    } else {
                        &moduli[0]
                    };

                    let q = n.clone() / &p;

                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, &params.e)?,
                    ));
                }
            }
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::Integer;

    use crate::{factors::Factors, Attack, KeyEntry, Parameters};

    use super::*;

    #[test]
    fn attack_two_keys() {
        let p1 = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
        let q1 = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
        let p2 = p1.clone(); // Common factor
        let q2 = Integer::from_str("10846735654326787878163407853463542565347654325489765432546578765432198765432198765432198765432198765432198765432198765432198765432198765432187654321").unwrap();

        let n1 = p1.clone() * &q1;
        let n2 = p2.clone() * &q2;
        let e = Integer::from(65537);

        let params = Parameters {
            n: Some(n1.clone()),
            e: e.clone(),
            keys: vec![KeyEntry {
                n: Some(n2),
                e: e.clone(),
                c: None,
            }],
            ..Default::default()
        };

        let solution = CommonFactorAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, Factors::from([p1, q1]));
    }

    #[test]
    fn attack_three_keys() {
        let p = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
        let q1 = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
        let q2 = Integer::from_str("10846735654326787878163407853463542565347654325489765432546578765432198765432198765432198765432198765432198765432198765432198765432198765432187654321").unwrap();
        let q3 = Integer::from_str("98765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321").unwrap();

        let n1 = p.clone() * &q1;
        let n2 = p.clone() * &q2;
        let n3 = p.clone() * &q3;
        let e = Integer::from(65537);

        let params = Parameters {
            n: Some(n1.clone()),
            e: e.clone(),
            keys: vec![
                KeyEntry {
                    n: Some(n2),
                    e: e.clone(),
                    c: None,
                },
                KeyEntry {
                    n: Some(n3),
                    e: e.clone(),
                    c: None,
                },
            ],
            ..Default::default()
        };

        let solution = CommonFactorAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, Factors::from([p, q1]));
    }

    #[test]
    fn attack_no_common_factor() {
        let p1 = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
        let q1 = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
        let p2 = Integer::from_str("10846735654326787878163407853463542565347654325489765432546578765432198765432198765432198765432198765432198765432198765432198765432198765432187654321").unwrap();
        let q2 = Integer::from_str("98765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321").unwrap();

        let n1 = p1 * &q1;
        let n2 = p2 * &q2;
        let e = Integer::from(65537);

        let params = Parameters {
            n: Some(n1),
            e: e.clone(),
            keys: vec![KeyEntry {
                n: Some(n2),
                e,
                c: None,
            }],
            ..Default::default()
        };

        let result = CommonFactorAttack.run(&params, None);
        assert!(result.is_err());
    }

    #[test]
    fn attack_missing_moduli() {
        let e = Integer::from(65537);

        let params = Parameters {
            e,
            ..Default::default()
        };

        let result = CommonFactorAttack.run(&params, None);
        assert!(matches!(result, Err(Error::MissingParameters)));
    }
}
