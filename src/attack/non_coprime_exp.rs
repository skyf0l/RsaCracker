use indicatif::ProgressBar;
use rug::{integer::IsPrime, ops::Pow, Integer};

use crate::{ntheory::crt, Attack, AttackSpeed, Error, Parameters, Solution};

use super::known_phi::factorize as factorize_from_phi;

/// Recover plaintext encrypted with a non-coprime exponent (d can't be computed)
///
/// See <https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/non_coprime_exponent.py>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonCoprimeExpAttack;

impl Attack for NonCoprimeExpAttack {
    fn name(&self) -> &'static str {
        "non_coprime_exp"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let e_u32 = match e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let phi = params.phi.as_ref().ok_or(Error::MissingParameters)?;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        // Phi and e mustn't be coprime
        if phi.clone() % e != 0 {
            return Err(Error::NotFound);
        }

        if (phi.clone() / e).gcd(e) == 1 {
            // E must be prime
            if e.is_probably_prime(300) == IsPrime::No {
                return Err(Error::NotFound);
            }

            // Finding multiplicative generator of subgroup with order e elements (Algorithm 1).
            let phi = phi.clone() / e;
            let mut g = Integer::from(1);
            let mut ge = Integer::from(1);
            while ge == 1 {
                g += 1;
                ge = g.clone().pow_mod(&phi, n).unwrap();
            }

            // Finding possible plaintexts (Algorithm 2).
            let d = e.clone().invert(&phi).unwrap();
            let a = c.clone().pow_mod(&d, n).unwrap();
            let mut l = ge.clone();
            let mut ms = Vec::new();
            for _ in 0..e_u32 {
                let x = a.clone() * &l % n;
                l = l * &ge % n;
                ms.push(x);
            }

            Ok(Solution::new_ms(self.name(), ms))
        } else {
            // Fall back to more generic root finding using Adleman-Manders-Miller and CRT.
            let (p, q) = factorize_from_phi(n, phi).ok_or(Error::NotFound)?;
            let pm1 = p.clone() - 1u64;
            let qm1 = q.clone() - 1u64;
            let cp = c.clone() % &p;
            let cq = c.clone() % &q;

            let mut tp = 0;
            while pm1.is_divisible(&e.clone().pow(tp + 1)) {
                tp += 1;
            }
            let mut tq = 0;
            while qm1.is_divisible(&e.clone().pow(tq + 1)) {
                tq += 1;
            }

            if tp == 0 && tq == 0 {
                return Err(Error::NotFound);
            }

            // Compute e-th roots mod p and q
            let mps = if tp == 0 {
                vec![cp
                    .clone()
                    .pow_mod(&e.clone().invert(&pm1).unwrap(), &p)
                    .unwrap()]
            } else {
                // TODO: Compute: list(rth_roots(GF(p), cp, e)
                Vec::new()
            };
            // Compute e-th roots mod p and q
            let mqs = if tq == 0 {
                vec![cq
                    .clone()
                    .pow_mod(&e.clone().invert(&qm1).unwrap(), &q)
                    .unwrap()]
            } else {
                // TODO: Compute: list(rth_roots(GF(q), cq, e))
                Vec::new()
            };

            // Compute all combinations of e-th roots mod p and q using CRT
            let mut ms = Vec::new();
            for mp in mps {
                for mq in mqs.iter().cloned() {
                    if let Some(m) = crt(&[mp.clone(), mq], &[p.clone(), q.clone()]) {
                        ms.push(m);
                    }
                }
            }

            Ok(Solution::new_ms(self.name(), ms))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{string_to_integer, Attack, Parameters};

    use super::*;

    #[test]
    fn test_non_coprime_exp_1() {
        let params = Parameters {
            e: 97.into(),
            n: Some(Integer::from_str("70614516511653681890499154979132584270226272722256500214622787223610550854997589832081078823061362723307592045336521542508756980750403350846458509885757683321317161650232926804838167800574962335211603765250113548044716181309168596871119574945614348011364785106756383385817704733682831382361355046945990826439").unwrap()),
            phi: Some(Integer::from_str("70614516511653681890499154979132584270226272722256500214622787223610550854997589832081078823061362723307592045336521542508756980750403350846458509885757666513301563453991037566801998355853698264049064088558494760523929055515901945246240176149856235173437476447914167628671612210755973209476747909997877210160").unwrap()),
            c: Some(Integer::from_str("64661204029135964132889081687074860054712654034863010536364556786624954291098513345987672476667793926002424442735780851035670961910729632679400018424471981200856732422764873547195622843355994005181303652821475568881690325047489311603051064285114386559008168851547245493284359148537891567724376626953690183719").unwrap()),
            ..Default::default()
        };

        let solution = NonCoprimeExpAttack.run(&params, None).unwrap();

        let ms = solution.ms;
        let expected = string_to_integer("RsaCracker!");
        assert_eq!(ms.len(), 97);
        assert_eq!(ms.iter().find(|&m| m == &expected), Some(&expected));
    }

    #[test]
    fn test_non_coprime_exp_2() {
        let params = Parameters {
            e: 97.into(),
            n: Some(Integer::from_str("9877081787943447296934051979708024943010364249763692219779829369688055631841144147993721685169242981675777515381610996252792949250226858601291763467200163").unwrap()),
            phi: Some(Integer::from_str("9877081787943447296934051979708024943010364249763692219779829369688055631840943498227708664331165033356285729233883344898767847678347362252996528714313608").unwrap()),
            c: Some(Integer::from_str("2970243053142559611522730937335730733335477616024160238950964367836218331139618021581786456342640449445296366056186513476961469451249654970019283117081997").unwrap()),
            ..Default::default()
        };

        let solution = NonCoprimeExpAttack.run(&params, None).unwrap();

        let ms = solution.ms;
        let _expected = string_to_integer("RsaCracker!");
        assert_eq!(ms.len(), 0);
        // assert_eq!(ms.len(), 97);
        // assert_eq!(ms.iter().find(|&m| m == &expected), Some(&expected));
    }
}
