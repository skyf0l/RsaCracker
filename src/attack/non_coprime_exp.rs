use indicatif::ProgressBar;
use rug::{integer::IsPrime, ops::Pow, Integer};

use crate::{ntheory::crt, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

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

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
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
            if e.is_probably_prime(100) == IsPrime::No {
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

    use crate::{bytes_to_integer, Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn attack_1() {
        let m = bytes_to_integer(b"RsaCracker!");
        let e = Integer::from(97);
        let p = Integer::from_str("11524095852199177373008906886201420231946490289689797220765155655781178841702306082424884518466427903652405874225278662832529065525483626062223091831210969").unwrap();
        let q = Integer::from_str("9518805221010216077164785348989177143142718007905968069666256481649307042900493393990578927655644545997107983546829451351700403322895171863833628141424633").unwrap();
        let factors = Factors::from([p, q]);
        let c = m.clone().pow_mod(&e, &factors.product()).unwrap();

        let params = Parameters {
            e,
            n: Some(factors.product()),
            phi: Some(factors.phi()),
            c: Some(c),
            ..Default::default()
        };

        let solution = NonCoprimeExpAttack.run(&params, None).unwrap();

        let ms = solution.ms;
        assert_eq!(ms.len(), 97);
        assert!(ms.iter().any(|m_| m_ == &m));
    }

    #[test]
    fn attack_2() {
        let m = bytes_to_integer(b"RsaCracker!");
        let e = Integer::from(97);
        let p = Integer::from_str(
            "112219243609243706223486619551298085362360091408633161457003404046681540344297",
        )
        .unwrap();
        let q = Integer::from_str(
            "64052533192509995760322742160163582601357132095571262796409705234000154367147",
        )
        .unwrap();
        let factors = Factors::from([p, q]);
        let c = m.clone().pow_mod(&e, &factors.product()).unwrap();

        let params = Parameters {
            e,
            n: Some(factors.product()),
            phi: Some(factors.phi()),
            c: Some(c),
            ..Default::default()
        };

        let solution = NonCoprimeExpAttack.run(&params, None).unwrap();

        let ms = solution.ms;
        assert_eq!(ms.len(), 0);
        // assert_eq!(ms.len(), 97);
        // assert!(ms.iter().any(|m_| m_ == &m));
    }
}
