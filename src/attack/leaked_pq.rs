use indicatif::ProgressBar;
use rug::{Complete, Integer};

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// Leaked p and/or q attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedPQAttack;

impl Attack for LeakedPQAttack {
    fn name(&self) -> &'static str {
        "leaked_pq"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let p = params.p.as_ref();
        let q = params.q.as_ref();
        let n = params.n.as_ref();

        if let (Some(p), Some(q)) = (p, q) {
            // If n is given, check if p * q == n
            if let Some(n) = n {
                if Integer::from(p * q) != *n {
                    return Err(Error::NotFound);
                }
            }

            Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(p, q, e)?,
            ))
        } else if let (Some(p), Some(n)) = (p, n) {
            let q = match n.div_rem_ref(p).complete() {
                (q, rem) if (rem) == Integer::ZERO => q,
                _ => return Err(Error::NotFound),
            };
            Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(p, q, e)?,
            ))
        } else if let (Some(q), Some(n)) = (q, n) {
            let p = match n.div_rem_ref(q).complete() {
                (p, rem) if (rem) == Integer::ZERO => p,
                _ => return Err(Error::NotFound),
            };
            Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(p, q, e)?,
            ))
        } else {
            Err(Error::MissingParameters)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn leaked_p() {
        let p = Integer::from_str("9518805221010216077164785348989177143142718007905968069666256481649307042900493393990578927655644545997107983546829451351700403322895171863833628141424633").unwrap();
        let q = Integer::from_str("11524095852199177373008906886201420231946490289689797220765155655781178841702306082424884518466427903652405874225278662832529065525483626062223091831210969").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            p: Some(p.clone()),
            ..Default::default()
        };

        let solution = LeakedPQAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn leaked_q() {
        let p = Integer::from_str("9518805221010216077164785348989177143142718007905968069666256481649307042900493393990578927655644545997107983546829451351700403322895171863833628141424633").unwrap();
        let q = Integer::from_str("11524095852199177373008906886201420231946490289689797220765155655781178841702306082424884518466427903652405874225278662832529065525483626062223091831210969").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            q: Some(q.clone()),
            ..Default::default()
        };

        let solution = LeakedPQAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn leaked_pq() {
        let p = Integer::from_str("9518805221010216077164785348989177143142718007905968069666256481649307042900493393990578927655644545997107983546829451351700403322895171863833628141424633").unwrap();
        let q = Integer::from_str("11524095852199177373008906886201420231946490289689797220765155655781178841702306082424884518466427903652405874225278662832529065525483626062223091831210969").unwrap();

        let params = Parameters {
            p: Some(p.clone()),
            q: Some(q.clone()),
            ..Default::default()
        };

        let solution = LeakedPQAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn leaked_pqn() {
        let p = Integer::from_str("9518805221010216077164785348989177143142718007905968069666256481649307042900493393990578927655644545997107983546829451351700403322895171863833628141424633").unwrap();
        let q = Integer::from_str("11524095852199177373008906886201420231946490289689797220765155655781178841702306082424884518466427903652405874225278662832529065525483626062223091831210969").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            p: Some(p.clone()),
            q: Some(q.clone()),
            ..Default::default()
        };

        let solution = LeakedPQAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn leaked_wrong_p() {
        let p = Integer::from_str("9518805221010216077164785348989177143142718007905968069666256481649307042900493393990578927655644545997107983546829451351700403322895171863833628141424633").unwrap();
        let q = Integer::from_str("11524095852199177373008906886201420231946490289689797220765155655781178841702306082424884518466427903652405874225278662832529065525483626062223091831210969").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            p: Some(Integer::from(97)),
            ..Default::default()
        };

        assert!(LeakedPQAttack.run(&params, None).is_err());
    }

    #[test]
    fn leaked_wrong_q() {
        let p = Integer::from_str("9518805221010216077164785348989177143142718007905968069666256481649307042900493393990578927655644545997107983546829451351700403322895171863833628141424633").unwrap();
        let q = Integer::from_str("11524095852199177373008906886201420231946490289689797220765155655781178841702306082424884518466427903652405874225278662832529065525483626062223091831210969").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            q: Some(Integer::from(97)),
            ..Default::default()
        };

        assert!(LeakedPQAttack.run(&params, None).is_err());
    }

    #[test]
    fn leaked_wrong_pq() {
        let p = Integer::from_str("9518805221010216077164785348989177143142718007905968069666256481649307042900493393990578927655644545997107983546829451351700403322895171863833628141424633").unwrap();
        let q = Integer::from_str("11524095852199177373008906886201420231946490289689797220765155655781178841702306082424884518466427903652405874225278662832529065525483626062223091831210969").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            p: Some(Integer::from(17)),
            q: Some(Integer::from(97)),
            ..Default::default()
        };

        assert!(LeakedPQAttack.run(&params, None).is_err());
    }
}
