use indicatif::ProgressBar;
use rug::{Complete, Integer};

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// Leaked CRT exponent attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedCrtExponentAttack;

impl Attack for LeakedCrtExponentAttack {
    fn name(&self) -> &'static str {
        "leaked_crt_exponent"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let dp = params
            .dp
            .as_ref()
            .or(params.dq.as_ref())
            .ok_or(Error::MissingParameters)?;

        let p = (Integer::from(2).pow_mod(&(e.clone() * dp), n).unwrap() - Integer::from(2)).gcd(n);
        let q = match n.div_rem_ref(&p).complete() {
            (q, rem) if (rem) == Integer::ZERO => q,
            _ => return Err(Error::NotFound),
        };

        Ok(Solution::new_pk(
            self.name(),
            PrivateKey::from_p_q(p, q, e)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn attack_with_dp() {
        let p = Integer::from_str("11286119233962956683847970955583547174126900576068955140812043138251144612210018366118655904338805742839011152429444711548116674258401336770787886116950097").unwrap();
        let q = Integer::from_str("11302579647033191873453051127960044798790362539734320254569985404000484550069720648924774572271794748850598385675421697300363187043630337638706364489536157").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();
        let dp = d.clone() % (p - 1);

        let params = Parameters {
            n: Some(factors.product()),
            dp: Some(dp),
            ..Default::default()
        };

        let solution = LeakedCrtExponentAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }

    #[test]
    fn attack_with_dq() {
        let p = Integer::from_str("11286119233962956683847970955583547174126900576068955140812043138251144612210018366118655904338805742839011152429444711548116674258401336770787886116950097").unwrap();
        let q = Integer::from_str("11302579647033191873453051127960044798790362539734320254569985404000484550069720648924774572271794748850598385675421697300363187043630337638706364489536157").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();
        let dq = d.clone() % (q - 1);

        let params = Parameters {
            n: Some(factors.product()),
            dq: Some(dq),
            ..Default::default()
        };

        let solution = LeakedCrtExponentAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }
}
