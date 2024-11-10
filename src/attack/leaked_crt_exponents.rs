use indicatif::ProgressBar;
use rug::{integer::IsPrime, Integer};

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// Recover modulus and primes from CRT exponents dP, dQ and qInv
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedCrtExponentsAttack;

impl Attack for LeakedCrtExponentsAttack {
    fn name(&self) -> &'static str {
        "leaked_crt_exponents"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = match params.e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };

        let (dp, dq, qinv) = if let Some(qinv) = params.qinv.as_ref() {
            (
                params.dp.as_ref().ok_or(Error::MissingParameters)?,
                params.dq.as_ref().ok_or(Error::MissingParameters)?,
                qinv,
            )
        } else {
            (
                params.dq.as_ref().ok_or(Error::MissingParameters)?,
                params.dp.as_ref().ok_or(Error::MissingParameters)?,
                params.pinv.as_ref().ok_or(Error::MissingParameters)?,
            )
        };

        let one = Integer::from(1);
        let d1p = dp.clone() * e - &one;

        // Brute force p
        for k in 3..e {
            if d1p.clone() % k == 0 {
                let p = d1p.clone() / k + &one;

                // If p is prime, p may be the modulus
                if p.is_probably_prime(100) != IsPrime::No {
                    let d1q = dq.clone() * e - &one;

                    // Brute force q
                    for m in 3..e {
                        if d1q.clone() % m == 0 {
                            let q = d1q.clone() / m + &one;

                            // If q is prime, q may be the modulus
                            if q.is_probably_prime(100) != IsPrime::No {
                                // If p and q satisfy the CRT, we have found the modulus
                                if (qinv * q.clone()) % p.clone() == 1
                                    || (qinv * p.clone()) % q.clone() == 1
                                {
                                    return Ok(Solution::new_pk(
                                        self.name(),
                                        PrivateKey::from_p_q(p, q, e)?,
                                    ));
                                }
                            }
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

    use crate::{Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn attack_with_qinv() {
        let p = Integer::from_str("11286119233962956683847970955583547174126900576068955140812043138251144612210018366118655904338805742839011152429444711548116674258401336770787886116950097").unwrap();
        let q = Integer::from_str("11302579647033191873453051127960044798790362539734320254569985404000484550069720648924774572271794748850598385675421697300363187043630337638706364489536157").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();
        let qinv = q.clone().invert(&p).unwrap();
        let dp = d.clone() % (p - 1);
        let dq = d.clone() % (q - 1);

        let params = Parameters {
            n: Some(factors.product()),
            dp: Some(dp),
            dq: Some(dq),
            qinv: Some(qinv),
            ..Default::default()
        };

        let solution = LeakedCrtExponentsAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }

    #[test]
    fn attack_with_pinv() {
        let p = Integer::from_str("11286119233962956683847970955583547174126900576068955140812043138251144612210018366118655904338805742839011152429444711548116674258401336770787886116950097").unwrap();
        let q = Integer::from_str("11302579647033191873453051127960044798790362539734320254569985404000484550069720648924774572271794748850598385675421697300363187043630337638706364489536157").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();
        let pinv = p.clone().invert(&q).unwrap();
        let dp = d.clone() % (p - 1);
        let dq = d.clone() % (q - 1);

        let params = Parameters {
            n: Some(factors.product()),
            dp: Some(dp),
            dq: Some(dq),
            pinv: Some(pinv),
            ..Default::default()
        };

        let solution = LeakedCrtExponentsAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }
}
