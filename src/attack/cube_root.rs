use rug::{ops::Pow, Integer};

use crate::{Attack, AttackResult, Error, Parameters};

/// Cube root attack (m < n/e and small e)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CubeRootAttack;

impl Attack for CubeRootAttack {
    fn name(&self) -> &'static str {
        "cube_root"
    }

    fn run(&self, params: &Parameters) -> AttackResult {
        if params.e != 3 && params.e != 5 {
            return Err(Error::NotFound);
        }

        let e = params.e.clone();
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;
        let mut low = Integer::ZERO;
        let mut high = c.clone();

        while low < high {
            let mid: Integer = (low.clone() + high.clone()) >> 1;

            if mid.clone().pow(e.to_u32().unwrap()) < *c {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        // Check if we found the exact cube root
        if low.clone().pow(e.to_u32().unwrap()) == *c {
            Ok((None, Some(low)))
        } else {
            Err(Error::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn hxp_ctf_2018_daring() {
        // From hxp CTF 2018 / daring
        // https://ctftime.org/task/7215

        let mut params = Parameters::from_pub_pem(
            "-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQC7LPIneSm9M962IJh4Op5Dwr9k
aud5nAOXZZvafTrbkfAMmFUv7u/VmNzvPiTWhuaHgKEhyzVFp9XXdp4u+KoQ41wd
H4LS7SJq5eWGaEU9riDcP1MF2orO+OWDgbzx9hgdz5k3LyEHTrmsUgUQNsHCVsZi
FQr8/gZPzYYTRWMYcwIBAw==
-----END PUBLIC KEY-----",
        );
        params.c = Some(Integer::from_str("2780321436921227845269766067805604547641764672251687438825498122989499386967784164108893743279610287605669769995594639683212592165536863280639528420328182048065518360606262307313806591343147104009274770408926901136562839153074067955850912830877064811031354484452546219065027914838811744269912371819665118277221").unwrap());

        let (priv_key, m) = CubeRootAttack.run(&params).unwrap();

        assert!(priv_key.is_none());
        assert_eq!(
            m.unwrap().to_string(),
            "14061500589727237715723597570826081039597762758283503070252061800455951899778424597542833650554379318141"
        );
    }
}
