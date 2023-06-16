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

    #[test]
    fn picoctf_2019_mini_rsa() {
        // From picoCTF 2019 / miniRSA
        // https://play.picoctf.org/practice/challenge/73

        let params = Parameters {
            e: 3.into(),
            n: Some(Integer::from_str("29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673").unwrap()),
            c: Some(Integer::from_str("2205316413931134031074603746928247799030155221252519872650073010782049179856976080512716237308882294226369300412719995904064931819531456392957957122459640736424089744772221933500860936331459280832211445548332429338572369823704784625368933").unwrap()),
            ..Default::default()
        };

        let (priv_key, m) = CubeRootAttack.run(&params).unwrap();

        assert!(priv_key.is_none());
        assert_eq!(
            m.unwrap().to_string(),
            "13016382529449106065894479374027604750406953699090365388203708028670029596145277"
        );
    }
}
