use crate::{Attack, AttackResult, Error, Parameters, PrivateKey};

/// Lenstra's ECM factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmAttack;

impl Attack for EcmAttack {
    fn name(&self) -> &'static str {
        "ecm"
    }

    fn run(&self, params: &Parameters) -> AttackResult {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let factors = ecm::ecm(n).iter().cloned().collect::<Vec<_>>();
        if factors.len() < 2 {
            return Err(Error::NotFound);
        }

        Ok((Some(PrivateKey::from_factors(&factors, e.clone())), None))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::Integer;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn picoctf_2019_b00tl3grsa3() {
        // From picoCTF 2019 / b00tl3gRSA3
        // https://play.picoctf.org/practice/challenge/78

        let params = Parameters {
            n: Some(Integer::from_str("39056050692509581712477334637015327160107749546869711670769113985808765355337838019479322609550615227820063496437067964762127955030720747918762625812999683748054248778837707320689607712699404493817028163140289756283879514920433554796594864889620997149988467724282545667018567538162474527658370249589467675820669571511041351522717322875880120407").unwrap()),
            ..Default::default()
        };

        let (priv_key, m) = EcmAttack.run(&params).unwrap();
        let priv_key = priv_key.unwrap();

        assert_eq!(
            priv_key.factors,
            vec![
                8796937381u64.into(),
                9412896307u64.into(),
                9475562711u64.into(),
                9743128037u64.into(),
                9794283581u64.into(),
                9860810317u64.into(),
                10065101351u64.into(),
                10126144591u64.into(),
                10249829593u64.into(),
                10350162761u64.into(),
                11030433097u64.into(),
                11044926953u64.into(),
                12049858129u64.into(),
                12392707807u64.into(),
                12505104169u64.into(),
                12510150683u64.into(),
                12780165793u64.into(),
                13540836383u64.into(),
                13882792481u64.into(),
                14191614407u64.into(),
                14250958681u64.into(),
                14522654269u64.into(),
                14974261927u64.into(),
                15081513319u64.into(),
                15311646247u64.into(),
                15439359787u64.into(),
                15574694939u64.into(),
                15792155903u64.into(),
                15792283421u64.into(),
                16127358157u64.into(),
                16352202593u64.into(),
                16380673457u64.into(),
                16426250371u64.into(),
                16554937393u64.into()
            ] as Vec<Integer>
        );
        assert!(m.is_none());
    }

    #[test]
    fn picoctf_2019_john_pollard() {
        // From picoCTF 2019 / john_pollard
        // https://play.picoctf.org/practice/challenge/6

        let params = Parameters::from_publickey(
            b"-----BEGIN CERTIFICATE-----
MIIB6zCB1AICMDkwDQYJKoZIhvcNAQECBQAwEjEQMA4GA1UEAxMHUGljb0NURjAe
Fw0xOTA3MDgwNzIxMThaFw0xOTA2MjYxNzM0MzhaMGcxEDAOBgNVBAsTB1BpY29D
VEYxEDAOBgNVBAoTB1BpY29DVEYxEDAOBgNVBAcTB1BpY29DVEYxEDAOBgNVBAgT
B1BpY29DVEYxCzAJBgNVBAYTAlVTMRAwDgYDVQQDEwdQaWNvQ1RGMCIwDQYJKoZI
hvcNAQEBBQADEQAwDgIHEaTUUhKxfwIDAQABMA0GCSqGSIb3DQEBAgUAA4IBAQAH
al1hMsGeBb3rd/Oq+7uDguueopOvDC864hrpdGubgtjv/hrIsph7FtxM2B4rkkyA
eIV708y31HIplCLruxFdspqvfGvLsCynkYfsY70i6I/dOA6l4Qq/NdmkPDx7edqO
T/zK4jhnRafebqJucXFH8Ak+G6ASNRWhKfFZJTWj5CoyTMIutLU9lDiTXng3rDU1
BhXg04ei1jvAf0UrtpeOA6jUyeCLaKDFRbrOm35xI79r28yO8ng1UAzTRclvkORt
b8LMxw7e+vdIntBGqf7T25PLn/MycGPPvNXyIsTzvvY/MXXJHnAqpI5DlqwzbRHz
q16/S1WLvzg4PsElmv1f
-----END CERTIFICATE-----",
        )
        .unwrap();

        let (priv_key, m) = EcmAttack.run(&params).unwrap();
        let priv_key = priv_key.unwrap();

        assert_eq!(
            priv_key.factors,
            vec![67867967.into(), 73176001.into(),] as Vec<Integer>
        );
        assert!(m.is_none());
    }
}
