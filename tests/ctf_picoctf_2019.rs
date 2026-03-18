use std::{str::FromStr, sync::Arc};

use rsacracker::{
    integer_to_string, run_attacks, run_specific_attacks, EcmAttack, Parameters, WienerAttack,
};
use rug::Integer;

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

    let solution = run_attacks(&params).unwrap();
    assert!(solution.pk.is_none());
    assert_eq!(
        integer_to_string(&solution.m.unwrap()).unwrap(),
        "picoCTF{n33d_a_lArg3r_e_ccaa7776}"
    );
}

#[test]
fn picoctf_2019_b00tl3grsa2() {
    // From picoCTF 2019 / b00tl3gRSA2
    // https://play.picoctf.org/practice/challenge/2

    let params = Parameters::from_raw(include_str!("raw/picoctf_2019_b00tl3grsa2.txt"));

    let solution = run_specific_attacks(&params, &[Arc::new(WienerAttack)]).unwrap();
    assert!(solution.pk.is_some());
    assert_eq!(
        integer_to_string(&solution.m.unwrap()).unwrap(),
        "picoCTF{bad_1d3a5_2152720}"
    );
}

#[test]
fn picoctf_2019_b00tl3grsa3() {
    // From picoCTF 2019 / b00tl3gRSA3
    // https://play.picoctf.org/practice/challenge/78

    let params = Parameters {
        n: Some(Integer::from_str("101944608207205828373234136985536127422758789188321061203233970866512105752389494532109758175073247548389686570704851101289141025209074305203459165089172207956558339993794255871893298918197670129098361534364062718759980887842594439938816962085529619977722435671024746830146652610211084398772129518078361766394000325505666361018996382168237814399").unwrap()),
        c: Some(Integer::from_str("99786171303922275959081216617536152037888309124594687511306157569035124203943678705390203205474301793645001254465850455029951908425497722684994271169736978420380097827831997504449294876180399533756151444353056127431110027084634535813567144986802591544317294433853297669960933014846916140367227430423379060880630745019733944800278222773619695082").unwrap()),
        ..Default::default()
    };

    let solution = run_specific_attacks(&params, &[Arc::new(EcmAttack)]).unwrap();
    assert!(solution.pk.is_some());
    assert_eq!(
        integer_to_string(&solution.m.unwrap()).unwrap(),
        "picoCTF{too_many_fact0rs_4025135}"
    );
}

#[test]
fn picoctf_2019_john_pollard() {
    // From picoCTF 2019 / john_pollard
    // https://play.picoctf.org/practice/challenge/6

    let params = Parameters::from_public_key(
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

    let solution = run_attacks(&params).unwrap();
    let pk = solution.pk.unwrap();

    assert_eq!(pk.p(), Integer::from(67867967));
    assert_eq!(pk.q(), Integer::from(73176001));
    assert!(solution.m.is_none());
}
