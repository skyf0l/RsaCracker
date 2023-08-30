use std::str::FromStr;

use rsacracker::{integer_to_string, run_attacks, Parameters};
use rug::Integer;

const PLAINTEXT: &str = "RsaCracker";
const KEY_PASSPHRASE: &str = "Skyf0l";

lazy_static::lazy_static!(
    static ref CIPHER: Integer = Integer::from_str("10081655714054146207611946782441334760726791245685168254988161960973092859816964620592959371094315545344538578719378318287478311296168179292095059619434203279406072992447601").unwrap();
);

macro_rules! public_key_test {
    ($name:ident, $key:expr) => {
        #[test]
        fn $name() {
            let params = Parameters {
                c: Some(CIPHER.clone()),
                ..Default::default()
            } + Parameters::from_public_key(include_bytes!(concat!("keys/", $key)))
                .unwrap();

            let solution = run_attacks(&params).unwrap();
            assert!(solution.pk.is_some());
            assert_eq!(integer_to_string(&solution.m.unwrap()).unwrap(), PLAINTEXT);
        }
    };
}

public_key_test!(public_openssh_der, "public_openssh.der");
public_key_test!(public_openssh_pem, "public_openssh.pem");
public_key_test!(public_openssl_der, "public_openssl.der");
public_key_test!(public_openssl_pem, "public_openssl.pem");
public_key_test!(public_rsa_der, "public_rsa.der");
public_key_test!(public_rsa_pem, "public_rsa.pem");
public_key_test!(public_rsa_pkcs1_der, "public_rsa_pkcs1.der");
public_key_test!(public_rsa_pkcs1_pem, "public_rsa_pkcs1.pem");
public_key_test!(x509_certificate_cer, "x509_certificate.cer");
public_key_test!(x509_certificate_der, "x509_certificate.der");

macro_rules! private_key_test {
    ($name:ident, $key:expr) => {
        #[test]
        fn $name() {
            let params = Parameters {
                c: Some(CIPHER.clone()),
                ..Default::default()
            } + Parameters::from_private_key(
                include_bytes!(concat!("keys/", $key)),
                Some(KEY_PASSPHRASE),
            )
            .unwrap();

            let solution = run_attacks(&params).unwrap();
            assert!(solution.pk.is_some());
            assert_eq!(integer_to_string(&solution.m.unwrap()).unwrap(), PLAINTEXT);
        }
    };
}

private_key_test!(private_openssh_der, "private_openssh.der");
private_key_test!(
    private_openssh_passphrase_der,
    "private_openssh_passphrase.der"
);
private_key_test!(
    private_openssh_passphrase_pem,
    "private_openssh_passphrase.pem"
);
private_key_test!(private_openssh_pem, "private_openssh.pem");
private_key_test!(private_openssl_der, "private_openssl.der");
private_key_test!(
    private_openssl_passphrase_pem,
    "private_openssl_passphrase.pem"
);
private_key_test!(private_openssl_pem, "private_openssl.pem");
private_key_test!(private_rsa_der, "private_rsa.der");
private_key_test!(private_rsa_passphrase_pem, "private_rsa_passphrase.pem");
private_key_test!(private_rsa_pem, "private_rsa.pem");

#[test]
fn to_pem() {
    let params = Parameters {
        c: Some(CIPHER.clone()),
        ..Default::default()
    } + Parameters::from_private_key(
        include_bytes!("keys/private_rsa.pem"),
        Some(KEY_PASSPHRASE),
    )
    .unwrap();

    let solution = run_attacks(&params).unwrap();
    let pk = solution.pk.unwrap();

    assert_eq!(
        pk.to_pem(&None).unwrap(),
        include_str!("keys/private_rsa.pem")
    );
}
