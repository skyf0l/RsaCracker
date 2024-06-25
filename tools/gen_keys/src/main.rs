use std::{fs, str::FromStr};

use rug::{integer::Order, Integer};

const KEY_PASSPHRASE: &[u8] = b"Skyf0l";
const OUT_PATH: &str = "../../tests/keys";

lazy_static::lazy_static!(
    static ref EXPONENT: Integer = 65537.into();
    static ref PRIME_P: Integer = Integer::from_str("202921288215980373158956726353723723679565499427971226694841252320159866171517787931619").unwrap();
    static ref PRIME_Q: Integer = Integer::from_str("202921288215980373158956726353723723679565499427971226694841252320159866171517787931621").unwrap();
    static ref MODULUS: Integer = Integer::from(&*PRIME_P * &*PRIME_Q);
    static ref PHI: Integer = (PRIME_P.clone() - 1) * (PRIME_Q.clone() - 1);
    static ref D: Integer = EXPONENT.clone().invert(&PHI).unwrap();
    static ref DP: Integer = D.clone() % (PRIME_P.clone() - 1);
    static ref DQ: Integer = D.clone() % (PRIME_Q.clone() - 1);
    static ref QINV: Integer = Integer::from(PRIME_Q.invert_ref(&PRIME_P).unwrap());
);

fn rsa_keys() -> openssl::rsa::Rsa<openssl::pkey::Private> {
    let rsa = openssl::rsa::RsaPrivateKeyBuilder::new(
        openssl::bn::BigNum::from_slice(&MODULUS.to_digits(Order::Msf)).unwrap(),
        openssl::bn::BigNum::from_slice(&EXPONENT.to_digits(Order::Msf)).unwrap(),
        openssl::bn::BigNum::from_slice(&D.to_digits(Order::Msf)).unwrap(),
    )
    .ok()
    .unwrap()
    .set_factors(
        openssl::bn::BigNum::from_slice(&PRIME_P.to_digits(Order::Msf)).unwrap(),
        openssl::bn::BigNum::from_slice(&PRIME_Q.to_digits(Order::Msf)).unwrap(),
    )
    .ok()
    .unwrap()
    .set_crt_params(
        openssl::bn::BigNum::from_slice(&DP.to_digits(Order::Msf)).unwrap(),
        openssl::bn::BigNum::from_slice(&DQ.to_digits(Order::Msf)).unwrap(),
        openssl::bn::BigNum::from_slice(&QINV.to_digits(Order::Msf)).unwrap(),
    )
    .ok()
    .unwrap()
    .build();

    // RSA public key
    fs::write(
        format!("{OUT_PATH}/public_rsa.pem"),
        rsa.public_key_to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/public_rsa_pkcs1.pem"),
        rsa.public_key_to_pem_pkcs1().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/public_rsa.der"),
        rsa.public_key_to_der().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/public_rsa_pkcs1.der"),
        rsa.public_key_to_der_pkcs1().unwrap(),
    )
    .unwrap();

    // RSA private key
    fs::write(
        format!("{OUT_PATH}/private_rsa.pem"),
        rsa.private_key_to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/private_rsa.der"),
        rsa.private_key_to_der().unwrap(),
    )
    .unwrap();

    // Encrypted RSA private key
    fs::write(
        format!("{OUT_PATH}/private_rsa_passphrase.pem"),
        rsa.private_key_to_pem_passphrase(openssl::symm::Cipher::aes_256_cbc(), KEY_PASSPHRASE)
            .unwrap(),
    )
    .unwrap();

    rsa
}

fn openssl_keys(
    rsa: openssl::rsa::Rsa<openssl::pkey::Private>,
) -> openssl::pkey::PKey<openssl::pkey::Private> {
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

    // OpenSSL public key
    fs::write(
        format!("{OUT_PATH}/public_openssl.pem"),
        pkey.public_key_to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/public_openssl.der"),
        pkey.public_key_to_der().unwrap(),
    )
    .unwrap();

    // OpenSSL private key
    fs::write(
        format!("{OUT_PATH}/private_openssl.pem"),
        pkey.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/private_openssl.der"),
        pkey.private_key_to_der().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/private_openssl_passphrase.pem"),
        pkey.private_key_to_pem_pkcs8_passphrase(
            openssl::symm::Cipher::aes_256_cbc(),
            KEY_PASSPHRASE,
        )
        .unwrap(),
    )
    .unwrap();

    pkey
}

fn openssh_keys() {
    let public_data = ssh_key::public::RsaPublicKey {
        e: ssh_key::Mpint::from_bytes(&EXPONENT.to_digits(rug::integer::Order::Msf)).unwrap(),
        n: ssh_key::Mpint::from_bytes(&MODULUS.to_digits(rug::integer::Order::Msf)).unwrap(),
    };
    let private_data = ssh_key::private::RsaPrivateKey {
        d: ssh_key::Mpint::from_bytes(&D.to_digits(rug::integer::Order::Msf)).unwrap(),
        p: ssh_key::Mpint::from_bytes(&PRIME_P.to_digits(rug::integer::Order::Msf)).unwrap(),
        q: ssh_key::Mpint::from_bytes(&PRIME_Q.to_digits(rug::integer::Order::Msf)).unwrap(),
        iqmp: ssh_key::Mpint::from_bytes(&QINV.to_digits(rug::integer::Order::Msf)).unwrap(),
    };
    let keypair = ssh_key::private::KeypairData::Rsa(ssh_key::private::RsaKeypair {
        public: public_data,
        private: private_data,
    });

    let private_key = ssh_key::private::PrivateKey::new(keypair, "Skyf0l").unwrap();
    let public_key = private_key.public_key();

    // OpenSSH public key
    fs::write(
        format!("{OUT_PATH}/public_openssh.pem"),
        public_key.to_openssh().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/public_openssh.der"),
        public_key.to_bytes().unwrap(),
    )
    .unwrap();

    // OpenSSH private key
    fs::write(
        format!("{OUT_PATH}/private_openssh.pem"),
        private_key.to_openssh(ssh_key::LineEnding::LF).unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/private_openssh.der"),
        private_key.to_bytes().unwrap(),
    )
    .unwrap();

    // Encrypted OpenSSH private key
    let private_key = private_key
        .encrypt(&mut rand_core::OsRng, KEY_PASSPHRASE)
        .unwrap();
    fs::write(
        format!("{OUT_PATH}/private_openssh_passphrase.pem"),
        private_key.to_openssh(ssh_key::LineEnding::LF).unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{OUT_PATH}/private_openssh_passphrase.der"),
        private_key.to_bytes().unwrap(),
    )
    .unwrap();
}

fn x509_cert(_pkey: openssl::pkey::PKey<openssl::pkey::Private>) {
    // openssl req -new -x509 -key tests/keys/private_openssl.pem -out tests/keys/x509_certificate.cer -days 365
    // sed -e '1d' -e '$d' tests/keys/x509_certificate.cer | base64 -d > tests/keys/x509_certificate.der
}

fn main() {
    let rsa = rsa_keys();
    let pkey = openssl_keys(rsa);

    openssh_keys();
    x509_cert(pkey)
}
