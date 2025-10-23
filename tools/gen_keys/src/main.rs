use std::{env, fs, path::PathBuf, str::FromStr};

use rand::SeedableRng;
use rug::{integer::Order, Integer};

const KEY_PASSPHRASE: &[u8] = b"Skyf0l";

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

fn rsa_keys(out_path: &str) -> openssl::rsa::Rsa<openssl::pkey::Private> {
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
        format!("{out_path}/public_rsa.pem"),
        rsa.public_key_to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/public_rsa_pkcs1.pem"),
        rsa.public_key_to_pem_pkcs1().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/public_rsa.der"),
        rsa.public_key_to_der().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/public_rsa_pkcs1.der"),
        rsa.public_key_to_der_pkcs1().unwrap(),
    )
    .unwrap();

    // RSA private key
    fs::write(
        format!("{out_path}/private_rsa.pem"),
        rsa.private_key_to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/private_rsa.der"),
        rsa.private_key_to_der().unwrap(),
    )
    .unwrap();

    // Encrypted RSA private key
    fs::write(
        format!("{out_path}/private_rsa_passphrase.pem"),
        rsa.private_key_to_pem_passphrase(openssl::symm::Cipher::aes_256_cbc(), KEY_PASSPHRASE)
            .unwrap(),
    )
    .unwrap();

    rsa
}

fn openssl_keys(
    rsa: openssl::rsa::Rsa<openssl::pkey::Private>,
    out_path: &str,
) -> openssl::pkey::PKey<openssl::pkey::Private> {
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

    // OpenSSL public key
    fs::write(
        format!("{out_path}/public_openssl.pem"),
        pkey.public_key_to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/public_openssl.der"),
        pkey.public_key_to_der().unwrap(),
    )
    .unwrap();

    // OpenSSL private key
    fs::write(
        format!("{out_path}/private_openssl.pem"),
        pkey.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/private_openssl.der"),
        pkey.private_key_to_der().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/private_openssl_passphrase.pem"),
        pkey.private_key_to_pem_pkcs8_passphrase(
            openssl::symm::Cipher::aes_256_cbc(),
            KEY_PASSPHRASE,
        )
        .unwrap(),
    )
    .unwrap();

    pkey
}

fn openssh_keys(out_path: &str) {
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
        format!("{out_path}/public_openssh.pem"),
        public_key.to_openssh().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/public_openssh.der"),
        public_key.to_bytes().unwrap(),
    )
    .unwrap();

    // OpenSSH private key
    fs::write(
        format!("{out_path}/private_openssh.pem"),
        private_key.to_openssh(ssh_key::LineEnding::LF).unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/private_openssh.der"),
        private_key.to_bytes().unwrap(),
    )
    .unwrap();

    // Encrypted OpenSSH private key
    // Use a fixed seed for deterministic key generation
    let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
    let private_key = private_key.encrypt(&mut rng, KEY_PASSPHRASE).unwrap();
    fs::write(
        format!("{out_path}/private_openssh_passphrase.pem"),
        private_key.to_openssh(ssh_key::LineEnding::LF).unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/private_openssh_passphrase.der"),
        private_key.to_bytes().unwrap(),
    )
    .unwrap();
}

fn x509_cert(
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    out_path: &str,
) -> openssl::x509::X509 {
    // Create a self-signed X.509 certificate with deterministic values
    let mut builder = openssl::x509::X509::builder().unwrap();
    builder.set_version(2).unwrap();

    let serial_number = openssl::bn::BigNum::from_u32(1).unwrap();
    let serial = openssl::asn1::Asn1Integer::from_bn(&serial_number).unwrap();
    builder.set_serial_number(&serial).unwrap();

    let mut name = openssl::x509::X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "RsaCracker").unwrap();
    name.append_entry_by_text("O", "RsaCracker Test Suite")
        .unwrap();
    name.append_entry_by_text("OU", "Testing").unwrap();
    let name = name.build();

    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();

    // Use fixed timestamps for deterministic generation
    let not_before = openssl::asn1::Asn1Time::from_str("20250101000000Z").unwrap();
    builder.set_not_before(&not_before).unwrap();
    let not_after = openssl::asn1::Asn1Time::from_str("20260101000000Z").unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.set_pubkey(pkey).unwrap();
    builder
        .sign(pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();

    let cert = builder.build();

    // Write X.509 certificate
    fs::write(
        format!("{out_path}/x509_certificate.cer"),
        cert.to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{out_path}/x509_certificate.der"),
        cert.to_der().unwrap(),
    )
    .unwrap();

    cert
}

fn x509_csr(pkey: &openssl::pkey::PKey<openssl::pkey::Private>, out_path: &str) {
    // Create a Certificate Signing Request
    let mut builder = openssl::x509::X509Req::builder().unwrap();

    let mut name = openssl::x509::X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "RsaCracker").unwrap();
    let name = name.build();

    builder.set_subject_name(&name).unwrap();
    builder.set_pubkey(pkey).unwrap();
    builder
        .sign(pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();

    let req = builder.build();

    // Write CSR
    fs::write(format!("{out_path}/x509_csr.csr"), req.to_pem().unwrap()).unwrap();
    fs::write(format!("{out_path}/x509_csr.der"), req.to_der().unwrap()).unwrap();
}

fn pkcs12(
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    cert: &openssl::x509::X509,
    out_path: &str,
) {
    // Create PKCS#12 bundle using the new API
    let pkcs12 = openssl::pkcs12::Pkcs12::builder()
        .name("friendly_name")
        .pkey(pkey)
        .cert(cert)
        .build2("test123")
        .unwrap();

    // Write PKCS#12
    fs::write(format!("{out_path}/pkcs12.p12"), pkcs12.to_der().unwrap()).unwrap();
}

fn pkcs7(
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    cert: &openssl::x509::X509,
    out_path: &str,
) {
    // Create PKCS#7 certificate chain (signed data with certificates)
    let mut certs = openssl::stack::Stack::new().unwrap();
    certs.push(cert.clone()).unwrap();

    let pkcs7 =
        openssl::pkcs7::Pkcs7::sign(cert, pkey, &certs, b"", openssl::pkcs7::Pkcs7Flags::NOATTR)
            .unwrap();

    // Write PKCS#7
    fs::write(format!("{out_path}/pkcs7.p7b"), pkcs7.to_pem().unwrap()).unwrap();
    fs::write(format!("{out_path}/pkcs7.p7c"), pkcs7.to_der().unwrap()).unwrap();
}

fn main() {
    // Get output path from command line arguments, default to ../../tests/keys
    let out_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "../../tests/keys".to_string());

    // Create output directory if it doesn't exist
    let out_path_buf = PathBuf::from(&out_path);
    if !out_path_buf.exists() {
        fs::create_dir_all(&out_path_buf).expect("Failed to create output directory");
    }

    let rsa = rsa_keys(&out_path);
    let pkey = openssl_keys(rsa, &out_path);

    openssh_keys(&out_path);

    // Generate X.509 certificate
    let cert = x509_cert(&pkey, &out_path);

    // Generate CSR
    x509_csr(&pkey, &out_path);

    // Generate PKCS#12
    pkcs12(&pkey, &cert, &out_path);

    // Generate PKCS#7
    pkcs7(&pkey, &cert, &out_path);
}
