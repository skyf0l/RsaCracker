use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine};

use rsacracker::{integer_to_string, run_attacks, Parameters};
use rug::Integer;

// General keys

#[test]
fn public_key_pem_pkcs8() {
    let params = Parameters {
        c: Some(320419646801136116600272659448u128.into()),
        ..Default::default()
    } + Parameters::from_public_key(
        b"-----BEGIN PUBLIC KEY-----
MCgwDQYJKoZIhvcNAQEBBQADFwAwFAINBM0NjrmddiFxxEwyDwIDAQAB
-----END PUBLIC KEY-----",
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

#[test]
fn public_key_der() {
    let params = Parameters {
        c: Some(320419646801136116600272659448u128.into()),
        ..Default::default()
    } + Parameters::from_public_key(
        &STANDARD
            .decode("MCgwDQYJKoZIhvcNAQEBBQADFwAwFAINBM0NjrmddiFxxEwyDwIDAQAB")
            .unwrap(),
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

#[test]
fn private_key_pem_pkcs8() {
    let params = Parameters {
        c: Some(320419646801136116600272659448u128.into()),
        ..Default::default()
    } + Parameters::from_private_key(
        b"-----BEGIN PRIVATE KEY-----
MGcCAQAwDQYJKoZIhvcNAQEBBQAEUzBRAgEAAg0EzQ2OuZ12IXHETDIPAgMBAAEC
DQH6lxz+KwQ83hI1g4kCBwG/vAwG+NUCBwK+u3sl8VMCBwCPtqB1rHECBmGQ0BE9
hwIGVVuRj4u8
-----END PRIVATE KEY-----",
        None,
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

#[test]
fn private_key_der() {
    let params = Parameters {
        c: Some(320419646801136116600272659448u128.into()),
        ..Default::default()
    } + Parameters::from_private_key(
        &STANDARD.decode("MFECAQACDQTNDY65nXYhccRMMg8CAwEAAQINAfqXHP4rBDzeEjWDiQIHAb+8DAb41QIHAr67eyXxUwIHAI+2oHWscQIGYZDQET2HAgZVW5GPi7w=").unwrap(),
        None,
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

#[test]
fn private_key_pem_pkcs8_passphrase() {
    let params = Parameters {
        c: Some(320419646801136116600272659448u128.into()),
        ..Default::default()
    } + Parameters::from_private_key(
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHLMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjsa1Jfmw60XgICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEEqO98i2kv6tEhmovhuxNZwEcOs0
EV5gP0hr53u8EyW9NEN8eQNZve9KZNkg3iOSeAQTLn1/d8nas4SQ31eBiFgbSv8V
yh9+EHQtukuwZM3BDhiGNj1tfTTAEzg7YITpKW8uwElER3VP9K5p2j001MWxvTxJ
VAHTx+AM4d6wU8Iudog=
-----END ENCRYPTED PRIVATE KEY-----",
        Some("Skyf0l".to_string()),
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

#[test]
fn private_key_der_passphrase() {
    let params = Parameters {
        c: Some(320419646801136116600272659448u128.into()),
        ..Default::default()
    } + Parameters::from_private_key(
        &STANDARD.decode("MIHLMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjkYPlQk3D70QICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEA0Jw8Kvw/NnGxmdoPu9z4AEcJTMfIvpNOez2JmLQNYzGSHzrJmg1gSemu8qLaL2xnJlSbGPDhq0KnfXx8mt0HKlfG4V/FE8KzH8UDJdwKHs/1GlXWz995dPUV338E4X4P+wv0xbmvAyMoXglVG7F479fdx+SoORGIr4oUebXhw5BoE=").unwrap(),
        Some("Skyf0l".to_string()),
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

// RSA keys

#[test]
fn rsa_private_key_pem_pkcs8() {
    let params = Parameters {
        c: Some(320419646801136116600272659448u128.into()),
        ..Default::default()
    } + Parameters::from_private_key(
        b"-----BEGIN RSA PRIVATE KEY-----
MFECAQACDQTNDY65nXYhccRMMg8CAwEAAQINAfqXHP4rBDzeEjWDiQIHAb+8DAb4
1QIHAr67eyXxUwIHAI+2oHWscQIGYZDQET2HAgZVW5GPi7w=
-----END RSA PRIVATE KEY-----",
        None,
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

#[test]
fn rsa_private_key_pem_pkcs8_passphrase() {
    let params = Parameters {
        c: Some(320419646801136116600272659448u128.into()),
        ..Default::default()
    } + Parameters::from_private_key(
        b"-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,15BEC590B09D0F715E5657786E5611BC

98bOKmR4qdJNhDZC5ZqwIcQebmi4tMbertIqlsU5dhrJEQwLZZpD7piConyTeH1t
6qiQIdfsDvjpFDB5YTZ+ZFrMszqdDNygefn1LKpLTlMq7E+eIkvYwdZoftbYtLwu
-----END RSA PRIVATE KEY-----",
        Some("Skyf0l".to_string()),
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

// X509 certificates

#[test]
fn x509_certificate_pem() {
    let params = Parameters {
        c: Some(Integer::from_str("804242812633967153937570212033741683965605246244435179792586325239769415253347503536376003578348289272495641556917742628841339865367896049690886103583410253778964852679750186529946575012585070169715734731739704129469607960975468371564564626465248176131374479196358604432391648908221010747510230767142590796400").unwrap()),
        ..Default::default()
    } + Parameters::from_public_key(
        b"-----BEGIN CERTIFICATE-----
MIIC/zCCAmegAwIBAgIUAwZtlVd7wDprkunkxCzgjEynESUwDQYJKoZIhvcNAQEL
BQAwgZAxCzAJBgNVBAYTAlhYMRMwEQYDVQQIDApSc2FDcmFja2VyMRMwEQYDVQQH
DApSc2FDcmFja2VyMQ8wDQYDVQQKDAZTa3lmMGwxEzARBgNVBAsMClJzYUNyYWNr
ZXIxDzANBgNVBAMMBlNreWYwbDEgMB4GCSqGSIb3DQEJARYRU2t5ZjBsQFJzYUNy
YWNrZXIwHhcNMjMwNjIyMjI0NjM2WhcNMjMwNjIzMjI0NjM2WjCBkDELMAkGA1UE
BhMCWFgxEzARBgNVBAgMClJzYUNyYWNrZXIxEzARBgNVBAcMClJzYUNyYWNrZXIx
DzANBgNVBAoMBlNreWYwbDETMBEGA1UECwwKUnNhQ3JhY2tlcjEPMA0GA1UEAwwG
U2t5ZjBsMSAwHgYJKoZIhvcNAQkBFhFTa3lmMGxAUnNhQ3JhY2tlcjCBnzANBgkq
hkiG9w0BAQEFAAOBjQAwgYkCgYEH5hMm5qr4RPPeOvwEguZf2p9ubqVpMKru37cW
vBDUWuyibXMkriWvtff9xIiwhQw51DXBhbK5/UVVPF5gx+18Et54MchZbTb8qnQy
rl57YnoTTUHRUC0rMp5MUisejlfp51w+9s8pazHrp439Lktj6ihTJDo+5eO7dKDq
AbhxR0ECAwEAAaNTMFEwHQYDVR0OBBYEFIT9qTzuZfFUWXrTJddlTaPlugc/MB8G
A1UdIwQYMBaAFIT9qTzuZfFUWXrTJddlTaPlugc/MA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADgYIAAIuEwc97pUX3m6N3U9CbsU42Q2DxIzZyh1v7XI9e
kOM+yzanOXaNr5GoqIhBz5CA/dRxOdjDZjkCQGUd+nX09YH+zGeg3sWE2w/l5Evl
Cc4Z4EoetIoYwcAWtuM9HRh6QYQv6HL59CWKMNNPzUtOoUVlhmFxpqC4VsAxcZcK
vpEN
-----END CERTIFICATE-----",
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}

#[test]
fn x509_certificate_der() {
    let params = Parameters {
        c: Some(Integer::from_str("804242812633967153937570212033741683965605246244435179792586325239769415253347503536376003578348289272495641556917742628841339865367896049690886103583410253778964852679750186529946575012585070169715734731739704129469607960975468371564564626465248176131374479196358604432391648908221010747510230767142590796400").unwrap()),
        ..Default::default()
    } + Parameters::from_public_key(
        &STANDARD.decode("MIIC/zCCAmegAwIBAgIUAwZtlVd7wDprkunkxCzgjEynESUwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlhYMRMwEQYDVQQIDApSc2FDcmFja2VyMRMwEQYDVQQHDApSc2FDcmFja2VyMQ8wDQYDVQQKDAZTa3lmMGwxEzARBgNVBAsMClJzYUNyYWNrZXIxDzANBgNVBAMMBlNreWYwbDEgMB4GCSqGSIb3DQEJARYRU2t5ZjBsQFJzYUNyYWNrZXIwHhcNMjMwNjIyMjI0NjM2WhcNMjMwNjIzMjI0NjM2WjCBkDELMAkGA1UEBhMCWFgxEzARBgNVBAgMClJzYUNyYWNrZXIxEzARBgNVBAcMClJzYUNyYWNrZXIxDzANBgNVBAoMBlNreWYwbDETMBEGA1UECwwKUnNhQ3JhY2tlcjEPMA0GA1UEAwwGU2t5ZjBsMSAwHgYJKoZIhvcNAQkBFhFTa3lmMGxAUnNhQ3JhY2tlcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEH5hMm5qr4RPPeOvwEguZf2p9ubqVpMKru37cWvBDUWuyibXMkriWvtff9xIiwhQw51DXBhbK5/UVVPF5gx+18Et54MchZbTb8qnQyrl57YnoTTUHRUC0rMp5MUisejlfp51w+9s8pazHrp439Lktj6ihTJDo+5eO7dKDqAbhxR0ECAwEAAaNTMFEwHQYDVR0OBBYEFIT9qTzuZfFUWXrTJddlTaPlugc/MB8GA1UdIwQYMBaAFIT9qTzuZfFUWXrTJddlTaPlugc/MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYIAAIuEwc97pUX3m6N3U9CbsU42Q2DxIzZyh1v7XI9ekOM+yzanOXaNr5GoqIhBz5CA/dRxOdjDZjkCQGUd+nX09YH+zGeg3sWE2w/l5EvlCc4Z4EoetIoYwcAWtuM9HRh6QYQv6HL59CWKMNNPzUtOoUVlhmFxpqC4VsAxcZcKvpEN").unwrap(),
    )
    .unwrap();

    let (private_key, m) = run_attacks(&params).unwrap();
    assert!(private_key.is_some());
    assert_eq!(integer_to_string(&m.unwrap()).unwrap(), "RsaCracker");
}
