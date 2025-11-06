use serde::{Deserialize, Serialize};
#[cfg(feature = "use_pem")]
use time::OffsetDateTime;
use wasm_bindgen_test::wasm_bindgen_test;

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey,
    crypto::{sign, verify},
    decode_header, jwt_signer_factory, jwt_verifier_factory,
};
#[cfg(feature = "use_pem")]
use jsonwebtoken::{Header, Validation, decode, encode};

const RSA_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_pem_pkcs1() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");
    let certificate_pem = include_bytes!("certificate_rsa_key_pkcs1.crt");

    for &alg in RSA_ALGORITHMS {
        let provider =
            jwt_signer_factory(&alg, &EncodingKey::from_rsa_pem(privkey_pem).unwrap()).unwrap();
        let mut encrypted = String::new();
        sign(&provider, b"hello world", &mut encrypted).unwrap();

        let is_valid = verify(
            &encrypted,
            b"hello world",
            &DecodingKey::from_rsa_pem(pubkey_pem).unwrap(),
            alg,
        )
        .unwrap();
        assert!(is_valid);

        let cert_is_valid = verify(
            &encrypted,
            b"hello world",
            &DecodingKey::from_rsa_pem(certificate_pem).unwrap(),
            alg,
        )
        .unwrap();
        assert!(cert_is_valid);
    }
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_pem_pkcs8() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs8.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs8.pem");
    let certificate_pem = include_bytes!("certificate_rsa_key_pkcs8.crt");

    for &alg in RSA_ALGORITHMS {
        let provider =
            jwt_signer_factory(&alg, &EncodingKey::from_rsa_pem(privkey_pem).unwrap()).unwrap();
        let mut encrypted = String::new();
        sign(&provider, b"hello world", &mut encrypted).unwrap();

        let is_valid = verify(
            &encrypted,
            b"hello world",
            &DecodingKey::from_rsa_pem(pubkey_pem).unwrap(),
            alg,
        )
        .unwrap();
        assert!(is_valid);

        let cert_is_valid = verify(
            &encrypted,
            b"hello world",
            &DecodingKey::from_rsa_pem(certificate_pem).unwrap(),
            alg,
        )
        .unwrap();
        assert!(cert_is_valid);
    }
}

#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_der() {
    let privkey_der = include_bytes!("private_rsa_key.der");
    let pubkey_der = include_bytes!("public_rsa_key.der");

    for &alg in RSA_ALGORITHMS {
        let provider = jwt_signer_factory(&alg, &EncodingKey::from_rsa_der(privkey_der)).unwrap();
        let mut encrypted = String::new();
        sign(&provider, b"hello world", &mut encrypted).unwrap();
        let is_valid =
            verify(&encrypted, b"hello world", &DecodingKey::from_rsa_der(pubkey_der), alg)
                .unwrap();
        assert!(is_valid);
    }
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");
    let certificate_pem = include_bytes!("certificate_rsa_key_pkcs1.crt");

    for &alg in RSA_ALGORITHMS {
        let header = Header::new(alg);
        let signing_provider =
            jwt_signer_factory(&header.alg, &EncodingKey::from_rsa_pem(privkey_pem).unwrap())
                .unwrap();
        let mut token = String::new();
        encode(&signing_provider, &header, &my_claims, &mut token).unwrap();
        let header: Header = decode_header(token.as_str()).unwrap();
        let decoding_provider =
            jwt_verifier_factory(&header.alg, &DecodingKey::from_rsa_pem(pubkey_pem).unwrap())
                .unwrap();
        let token_data =
            decode::<Claims, Header>(&decoding_provider, &header.alg, &token, &Validation::new(alg))
                .unwrap();
        assert_eq!(my_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());

        let decoding_provider =
            jwt_verifier_factory(&header.alg, &DecodingKey::from_rsa_pem(certificate_pem).unwrap())
                .unwrap();
        let cert_token_data =
            decode::<Claims, Header>(&decoding_provider, &header.alg, &token, &Validation::new(alg))
                .unwrap();
        assert_eq!(my_claims, cert_token_data.claims);
        assert!(cert_token_data.header.kid.is_none());
    }
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn rsa_modulus_exponent() {
    let privkey = include_str!("private_rsa_key_pkcs1.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let n = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
    let e = "AQAB";

    let header = Header::new(Algorithm::RS256);
    let signing_provider =
        jwt_signer_factory(&header.alg, &EncodingKey::from_rsa_pem(privkey.as_ref()).unwrap())
            .unwrap();
    let mut encrypted = String::new();
    encode(&signing_provider, &header, &my_claims, &mut encrypted).unwrap();
    let header: Header = decode_header(encrypted.as_str()).unwrap();
    let decoding_provider =
        jwt_verifier_factory(&header.alg, &DecodingKey::from_rsa_components(n, e).unwrap())
            .unwrap();
    let res = decode::<Claims, Header>(
        &decoding_provider,
        &header.alg,
        &encrypted,
        &Validation::new(Algorithm::RS256),
    );
    assert!(res.is_ok());
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn rsa_jwk() {
    use jsonwebtoken::jwk::Jwk;
    use serde_json::json;

    let privkey = include_str!("private_rsa_key_pkcs8.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let jwk:Jwk = serde_json::from_value(json!({
        "kty": "RSA",
        "n": "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
        "e": "AQAB",
        "kid": "rsa01",
        "alg": "RS256",
        "use": "sig"
    })).unwrap();

    let header = Header::new(Algorithm::RS256);
    let signing_provider =
        jwt_signer_factory(&header.alg, &EncodingKey::from_rsa_pem(privkey.as_ref()).unwrap())
            .unwrap();
    let mut encrypted = String::new();
    encode(&signing_provider, &header, &my_claims, &mut encrypted).unwrap();
    let header: Header = decode_header(encrypted.as_str()).unwrap();
    let decoding_provider =
        jwt_verifier_factory(&header.alg, &DecodingKey::from_jwk(&jwk).unwrap()).unwrap();
    let res = decode::<Claims, Header>(
        &decoding_provider,
        &header.alg,
        &encrypted,
        &Validation::new(Algorithm::RS256),
    );
    assert!(res.is_ok());
}

// https://jwt.io/ is often used for examples so ensure their example works with jsonwebtoken
#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn roundtrip_with_jwtio_example_jey() {
    let privkey_pem = include_bytes!("private_jwtio.pem");
    let pubkey_pem = include_bytes!("public_jwtio.pem");
    let certificate_pem = include_bytes!("certificate_jwtio.crt");

    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };

    for &alg in RSA_ALGORITHMS {
        let header = Header::new(alg);
        let signing_provider =
            jwt_signer_factory(&header.alg, &EncodingKey::from_rsa_pem(privkey_pem).unwrap())
                .unwrap();
        let mut token = String::new();
        encode(&signing_provider, &header, &my_claims, &mut token).unwrap();

        let header: Header = decode_header(token.as_str()).unwrap();
        let decoding_provider =
            jwt_verifier_factory(&header.alg, &DecodingKey::from_rsa_pem(pubkey_pem).unwrap())
                .unwrap();
        let token_data =
            decode::<Claims, Header>(&decoding_provider, &header.alg, &token, &Validation::new(alg))
                .unwrap();
        assert_eq!(my_claims, token_data.claims);

        let decoding_provider =
            jwt_verifier_factory(&header.alg, &DecodingKey::from_rsa_pem(certificate_pem).unwrap())
                .unwrap();
        let cert_token_data =
            decode::<Claims, Header>(&decoding_provider, &header.alg, &token, &Validation::new(alg))
                .unwrap();
        assert_eq!(my_claims, cert_token_data.claims);
    }
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn rsa_jwk_from_key() {
    use jsonwebtoken::jwk::Jwk;
    use serde_json::json;

    let privkey = include_str!("private_rsa_key_pkcs8.pem");
    let encoding_key = EncodingKey::from_rsa_pem(privkey.as_ref()).unwrap();
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
    assert_eq!(jwk, serde_json::from_value(json!({
        "kty": "RSA",
        "n": "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
        "e": "AQAB",
        "alg": "RS256",
    })).unwrap());
}
