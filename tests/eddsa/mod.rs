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

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_pk8() {
    let privkey = include_bytes!("private_ed25519_key.pk8");
    let pubkey = include_bytes!("public_ed25519_key.pk8");

    let provider =
        jwt_signer_factory(&Algorithm::EdDSA, &EncodingKey::from_ed_der(privkey)).unwrap();
    let mut encrypted = String::new();
    sign(&provider, b"hello world", &mut encrypted).unwrap();
    let is_valid =
        verify(&encrypted, b"hello world", &DecodingKey::from_ed_der(pubkey), Algorithm::EdDSA)
            .unwrap();
    assert!(is_valid);
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_pem() {
    let privkey_pem = include_bytes!("private_ed25519_key.pem");
    let pubkey_pem = include_bytes!("public_ed25519_key.pem");
    let provider =
        jwt_signer_factory(&Algorithm::EdDSA, &EncodingKey::from_ed_pem(privkey_pem).unwrap())
            .unwrap();
    let mut encrypted = String::new();
    sign(&provider, b"hello world", &mut encrypted).unwrap();
    let is_valid = verify(
        &encrypted,
        b"hello world",
        &DecodingKey::from_ed_pem(pubkey_pem).unwrap(),
        Algorithm::EdDSA,
    )
    .unwrap();
    assert!(is_valid);
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_claim() {
    let privkey_pem = include_bytes!("private_ed25519_key.pem");
    let pubkey_pem = include_bytes!("public_ed25519_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let header = Header::new(Algorithm::EdDSA);
    let signing_provider =
        jwt_signer_factory(&header.alg, &EncodingKey::from_ed_pem(privkey_pem).unwrap()).unwrap();
    let mut token = String::new();
    encode(&signing_provider, &header, &my_claims, &mut token).unwrap();
    let header: Header = decode_header(token.as_str()).unwrap();
    let decoding_provider =
        jwt_verifier_factory(&header.alg, &DecodingKey::from_ed_pem(pubkey_pem).unwrap()).unwrap();
    let token_data = decode::<Claims, Header>(
        &decoding_provider,
        &header.alg,
        &token,
        &Validation::new(Algorithm::EdDSA),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn ed_x() {
    let privkey = include_str!("private_ed25519_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let x = "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8";

    let header = Header::new(Algorithm::EdDSA);
    let signing_provider =
        jwt_signer_factory(&header.alg, &EncodingKey::from_ed_pem(privkey.as_ref()).unwrap())
            .unwrap();

    let mut encrypted = String::new();
    encode(&signing_provider, &header, &my_claims, &mut encrypted).unwrap();
    let header: Header = decode_header(encrypted.as_str()).unwrap();
    let decoding_provider =
        jwt_verifier_factory(&header.alg, &DecodingKey::from_ed_components(x).unwrap()).unwrap();
    let res = decode::<Claims, Header>(
        &decoding_provider,
        &header.alg,
        &encrypted,
        &Validation::new(Algorithm::EdDSA),
    );
    assert!(res.is_ok());
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn ed_jwk() {
    use jsonwebtoken::jwk::Jwk;
    use serde_json::json;

    let privkey = include_str!("private_ed25519_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let jwk: Jwk = serde_json::from_value(json!({
            "kty": "OKP",
            "use": "sig",
            "crv": "Ed25519",
            "x": "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8",
            "kid": "ed01",
            "alg": "EdDSA"
    }))
    .unwrap();

    let header = Header::new(Algorithm::EdDSA);
    let signing_provider =
        jwt_signer_factory(&header.alg, &EncodingKey::from_ed_pem(privkey.as_ref()).unwrap())
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
        &Validation::new(Algorithm::EdDSA),
    );
    assert!(res.is_ok());
}
