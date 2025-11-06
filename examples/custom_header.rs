extern crate alloc;
use alloc::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    jwt_signer_factory, jwt_verifier_factory,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    company: String,
    exp: u64,
}

fn main() {
    let my_claims =
        Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 10000000000 };
    let key = b"secret";

    let mut extras = BTreeMap::new();
    extras.insert("custom".to_string(), "header".to_string());

    let header = Header {
        kid: Some("signing_key".to_owned()),
        alg: Algorithm::HS512,
        extras,
        ..Default::default()
    };
    let signing_provider = jwt_signer_factory(&header.alg, &EncodingKey::from_secret(key)).unwrap();
    let mut token = String::new();

    match encode(&signing_provider, &header, &my_claims, &mut token) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };
    println!("{:?}", token);

    let header: Header = decode_header(token.as_str()).unwrap();
    let decoding_provider =
        jwt_verifier_factory(&header.alg, &DecodingKey::from_secret(key)).unwrap();

    let token_data = match decode::<Claims, Header>(
        &decoding_provider,
        &header.alg,
        &token,
        &Validation::new(Algorithm::HS512),
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!(),
        },
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}
