use serde::{Deserialize, Serialize};

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    jwt_signer_factory, jwt_verifier_factory,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    aud: String,
    sub: String,
    company: String,
    exp: u64,
}

fn main() {
    let key = b"secret";
    let my_claims = Claims {
        aud: "me".to_owned(),
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned(),
        exp: 10000000000,
    };
    let header = Header::default();
    let signing_provider = jwt_signer_factory(&header.alg, &EncodingKey::from_secret(key)).unwrap();
    let mut token = String::new();
    match encode(&signing_provider, &header, &my_claims, &mut token) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    let mut validation = Validation::new(Algorithm::HS256);
    validation.sub = Some("b@b.com".to_string());
    validation.set_audience(&["me"]);
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    let header: Header = decode_header(token.as_str()).unwrap();
    let decoding_provider =
        jwt_verifier_factory(&header.alg, &DecodingKey::from_secret(key)).unwrap();
    let token_data =
        match decode::<Claims, Header>(&decoding_provider, &header.alg, &token, &validation) {
            Ok(c) => c,
            Err(err) => match *err.kind() {
                ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
                ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
                _ => panic!("Some other errors"),
            },
        };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}
