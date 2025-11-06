extern crate alloc;
use alloc::collections::BTreeMap;
use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    jwt_signer_factory, jwt_verifier_factory,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
}

fn bench_encode(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned() };
    let key = EncodingKey::from_secret("secret".as_ref());
    let header = Header::default();
    let signing_provider = jwt_signer_factory(&header.alg, &key).unwrap();
    let mut data = String::with_capacity(1000);

    c.bench_function("bench_encode", |b| {
        b.iter(|| {
            encode(
                black_box(&signing_provider),
                black_box(&header),
                black_box(&claim),
                black_box(&mut data),
            )
            .unwrap();
            data.clear();
        })
    });
}

fn bench_encode_custom_extra_headers(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned() };
    let key = EncodingKey::from_secret("secret".as_ref());
    let mut extras = BTreeMap::new();
    extras.insert("custom".to_string(), "header".to_string());
    let header = Header { extras, ..Default::default() };
    let signing_provider = jwt_signer_factory(&header.alg, &key).unwrap();
    let mut data = String::with_capacity(1000);

    c.bench_function("bench_encode", |b| {
        b.iter(|| {
            encode(
                black_box(&signing_provider),
                black_box(&header),
                black_box(&claim),
                black_box(&mut data),
            )
            .unwrap();
            data.clear();
        })
    });
}

fn bench_decode(c: &mut Criterion) {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    let key = DecodingKey::from_secret("secret".as_ref());
    let header: Header = decode_header(token).unwrap();
    let decoding_provider = jwt_verifier_factory(&header.alg, &key).unwrap();

    c.bench_function("bench_decode", |b| {
        b.iter(|| {
            decode::<Claims, Header>(
                black_box(&decoding_provider),
                black_box(&header.alg),
                black_box(token),
                black_box(&Validation::new(Algorithm::HS256)),
            )
        })
    });
}

criterion_group!(benches, bench_encode, bench_encode_custom_extra_headers, bench_decode);
criterion_main!(benches);
