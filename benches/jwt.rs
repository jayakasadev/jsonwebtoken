use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jsonwebtoken::{decode, encode, Algorithm, BaseHeader, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CustomHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    pub alg: Algorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<String>,
}

impl BaseHeader for CustomHeader {
    fn get_algorithm(&self) -> Algorithm {
        self.alg
    }
}

fn bench_encode(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned() };
    let key = EncodingKey::from_secret("secret".as_ref());

    c.bench_function("bench_encode", |b| {
        b.iter(|| encode(black_box(&Header::default()), black_box(&claim), black_box(&key)))
    });
}

fn bench_encode_custom_header(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned() };
    let key = EncodingKey::from_secret("secret".as_ref());

    let header = CustomHeader {
        kid: Some("kid".to_string()),
        custom: Some("header".to_string()),
        ..Default::default()
    };

    c.bench_function("bench_encode", |b| {
        b.iter(|| encode(black_box(&header), black_box(&claim), black_box(&key)))
    });
}

fn bench_decode(c: &mut Criterion) {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    let key = DecodingKey::from_secret("secret".as_ref());

    c.bench_function("bench_decode", |b| {
        b.iter(|| {
            decode::<Header, Claims>(
                black_box(token),
                black_box(&key),
                black_box(&Validation::new(Algorithm::HS256)),
            )
        })
    });
}

criterion_group!(benches, bench_encode, bench_encode_custom_header, bench_decode);
criterion_main!(benches);
