use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::{fmt, result};
use core::fmt::Formatter;
use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::jwk::Jwk;
use crate::serialization::b64_decode;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde::ser::SerializeStruct;

/// A basic trait defining the required functionality for a Header type
pub trait GetHeader {
    /// Get header
    fn get_header(&self) -> BaseHeader;
    /// Build a new instance of the header
    fn new(algorithm: Algorithm) -> Self;
}

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseHeader {
    /// The type of JWS: it can only be "JWT" here
    ///
    /// Defined in [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    pub typ: Option<String>,
    /// The algorithm used
    ///
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    pub alg: Algorithm,
    /// Content type
    ///
    /// Defined in [RFC7519#5.2](https://tools.ietf.org/html/rfc7519#section-5.2).
    pub cty: Option<String>,
    /// JSON Key URL
    ///
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    pub jku: Option<String>,
    /// JSON Web Key
    ///
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    pub jwk: Option<Jwk>,
    /// Key ID
    ///
    /// Defined in [RFC7515#4.1.4](https://tools.ietf.org/html/rfc7515#section-4.1.4).
    pub kid: Option<String>,
    /// X.509 URL
    ///
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    pub x5u: Option<String>,
    /// X.509 certificate chain. A Vec of base64 encoded ASN.1 DER certificates.
    ///
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    pub x5c: Option<Vec<String>>,
    /// X.509 SHA1 certificate thumbprint
    ///
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    pub x5t: Option<String>,
    /// X.509 SHA256 certificate thumbprint
    ///
    /// Defined in [RFC7515#4.1.8](https://tools.ietf.org/html/rfc7515#section-4.1.8).
    ///
    /// This will be serialized/deserialized as "x5t#S256", as defined by the RFC.
    pub x5t_s256: Option<String>,
}

impl Serialize for BaseHeader {
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        let mut count = 1;
        if self.typ.is_some() {
            count += 1;
        }
        if self.cty.is_some() {
            count += 1;
        }
        if self.jku.is_some() {
            count += 1;
        }
        if self.jwk.is_some() {
            count += 1;
        }
        if self.kid.is_some() {
            count += 1;
        }
        if self.x5u.is_some() {
            count += 1;
        }
        if self.x5c.is_some() {
            count += 1;
        }
        if self.x5t.is_some() {
            count += 1;
        }
        if self.x5t_s256.is_some() {
            count += 1;
        }
        let mut state = serializer.serialize_struct("BaseHeader", count)?;
        self.typ.clone().map_or((), |typ| state.serialize_field("typ", &typ).unwrap());
        state.serialize_field("alg", &self.alg)?;
        self.cty.clone().map_or((), |cty| state.serialize_field("cty", &cty).unwrap());
        self.jku.clone().map_or((), |jku| state.serialize_field("jku", &jku).unwrap());
        self.jwk.clone().map_or((), |jwk| state.serialize_field("jwk", &jwk).unwrap());
        self.kid.clone().map_or((), |kid| state.serialize_field("kid", &kid).unwrap());
        self.x5u.clone().map_or((), |x5u| state.serialize_field("x5u", &x5u).unwrap());
        self.x5c.clone().map_or((), |x5c| state.serialize_field("x5c", &x5c).unwrap());
        self.x5t.clone().map_or((), |x5t| state.serialize_field("x5t", &x5t).unwrap());
        self.x5t_s256.clone().map_or((), |x5t_s256| state.serialize_field("x5t#S256", &x5t_s256).unwrap());
        state.end()
    }
}


impl <'de> Deserialize<'de> for BaseHeader {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        const FIELDS: &[&str] = &["typ", "alg", "cty", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256"];
        enum Field{Typ, Alg, Cty, Jku, Jwk, Kid, X5u, X5c, X5t, X5tS256}
        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
            where
                D: Deserializer<'de>
            {
                struct FieldVisitor;
                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`typ` or `alg` or `cty` or `jku` or `jwk` or `kid` or `x5u` or `x5c` or `x5t` or `x5t#S256`")
                    }

                    fn visit_str<E>(self, value: &str) -> result::Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "typ" => Ok(Field::Typ),
                            "alg" => Ok(Field::Alg),
                            "cty" => Ok(Field::Cty),
                            "jku" => Ok(Field::Jku),
                            "jwk" => Ok(Field::Jwk),
                            "kid" => Ok(Field::Kid),
                            "x5u" => Ok(Field::X5u),
                            "x5c" => Ok(Field::X5c),
                            "x5t" => Ok(Field::X5t),
                            "x5t#S256" => Ok(Field::X5tS256),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }



        struct BaseHeaderVisitor;

        impl<'de> Visitor<'de> for BaseHeaderVisitor {
            type Value = BaseHeader;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct BaseHeader")
            }

            fn visit_seq<A>(self, mut seq: A) -> result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>
            {
                let typ = seq.next_element()?;
                let alg = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let cty = seq.next_element()?;
                let jku = seq.next_element()?;
                let jwk = seq.next_element()?;
                let kid = seq.next_element()?;
                let x5u = seq.next_element()?;
                let x5c = seq.next_element()?;
                let x5t = seq.next_element()?;
                let x5t_s256 = seq.next_element()?;
                Ok(
                    BaseHeader {
                        typ,
                        alg,
                        cty,
                        jku,
                        jwk,
                        kid,
                        x5u,
                        x5c,
                        x5t,
                        x5t_s256,
                    }
                )
            }

            fn visit_map<A>(self, mut map: A) -> result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>
            {
                let mut typ = None;
                let mut alg = None;
                let mut cty = None;
                let mut jku = None;
                let mut jwk = None;
                let mut kid = None;
                let mut x5u = None;
                let mut x5c = None;
                let mut x5t = None;
                let mut x5t_s256 = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Typ => {
                            if typ.is_some() {
                                return Err(de::Error::duplicate_field("typ"));
                            }
                            typ = Some(map.next_value()?);
                        }
                        Field::Alg => {
                            if alg.is_some() {
                                return Err(de::Error::duplicate_field("alg"));
                            }
                            alg = Some(map.next_value()?);
                        }
                        Field::Cty => {
                            if cty.is_some() {
                                return Err(de::Error::duplicate_field("cty"));
                            }
                            cty = Some(map.next_value()?);
                        }
                        Field::Jku => {
                            if jku.is_some() {
                                return Err(de::Error::duplicate_field("jku"));
                            }
                            jku = Some(map.next_value()?);
                        }
                        Field::Jwk => {
                            if jwk.is_some() {
                                return Err(de::Error::duplicate_field("jwk"));
                            }
                            jwk = Some(map.next_value()?);
                        }
                        Field::Kid => {
                            if kid.is_some() {
                                return Err(de::Error::duplicate_field("kid"));
                            }
                            kid = Some(map.next_value()?);
                        }
                        Field::X5u => {
                            if x5u.is_some() {
                                return Err(de::Error::duplicate_field("x5u"));
                            }
                            x5u = Some(map.next_value()?);
                        }
                        Field::X5c => {
                            if x5c.is_some() {
                                return Err(de::Error::duplicate_field("x5c"));
                            }
                            x5c = Some(map.next_value()?);
                        }
                        Field::X5t => {
                            if x5t.is_some() {
                                return Err(de::Error::duplicate_field("x5t"));
                            }
                            x5t = Some(map.next_value()?);
                        }
                        Field::X5tS256 => {
                            if x5t_s256.is_some() {
                                return Err(de::Error::duplicate_field("x5t#S256"));
                            }
                            x5t_s256 = Some(map.next_value()?);
                        }
                    }
                }
                let alg = alg.ok_or_else(|| de::Error::missing_field("alg"))?;
                Ok(
                    BaseHeader {
                        typ,
                        alg,
                        cty,
                        jku,
                        jwk,
                        kid,
                        x5u,
                        x5c,
                        x5t,
                        x5t_s256,
                    }
                )
            }
        }
        deserializer.deserialize_struct("BaseHeader", FIELDS, BaseHeaderVisitor)
    }
}

impl BaseHeader {
    /// Returns a JWT header with the algorithm given
    pub fn new(algorithm: Algorithm) -> Self {
        BaseHeader {
            typ: Some("JWT".to_string()),
            alg: algorithm,
            cty: None,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
        }
    }

    /// Decodes the X.509 certificate chain into ASN.1 DER format.
    pub fn x5c_der(&self) -> Result<Option<Vec<Vec<u8>>>> {
        Ok(self
            .x5c
            .as_ref()
            .map(|b64_certs| {
                b64_certs.iter().map(|x| STANDARD.decode(x)).collect::<result::Result<_, _>>()
            })
            .transpose()?)
    }
}

/// A basic container for headers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// inner header
    #[serde(flatten)]
    pub base: BaseHeader,
}

impl GetHeader for Header {
    fn get_header(&self) -> BaseHeader {
        self.base.clone()
    }

    fn new(algorithm: Algorithm) -> Self {
        Header{base: BaseHeader::new(algorithm)}
    }
}

/// Decodes a JWT header from a base64 encoded type
pub fn from_encoded<T: AsRef<[u8]>, H: DeserializeOwned>(encoded_part: T) -> Result<H> {
    let decoded = b64_decode(encoded_part)?;
    Ok(serde_json::from_slice(&decoded)?)
}

impl Default for BaseHeader {
    /// Returns a JWT header using the default Algorithm, HS256
    fn default() -> Self {
        BaseHeader::new(Algorithm::default())
    }
}

impl Default for Header {
    /// Returns a JWT header using the default Algorithm, HS256
    fn default() -> Self {
        Header { base: BaseHeader::default() }
    }
}
