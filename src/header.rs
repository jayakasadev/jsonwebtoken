use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::result;
use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::jwk::Jwk;
use crate::serialization::b64_decode;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// A basic trait defining the required functionality for a Header type
pub trait GetHeader {
    /// Get header
    fn get_header(&self) -> BaseHeader;
}

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseHeader {
    /// The type of JWS: it can only be "JWT" here
    ///
    /// Defined in [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// The algorithm used
    ///
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    pub alg: Algorithm,
    /// Content type
    ///
    /// Defined in [RFC7519#5.2](https://tools.ietf.org/html/rfc7519#section-5.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    /// JSON Key URL
    ///
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    /// JSON Web Key
    ///
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// Key ID
    ///
    /// Defined in [RFC7515#4.1.4](https://tools.ietf.org/html/rfc7515#section-4.1.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// X.509 URL
    ///
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    /// X.509 certificate chain. A Vec of base64 encoded ASN.1 DER certificates.
    ///
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// X.509 SHA1 certificate thumbprint
    ///
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    /// X.509 SHA256 certificate thumbprint
    ///
    /// Defined in [RFC7515#4.1.8](https://tools.ietf.org/html/rfc7515#section-4.1.8).
    ///
    /// This will be serialized/deserialized as "x5t#S256", as defined by the RFC.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<String>,
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

impl Header {
    /// Basic builder
    pub fn new(algorithm: Algorithm) -> Self {
        Header{base: BaseHeader::new(algorithm)}
    }
}

impl GetHeader for Header {
    fn get_header(&self) -> BaseHeader {
        self.base.clone()
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
