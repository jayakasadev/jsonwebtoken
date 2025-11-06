extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use serde::ser::Serialize;

use crate::algorithms::AlgorithmFamily;
use crate::errors::{ErrorKind, Result, new_error};
#[cfg(feature = "use_pem")]
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{b64_encode, b64_encode_part};
use crate::{Algorithm, BaseHeader};
// Crypto
#[cfg(feature = "aws_lc_rs")]
use crate::crypto::aws_lc::{
    ecdsa::{Es256Signer, Es384Signer},
    eddsa::EdDSASigner,
    hmac::{Hs256Signer, Hs384Signer, Hs512Signer},
    rsa::{
        Rsa256Signer, Rsa384Signer, Rsa512Signer, RsaPss256Signer, RsaPss384Signer, RsaPss512Signer,
    },
};
use crate::crypto::rust_crypto::SignerAlgorithm;
#[cfg(feature = "rust_crypto")]
use crate::crypto::rust_crypto::{
    ecdsa::{Es256Signer, Es384Signer},
    eddsa::EdDSASigner,
    hmac::{Hs256Signer, Hs384Signer, Hs512Signer},
    rsa::{
        Rsa256Signer, Rsa384Signer, Rsa512Signer, RsaPss256Signer, RsaPss384Signer, RsaPss512Signer,
    },
};

/// A key to encode a JWT with. Can be a secret, a PEM-encoded key or a DER-encoded key.
/// This key can be re-used so make sure you only initialize it once if you can for better performance.
#[derive(Clone)]
pub struct EncodingKey {
    pub(crate) family: AlgorithmFamily,
    pub(crate) content: Vec<u8>,
}

impl EncodingKey {
    /// The algorithm family this key is for.
    pub fn family(&self) -> AlgorithmFamily {
        self.family
    }

    /// If you're using a HMAC secret that is not base64, use that.
    pub fn from_secret(secret: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Hmac, content: secret.to_vec() }
    }

    /// If you have a base64 HMAC secret, use that.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        let out = STANDARD.decode(secret)?;
        Ok(EncodingKey { family: AlgorithmFamily::Hmac, content: out })
    }

    /// For loading websafe base64 HMAC secrets, ex: ACME EAB credentials.
    pub fn from_urlsafe_base64_secret(secret: &str) -> Result<Self> {
        let out = URL_SAFE.decode(secret)?;
        Ok(EncodingKey { family: AlgorithmFamily::Hmac, content: out })
    }

    /// If you are loading a RSA key from a .pem file.
    /// This errors if the key is not a valid RSA key.
    /// Only exists if the feature `use_pem` is enabled.
    ///
    /// # NOTE
    ///
    /// According to the [ring doc](https://docs.rs/ring/latest/ring/signature/struct.RsaKeyPair.html#method.from_pkcs8),
    /// the key should be at least 2047 bits.
    ///
    #[cfg(feature = "use_pem")]
    pub fn from_rsa_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_rsa_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Rsa, content: content.to_vec() })
    }

    /// If you are loading a ECDSA key from a .pem file
    /// This errors if the key is not a valid private EC key
    /// Only exists if the feature `use_pem` is enabled.
    ///
    /// # NOTE
    ///
    /// The key should be in PKCS#8 form.
    ///
    /// You can generate a key with the following:
    ///
    /// ```sh
    /// openssl ecparam -genkey -noout -name prime256v1 \
    ///     | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
    /// ```
    #[cfg(feature = "use_pem")]
    pub fn from_ec_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ec_private_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Ec, content: content.to_vec() })
    }

    /// If you are loading a EdDSA key from a .pem file
    /// This errors if the key is not a valid private Ed key
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ed_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ed_private_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Ed, content: content.to_vec() })
    }

    /// If you know what you're doing and have the DER-encoded key, for RSA only
    pub fn from_rsa_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Rsa, content: der.to_vec() }
    }

    /// If you know what you're doing and have the DER-encoded key, for ECDSA
    pub fn from_ec_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Ec, content: der.to_vec() }
    }

    /// If you know what you're doing and have the DER-encoded key, for EdDSA
    pub fn from_ed_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Ed, content: der.to_vec() }
    }

    pub(crate) fn inner(&self) -> &[u8] {
        &self.content
    }

    pub(crate) fn try_get_hmac_secret(&self) -> Result<&[u8]> {
        if self.family == AlgorithmFamily::Hmac {
            Ok(self.inner())
        } else {
            Err(new_error(ErrorKind::InvalidKeyFormat))
        }
    }
}

impl Debug for EncodingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncodingKey")
            .field("family", &self.family)
            .field("content", &"[redacted]")
            .finish()
    }
}

/// Encode the header and claims given and sign the payload using the algorithm from the header and the key.
/// If the algorithm given is RSA or EC, the key needs to be in the PEM format.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{encode, Algorithm, Header, EncodingKey, jwt_signer_factory};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let my_claims = Claims {
///     sub: "b@b.com".to_owned(),
///     company: "ACME".to_owned()
/// };
///
/// // my_claims is a struct that implements Serialize
/// // This will create a JWT using HS256 as algorithm
/// let header = Header::default();
/// let signing_provider = jwt_signer_factory(&header.alg, &EncodingKey::from_secret("secret".as_ref())).unwrap();
/// let mut token = String::new();
/// encode(&signing_provider, &Header::default(), &my_claims, &mut token).unwrap();
/// ```
pub fn encode<T: Serialize, H: BaseHeader + Serialize>(
    signing_provider: &SignerAlgorithm,
    header: &H,
    claims: &T,
    data: &mut String,
) -> Result<()> {
    if signing_provider.algorithm() != header.algorithm() {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    b64_encode_part(&header, data)?;
    data.push('.');
    b64_encode_part(claims, data)?;

    let signature = signing_provider.sign(data.as_bytes());
    data.push('.');
    b64_encode(&signature, data);

    Ok(())
}

/// Return the correct [`JwtSigner`] based on the `algorithm`.
pub fn jwt_signer_factory(
    algorithm: &Algorithm,
    key: &EncodingKey,
) -> Result<Box<SignerAlgorithm>> {
    if key.family != algorithm.family() {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    let jwt_signer = match algorithm {
        Algorithm::HS256 => Box::new(SignerAlgorithm::HS256(Hs256Signer::new(key)?)),
        Algorithm::HS384 => Box::new(SignerAlgorithm::HS384(Hs384Signer::new(key)?)),
        Algorithm::HS512 => Box::new(SignerAlgorithm::HS512(Hs512Signer::new(key)?)),
        Algorithm::ES256 => Box::new(SignerAlgorithm::ES256(Es256Signer::new(key)?)),
        Algorithm::ES384 => Box::new(SignerAlgorithm::ES384(Es384Signer::new(key)?)),
        Algorithm::RS256 => Box::new(SignerAlgorithm::RS256(Rsa256Signer::new(key)?)),
        Algorithm::RS384 => Box::new(SignerAlgorithm::RS384(Rsa384Signer::new(key)?)),
        Algorithm::RS512 => Box::new(SignerAlgorithm::RS512(Rsa512Signer::new(key)?)),
        Algorithm::PS256 => Box::new(SignerAlgorithm::PS256(RsaPss256Signer::new(key)?)),
        Algorithm::PS384 => Box::new(SignerAlgorithm::PS384(RsaPss384Signer::new(key)?)),
        Algorithm::PS512 => Box::new(SignerAlgorithm::PS512(RsaPss512Signer::new(key)?)),
        Algorithm::EdDSA => Box::new(SignerAlgorithm::EdDSA(EdDSASigner::new(key)?)),
    };

    Ok(jwt_signer)
}
