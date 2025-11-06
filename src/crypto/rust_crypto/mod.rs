use crate::Algorithm;
use crate::crypto::rust_crypto::ecdsa::{Es256Signer, Es256Verifier, Es384Signer, Es384Verifier};
use crate::crypto::rust_crypto::eddsa::{EdDSASigner, EdDSAVerifier};
use crate::crypto::rust_crypto::hmac::{
    Hs256Signer, Hs256Verifier, Hs384Signer, Hs384Verifier, Hs512Signer, Hs512Verifier,
};
use crate::crypto::rust_crypto::rsa::{
    Rsa256Signer, Rsa256Verifier, Rsa384Signer, Rsa384Verifier, Rsa512Signer, Rsa512Verifier,
    RsaPss256Signer, RsaPss256Verifier, RsaPss384Signer, RsaPss384Verifier, RsaPss512Signer,
    RsaPss512Verifier,
};
use crate::crypto::{JwtSigner, JwtVerifier};
use alloc::vec::Vec;
use signature::{Signer, Verifier};

pub(crate) mod ecdsa;
pub(crate) mod eddsa;
pub(crate) mod hmac;
pub(crate) mod rsa;

/// Verifying algorithms supported by `jsonwebtoken`
#[derive(Debug)]
pub enum VerifierAlgorithm {
    /// HS256
    HS256(Hs256Verifier),
    /// HS384
    HS384(Hs384Verifier),
    /// HS512
    HS512(Hs512Verifier),
    /// ES256
    ES256(Es256Verifier),
    /// ES384
    ES384(Es384Verifier),
    /// RS256
    RS256(Rsa256Verifier),
    /// RS384
    RS384(Rsa384Verifier),
    /// RS512
    RS512(Rsa512Verifier),
    /// PS256
    PS256(RsaPss256Verifier),
    /// PS384
    PS384(RsaPss384Verifier),
    /// PS512
    PS512(RsaPss512Verifier),
    /// EdDSA
    EdDSA(EdDSAVerifier),
}

/// Signing algorithms supported by `jsonwebtoken`
#[derive(Debug)]
pub enum SignerAlgorithm {
    /// HS256
    HS256(Hs256Signer),
    /// HS384
    HS384(Hs384Signer),
    /// HS512
    HS512(Hs512Signer),
    /// ES256
    ES256(Es256Signer),
    /// ES384
    ES384(Es384Signer),
    /// RS256
    RS256(Rsa256Signer),
    /// RS384
    RS384(Rsa384Signer),
    /// RS512
    RS512(Rsa512Signer),
    /// PS256
    PS256(RsaPss256Signer),
    /// PS384
    PS384(RsaPss384Signer),
    /// PS512
    PS512(RsaPss512Signer),
    /// EdDSA
    EdDSA(EdDSASigner),
}

impl VerifierAlgorithm {
    pub(crate) fn algorithm(&self) -> Algorithm {
        match self {
            VerifierAlgorithm::HS256(alg) => alg.algorithm(),
            VerifierAlgorithm::HS384(alg) => alg.algorithm(),
            VerifierAlgorithm::HS512(alg) => alg.algorithm(),
            VerifierAlgorithm::ES256(alg) => alg.algorithm(),
            VerifierAlgorithm::ES384(alg) => alg.algorithm(),
            VerifierAlgorithm::RS256(alg) => alg.algorithm(),
            VerifierAlgorithm::RS384(alg) => alg.algorithm(),
            VerifierAlgorithm::RS512(alg) => alg.algorithm(),
            VerifierAlgorithm::PS256(alg) => alg.algorithm(),
            VerifierAlgorithm::PS384(alg) => alg.algorithm(),
            VerifierAlgorithm::PS512(alg) => alg.algorithm(),
            VerifierAlgorithm::EdDSA(alg) => alg.algorithm(),
        }
    }

    /// Verify signature
    pub fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> Result<(), signature::Error> {
        match self {
            VerifierAlgorithm::HS256(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::HS384(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::HS512(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::ES256(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::ES384(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::RS256(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::RS384(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::RS512(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::PS256(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::PS384(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::PS512(alg) => alg.verify(msg, signature),
            VerifierAlgorithm::EdDSA(alg) => alg.verify(msg, signature),
        }
    }
}

impl SignerAlgorithm {
    pub(crate) fn algorithm(&self) -> Algorithm {
        match self {
            SignerAlgorithm::HS256(alg) => alg.algorithm(),
            SignerAlgorithm::HS384(alg) => alg.algorithm(),
            SignerAlgorithm::HS512(alg) => alg.algorithm(),
            SignerAlgorithm::ES256(alg) => alg.algorithm(),
            SignerAlgorithm::ES384(alg) => alg.algorithm(),
            SignerAlgorithm::RS256(alg) => alg.algorithm(),
            SignerAlgorithm::RS384(alg) => alg.algorithm(),
            SignerAlgorithm::RS512(alg) => alg.algorithm(),
            SignerAlgorithm::PS256(alg) => alg.algorithm(),
            SignerAlgorithm::PS384(alg) => alg.algorithm(),
            SignerAlgorithm::PS512(alg) => alg.algorithm(),
            SignerAlgorithm::EdDSA(alg) => alg.algorithm(),
        }
    }
    /// Sign message
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            SignerAlgorithm::HS256(alg) => alg.sign(msg),
            SignerAlgorithm::HS384(alg) => alg.sign(msg),
            SignerAlgorithm::HS512(alg) => alg.sign(msg),
            SignerAlgorithm::ES256(alg) => alg.sign(msg),
            SignerAlgorithm::ES384(alg) => alg.sign(msg),
            SignerAlgorithm::RS256(alg) => alg.sign(msg),
            SignerAlgorithm::RS384(alg) => alg.sign(msg),
            SignerAlgorithm::RS512(alg) => alg.sign(msg),
            SignerAlgorithm::PS256(alg) => alg.sign(msg),
            SignerAlgorithm::PS384(alg) => alg.sign(msg),
            SignerAlgorithm::PS512(alg) => alg.sign(msg),
            SignerAlgorithm::EdDSA(alg) => alg.sign(msg),
        }
    }
}
