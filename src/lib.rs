//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![no_std]
#![deny(missing_docs)]
extern crate alloc;

mod algorithms;
/// Lower level functions, if you want to do something other than JWTs
pub mod crypto;
mod decoding;
mod encoding;
/// All the errors that can be encountered while encoding/decoding JWTs
pub mod errors;
/// All the header fields that can be used in JWTs
pub mod header;
pub mod jwk;
#[cfg(feature = "use_pem")]
mod pem;
mod serialization;
mod validation;

pub use algorithms::Algorithm;
pub use decoding::{decode, decode_header, DecodingKey, TokenData};
pub use encoding::{encode, EncodingKey};
pub use header::{GetHeader, Header};
pub use validation::{get_current_timestamp, Validation};
