// TODO:
// - Add doc links to the spec where applicable
// - Consider limiting exposed types only to what the user will need
// - Test integration with existing azure storage crates
// - Compare to old azure_storage and azure_storage_blobs URL generators
//
#![doc = include_str!("../README.md")]

mod key;
pub(crate) mod resource;
pub(crate) mod sas;

#[cfg(test)]
pub(crate) mod test_utils;

pub mod error;
pub use key::{UserDelegationKey, UserDelegationKeyFetcher};
pub use resource::{Resource, blob, file, queue, table};
pub use sas::SignedProtocol;
pub use sas::builder::UserDelegationSasBuilder;

/// Re-export of the [`time`] crate.
pub use time;
/// Re-export of the [`url`] crate.
pub use url;
