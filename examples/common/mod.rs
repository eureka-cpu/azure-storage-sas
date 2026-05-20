//! Shared test-fixture data for the blob SAS examples.
//!
//! Each example includes this module with `#[path = "common/mod.rs"] mod common;`.

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use time::{Duration, OffsetDateTime};

pub const ACCOUNT: &str = "devstoreaccount1";
pub const BLOB_ENDPOINT: &str = "https://127.0.0.1:10000/devstoreaccount1";

/// A minimal unsigned JWT that Azurite's `--oauth basic` mode accepts.
///
/// Header:  `{"alg":"none","typ":"JWT"}`
/// Payload: `{"aud":"https://storage.azure.com","iss":"https://sts.windows.net/tid-test/",
///           "iat":1000000000,"nbf":1000000000,"exp":9999999999,
///           "oid":"oid-test","tid":"tid-test"}`
///
/// Azurite validates that `iss` starts with a known STS prefix, and that `iat`, `nbf`,
/// and `exp` are all present. The signature part is empty (`alg: none`).
const DUMMY_JWT: &str = concat!(
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
    ".",
    "eyJhdWQiOiJodHRwczovL3N0b3JhZ2UuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvdGlkLXRlc3QvIiwiaWF0IjoxMDAwMDAwMDAwLCJuYmYiOjEwMDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OSwib2lkIjoib2lkLXRlc3QiLCJ0aWQiOiJ0aWQtdGVzdCJ9",
    "."
);

/// Implements [`TokenCredential`] by returning [`DUMMY_JWT`], which Azurite accepts in
/// `--oauth basic` mode without signature validation.
#[derive(Debug)]
pub struct DummyCredential;

#[async_trait::async_trait]
impl TokenCredential for DummyCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Ok(AccessToken::new(
            DUMMY_JWT,
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
    }
}
