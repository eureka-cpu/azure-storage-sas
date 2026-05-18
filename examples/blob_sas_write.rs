//! Demonstrates writing then reading a blob using user delegation SAS tokens.
//!
//! # Prerequisites
//!
//! Generate a self-signed TLS cert once per machine (gitignored, not committed):
//!
//! ```sh
//! openssl req -x509 -newkey rsa:2048 \
//!   -keyout dev-certs/key.pem -out dev-certs/cert.pem \
//!   -days 3650 -nodes -subj "/CN=127.0.0.1" \
//!   -addext "subjectAltName=IP:127.0.0.1"
//! ```
//!
//! Start Azurite with OAuth + TLS:
//!
//! ```sh
//! azurite --oauth basic --skipApiVersionCheck \
//!   --cert dev-certs/cert.pem --key dev-certs/key.pem
//! ```
//!
//! Then run with:
//!
//! ```sh
//! cargo run --example blob_sas_write
//! ```

use std::sync::Arc;

use azure_core::{
    Bytes,
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    http::{ClientOptions, Transport},
};
use azure_storage_blob::{
    BlobClient, BlobClientOptions, BlobServiceClient, BlobServiceClientOptions,
};
use azure_storage_sas::{
    UserDelegationKeyFetcher, UserDelegationSasBuilder,
    blob::{BlobResource, BlobSasPermissions},
};
use time::{Duration, OffsetDateTime};
use url::Url;

const ACCOUNT: &str = "devstoreaccount1";
const BLOB_ENDPOINT: &str = "https://127.0.0.1:10000/devstoreaccount1";

/// A minimal unsigned JWT that Azurite's `--oauth basic` mode accepts.
///
/// Header:  {"alg":"none","typ":"JWT"}
/// Payload: {"aud":"https://storage.azure.com","iss":"https://sts.windows.net/tid-test/",
///           "iat":1000000000,"nbf":1000000000,"exp":9999999999,
///           "oid":"oid-test","tid":"tid-test"}
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
struct DummyCredential;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .pretty()
        .init();

    const CONTAINER: &str = "sas-write-example";
    const BLOB: &str = "written-via-sas.txt";
    const CONTENT: &str = "Written through a user delegation SAS";

    // Create a service client authenticated with a Bearer token credential.
    // `danger_accept_invalid_certs` is needed for Azurite's self-signed TLS cert.
    let service = BlobServiceClient::new(
        Url::parse(BLOB_ENDPOINT)?,
        Some(Arc::new(DummyCredential)),
        Some(BlobServiceClientOptions {
            client_options: ClientOptions {
                transport: Some(Transport::new(Arc::new(
                    reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .build()?,
                ))),
                ..Default::default()
            },
            ..Default::default()
        }),
    )?;

    // Set up: create a container to write into.
    tracing::info!(container = CONTAINER, "creating container");
    if let Err(err) = service.blob_container_client(CONTAINER).create(None).await {
        tracing::warn!("failed to create container: {err:?}");
    }

    // Obtain a user delegation key. In production this is fetched from the Azure
    // storage service using the caller's Entra ID identity.
    tracing::info!("fetching user delegation key");
    let key = UserDelegationKeyFetcher::new(ACCOUNT, Arc::new(DummyCredential))
        .endpoint(Url::parse(BLOB_ENDPOINT)?)
        .http_client(
            reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()?,
        )
        .fetch()
        .await?;
    tracing::info!(oid = %key.signed_oid, expiry = %key.signed_expiry, "delegation key obtained");

    let expiry = OffsetDateTime::now_utc() + Duration::hours(1);

    // Build a write SAS URL (create + write permissions) and upload through it.
    let write_url = UserDelegationSasBuilder::new(
        ACCOUNT,
        BlobResource {
            container: CONTAINER.into(),
            blob: BLOB.into(),
            options: None,
        },
        BlobSasPermissions {
            create: true,
            write: true,
            ..Default::default()
        },
        expiry,
    )
    .endpoint(Url::parse(BLOB_ENDPOINT)?)
    .with_key(key.clone())
    .build()?;
    tracing::info!(url = %write_url, "write SAS URL built");

    BlobClient::new(
        write_url,
        None,
        Some(BlobClientOptions {
            client_options: ClientOptions {
                transport: Some(Transport::new(Arc::new(
                    reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .build()?,
                ))),
                ..Default::default()
            },
            ..Default::default()
        }),
    )?
    .upload(Bytes::from_static(CONTENT.as_bytes()).into(), None)
    .await?;
    tracing::info!(blob = BLOB, "blob uploaded via SAS");

    // Build a read SAS URL and verify the content that was just written.
    let read_url = UserDelegationSasBuilder::new(
        ACCOUNT,
        BlobResource {
            container: CONTAINER.into(),
            blob: BLOB.into(),
            options: None,
        },
        BlobSasPermissions {
            read: true,
            ..Default::default()
        },
        expiry,
    )
    .endpoint(Url::parse(BLOB_ENDPOINT)?)
    .with_key(key)
    .build()?;
    tracing::info!(url = %read_url, "read SAS URL built");

    let result = BlobClient::new(
        read_url,
        None,
        Some(BlobClientOptions {
            client_options: ClientOptions {
                transport: Some(Transport::new(Arc::new(
                    reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .build()?,
                ))),
                ..Default::default()
            },
            ..Default::default()
        }),
    )?
    .download(None)
    .await?;
    let body = result.body.collect_string().await?;
    tracing::info!(content = %body, "blob downloaded via SAS");

    assert_eq!(body, CONTENT);
    Ok(())
}
