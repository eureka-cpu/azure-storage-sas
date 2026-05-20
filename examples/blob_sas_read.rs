//! Demonstrates reading a blob using a user delegation SAS.
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
//! cargo run --example blob_sas_read
//! ```

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use azure_core::{
    Bytes,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .pretty()
        .init();

    const CONTAINER: &str = "sas-read-example";
    const BLOB: &str = "hello.txt";
    const CONTENT: &str = "Hello from user delegation SAS!";

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let transport = Transport::new(Arc::new(client.clone()));

    // Create a service client authenticated with a Bearer token credential.
    // `danger_accept_invalid_certs` is needed for Azurite's self-signed TLS cert.
    let service = BlobServiceClient::new(
        Url::parse(common::BLOB_ENDPOINT)?,
        Some(Arc::new(common::DummyCredential)),
        Some(BlobServiceClientOptions {
            client_options: ClientOptions {
                transport: Some(transport.clone()),
                ..Default::default()
            },
            ..Default::default()
        }),
    )?;

    // Set up: create a container and upload a blob to read.
    tracing::info!(container = CONTAINER, "creating container");
    if let Err(err) = service.blob_container_client(CONTAINER).create(None).await {
        tracing::warn!("failed to create container: {err:?}");
    }

    tracing::info!(container = CONTAINER, blob = BLOB, "uploading blob");
    service
        .blob_client(CONTAINER, BLOB)
        .upload(Bytes::from_static(CONTENT.as_bytes()).into(), None)
        .await?;

    // Obtain a user delegation key. In production this is fetched from the Azure
    // storage service using the caller's Entra ID identity.
    tracing::info!("fetching user delegation key");
    let key = UserDelegationKeyFetcher::new(common::ACCOUNT, Arc::new(common::DummyCredential))
        .endpoint(Url::parse(common::BLOB_ENDPOINT)?)
        .http_client(client)
        .fetch()
        .await?;
    tracing::info!(oid = %key.signed_oid, expiry = %key.signed_expiry, "delegation key obtained");

    // Build a read SAS URL valid for one hour, signed with the delegation key.
    let expiry = OffsetDateTime::now_utc() + Duration::hours(1);
    let sas_url = UserDelegationSasBuilder::new(
        common::ACCOUNT,
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
    .endpoint(Url::parse(common::BLOB_ENDPOINT)?)
    .signed_version("2025-07-05")
    .with_key(key)
    .build()?;
    tracing::info!(url = %sas_url, "SAS URL built");

    // Download the blob anonymously — no credential, the SAS in the URL authenticates.
    let result = BlobClient::new(
        sas_url,
        None,
        Some(BlobClientOptions {
            client_options: ClientOptions {
                transport: Some(transport),
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
