//! Demonstrates that an expired user delegation SAS is rejected with 403.
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
//! cargo run --example blob_sas_expiry
//! ```

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use azure_core::{
    Bytes,
    http::{ClientOptions, StatusCode, Transport},
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

    const CONTAINER: &str = "sas-expiry-example";
    const BLOB: &str = "expiry-check.txt";
    const CONTENT: &str = "expiry check";

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

    // Set up: create a container and upload a blob to attempt reading.
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

    // Build a SAS URL with an expiry 5 minutes in the past.
    let already_expired = OffsetDateTime::now_utc() - Duration::minutes(5);
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
        already_expired,
    )
    .endpoint(Url::parse(common::BLOB_ENDPOINT)?)
    .signed_version("2025-07-05")
    .with_key(key)
    .build()?;
    tracing::info!(url = %sas_url, "expired SAS URL built");

    // The request should be rejected with 403 Forbidden.
    match BlobClient::new(
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
    .await
    {
        Err(e) if e.http_status() == Some(StatusCode::Forbidden) => {
            tracing::info!(status = 403, "expired SAS correctly rejected");
        }
        Ok(_) => panic!("expected 403 Forbidden for expired SAS but request succeeded"),
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
