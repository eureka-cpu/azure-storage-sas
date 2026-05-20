//! Demonstrates a SAS token that restricts usage to requests containing a specific header.
//!
//! The `srh` (signedRequestHeaders) field lists header names that *must* be present on
//! every request made with the SAS. Azure Storage validates that each listed header is
//! included and that its value is signed into the SAS token.
//!
//! This example signs `x-ms-blob-type` into the SAS. The Azure Blob Storage SDK
//! automatically sends `x-ms-blob-type: BlockBlob` on every upload, satisfying the
//! requirement. A raw HTTP request omitting the header would be rejected with 403.
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
//! cargo run --example blob_sas_required_headers
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
    blob::{BlobResource, BlobResourceOptions, BlobSasPermissions},
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

    const CONTAINER: &str = "sas-required-headers-example";
    const BLOB: &str = "restricted-upload.txt";
    const CONTENT: &str = "Uploaded with a SAS that requires x-ms-blob-type";

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

    // Set up: create a container to write into.
    tracing::info!(container = CONTAINER, "creating container");
    if let Err(err) = service.blob_container_client(CONTAINER).create(None).await {
        tracing::warn!("failed to create container: {err:?}");
    }

    // Obtain a user delegation key.
    tracing::info!("fetching user delegation key");
    let key = UserDelegationKeyFetcher::new(common::ACCOUNT, Arc::new(common::DummyCredential))
        .endpoint(Url::parse(common::BLOB_ENDPOINT)?)
        .http_client(client)
        .fetch()
        .await?;
    tracing::info!(oid = %key.signed_oid, expiry = %key.signed_expiry, "delegation key obtained");

    let expiry = OffsetDateTime::now_utc() + Duration::hours(1);

    // Build a write SAS that requires the `x-ms-blob-type` header on every request.
    // The header name is signed into the string-to-sign and appears as `srh` in the URL.
    // Azure Storage will reject any request that omits a listed required header.
    let write_url = UserDelegationSasBuilder::new(
        common::ACCOUNT,
        BlobResource {
            container: CONTAINER.into(),
            blob: BLOB.into(),
            options: Some(BlobResourceOptions {
                signed_request_headers: Some("x-ms-blob-type".into()),
                ..Default::default()
            }),
        },
        BlobSasPermissions {
            create: true,
            write: true,
            ..Default::default()
        },
        expiry,
    )
    .endpoint(Url::parse(common::BLOB_ENDPOINT)?)
    .signed_version("2025-07-05")
    .with_key(key.clone())
    .build()?;

    tracing::info!(url = %write_url, "write SAS URL built");
    assert!(
        write_url
            .query_pairs()
            .any(|(k, v)| k == "srh" && v == "x-ms-blob-type"),
        "srh must be present in the SAS URL"
    );

    // The Azure Blob SDK automatically sends `x-ms-blob-type: BlockBlob` on every
    // upload, satisfying the SAS requirement.
    BlobClient::new(
        write_url,
        None,
        Some(BlobClientOptions {
            client_options: ClientOptions {
                transport: Some(transport.clone()),
                ..Default::default()
            },
            ..Default::default()
        }),
    )?
    .upload(Bytes::from_static(CONTENT.as_bytes()).into(), None)
    .await?;
    tracing::info!(blob = BLOB, "blob uploaded via header-restricted SAS");

    // Read back to verify.
    let read_url = UserDelegationSasBuilder::new(
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

    let result = BlobClient::new(
        read_url,
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
    tracing::info!(content = %body, "blob downloaded and verified");

    assert_eq!(body, CONTENT);
    Ok(())
}
