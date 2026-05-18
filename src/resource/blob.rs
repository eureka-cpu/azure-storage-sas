//! Azure Blob Storage SAS resources.
//!
//! Provides resource types for the five addressable Blob Storage scopes:
//!
//! | Type | `sr` | Scope |
//! |------|------|-------|
//! | [`BlobResource`] | `b` | A single blob |
//! | [`ContainerResource`] | `c` | All blobs in a container |
//! | [`DirectoryResource`] | `d` | A virtual directory (requires hierarchical namespace) |
//! | [`BlobSnapshotResource`] | `bs` | A specific blob snapshot |
//! | [`BlobVersionResource`] | `bv` | A specific blob version |
//!
//! Permissions are expressed with [`Resource::Permissions`](crate::resource::Resource::Permissions) and encoded in spec order (`racwdxyltmeopi`).
//!
//! <https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas#specify-the-signed-resource-field-blob-storage-only>

use std::fmt;

use time::OffsetDateTime;
use time::macros::format_description;
use uuid::Uuid;

use url::Url;

use crate::{
    error::SasError,
    resource::{Resource, sealed},
    sas::{SasSigningContext, SasUrlParams, append_common_sas_params, append_path},
};

pub mod container;
pub mod directory;
pub mod snapshot;
pub mod version;
pub use container::ContainerResource;
pub use directory::DirectoryResource;
pub use snapshot::BlobSnapshotResource;
pub use version::BlobVersionResource;

/// Default API version for Blob Storage user delegation SAS tokens.
pub const BLOB_DEFAULT_VERSION: &str = "2022-11-02";

pub(crate) fn format_blob_time(dt: OffsetDateTime) -> String {
    dt.format(format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:7]Z"
    ))
    .expect("snapshot time formatting failed")
}

/// Permissions for a Blob Storage SAS token.
///
/// Permissions are emitted in spec order: `racwdxyltmeopi`
///
/// <https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas#specify-permissions>
/// <https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas#permissions-for-a-directory-container-or-blob>
#[derive(Default)]
pub struct BlobSasPermissions {
    /// Read content, blocklist, properties, and metadata.
    pub read: bool,
    /// Add a block to an append blob.
    pub add: bool,
    /// Write a new blob, snapshot, or copy to a new blob.
    pub create: bool,
    /// Create or write content, properties, metadata, or blocklist.
    pub write: bool,
    /// Delete a blob.
    pub delete: bool,
    /// Delete a blob version.
    pub delete_version: bool,
    /// Permanently delete a blob snapshot or version.
    pub permanent_delete: bool,
    /// Read or write blob tags.
    pub tags: bool,
    /// Move a blob or directory.
    pub move_blob: bool,
    /// Get system properties; set POSIX ACL if hierarchical namespace is enabled.
    pub execute: bool,
    /// Set owner or owning group when hierarchical namespace is enabled.
    pub ownership: bool,
    /// Set permissions and POSIX ACLs when hierarchical namespace is enabled.
    pub permissions: bool,
    /// Set or delete immutability policy or legal hold on a blob.
    pub set_immutability_policy: bool,
}

impl fmt::Display for BlobSasPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Order per spec table: racwdxyltmeopi
        if self.read {
            write!(f, "r")?;
        }
        if self.add {
            write!(f, "a")?;
        }
        if self.create {
            write!(f, "c")?;
        }
        if self.write {
            write!(f, "w")?;
        }
        if self.delete {
            write!(f, "d")?;
        }
        if self.delete_version {
            write!(f, "x")?;
        }
        if self.permanent_delete {
            write!(f, "y")?;
        }
        if self.tags {
            write!(f, "t")?;
        }
        if self.move_blob {
            write!(f, "m")?;
        }
        if self.execute {
            write!(f, "e")?;
        }
        if self.ownership {
            write!(f, "o")?;
        }
        if self.permissions {
            write!(f, "p")?;
        }
        if self.set_immutability_policy {
            write!(f, "i")?;
        }
        Ok(())
    }
}

/// Optional fields for blob SAS resources.
///
/// All five blob resource types accept `options: Option<BlobResourceOptions>`.
///
/// ```rust,ignore
/// BlobResource {
///     container: "mycontainer".into(),
///     blob: "myblob.txt".into(),
///     options: Some(BlobResourceOptions {
///         cache_control: Some("no-cache".into()),
///         ..Default::default()
///     }),
/// }
/// ```
///
/// <https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas#specify-query-parameters-to-override-response-headers-blob-storage-and-azure-files-only>
#[derive(Default)]
pub struct BlobResourceOptions {
    /// Signed correlation ID (`scid`) — ties the SAS to a specific request for auditing.
    pub correlation_id: Option<Uuid>,
    /// Encryption scope (`ses`) — restricts the SAS to a named encryption scope.
    pub encryption_scope: Option<String>,
    /// Override `Cache-Control` response header (`rscc`).
    pub cache_control: Option<String>,
    /// Override `Content-Disposition` response header (`rscd`).
    pub content_disposition: Option<String>,
    /// Override `Content-Encoding` response header (`rsce`).
    pub content_encoding: Option<String>,
    /// Override `Content-Language` response header (`rscl`).
    pub content_language: Option<String>,
    /// Override `Content-Type` response header (`rsct`).
    pub content_type: Option<String>,
}

/// https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas#specify-query-parameters-to-override-response-headers-blob-storage-and-azure-files-only
pub(crate) struct BlobStringToSign<'a> {
    pub ctx: &'a SasSigningContext<'a>,
    pub sr: &'a str,
    pub snapshot_time: &'a str,
    pub correlation_id: Option<&'a str>,
    pub encryption_scope: Option<&'a str>,
    pub cache_control: Option<&'a str>,
    pub content_disposition: Option<&'a str>,
    pub content_encoding: Option<&'a str>,
    pub content_language: Option<&'a str>,
    pub content_type: Option<&'a str>,
}

impl std::fmt::Display for BlobStringToSign<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ctx = self.ctx;
        write!(
            f,
            "{}",
            [
                ctx.permissions,                               // [0]  signedPermissions
                ctx.start,                                     // [1]  signedStart
                ctx.expiry,                                    // [2]  signedExpiry
                ctx.canon,                                     // [3]  canonicalizedResource
                &ctx.key.signed_oid,                           // [4]  signedKeyObjectId
                &ctx.key.signed_tid,                           // [5]  signedKeyTenantId
                &ctx.key.signed_start,                         // [6]  signedKeyStart
                &ctx.key.signed_expiry,                        // [7]  signedKeyExpiry
                &ctx.key.signed_service,                       // [8]  signedKeyService
                &ctx.key.signed_version,                       // [9]  signedKeyVersion
                ctx.authorized_user_object_id.unwrap_or(""),   // [10] signedAuthorizedUserObjectId
                ctx.unauthorized_user_object_id.unwrap_or(""), // [11] signedUnauthorizedUserObjectId
                self.correlation_id.unwrap_or(""),             // [12] signedCorrelationId
                ctx.ip.unwrap_or(""),                          // [13] signedIP
                ctx.protocol.as_str(),                         // [14] signedProtocol
                ctx.version,                                   // [15] signedVersion
                self.sr,                                       // [16] signedResource
                self.snapshot_time,                            // [17] signedSnapshotTime
                self.encryption_scope.unwrap_or(""),           // [18] signedEncryptionScope
                self.cache_control.unwrap_or(""),              // [19] rscc
                self.content_disposition.unwrap_or(""),        // [20] rscd
                self.content_encoding.unwrap_or(""),           // [21] rsce
                self.content_language.unwrap_or(""),           // [22] rscl
                self.content_type.unwrap_or(""),               // [23] rsct
            ]
            .join("\n")
        )
    }
}

/// A single blob (`sr=b`).
pub struct BlobResource {
    pub container: String,
    pub blob: String,
    pub options: Option<BlobResourceOptions>,
}

impl Resource for BlobResource {
    type Permissions = BlobSasPermissions;
}

impl sealed::BlobService for BlobResource {}

impl sealed::Resource for BlobResource {
    fn default_endpoint(&self, account: &str) -> Url {
        Url::parse(&format!("https://{}.blob.core.windows.net", account)).unwrap()
    }
    fn default_api_version(&self) -> &'static str {
        BLOB_DEFAULT_VERSION
    }
    fn canonicalized_resource(&self, account: &str) -> String {
        format!("/blob/{}/{}/{}", account, self.container, self.blob)
    }
    fn string_to_sign(&self, ctx: &SasSigningContext<'_>) -> String {
        let opts = self.options.as_ref();
        let correlation_id = opts.and_then(|o| o.correlation_id).map(|id| id.to_string());
        BlobStringToSign {
            ctx,
            sr: "b",
            snapshot_time: "",
            correlation_id: correlation_id.as_deref(),
            encryption_scope: opts.and_then(|o| o.encryption_scope.as_deref()),
            cache_control: opts.and_then(|o| o.cache_control.as_deref()),
            content_disposition: opts.and_then(|o| o.content_disposition.as_deref()),
            content_encoding: opts.and_then(|o| o.content_encoding.as_deref()),
            content_language: opts.and_then(|o| o.content_language.as_deref()),
            content_type: opts.and_then(|o| o.content_type.as_deref()),
        }
        .to_string()
    }
    fn sas_url(&self, account_endpoint: &Url, params: &SasUrlParams<'_>) -> Result<Url, SasError> {
        let mut url = append_path(
            account_endpoint,
            &format!("{}/{}", self.container, self.blob),
        );
        let opts = self.options.as_ref();
        let mut q = url.query_pairs_mut();
        q.append_pair("sv", params.version).append_pair("sr", "b");
        append_common_sas_params(&mut q, params);
        if let Some(v) = opts.and_then(|o| o.encryption_scope.as_deref()) {
            q.append_pair("ses", v);
        }
        if let Some(v) = opts.and_then(|o| o.cache_control.as_deref()) {
            q.append_pair("rscc", v);
        }
        if let Some(v) = opts.and_then(|o| o.content_disposition.as_deref()) {
            q.append_pair("rscd", v);
        }
        if let Some(v) = opts.and_then(|o| o.content_encoding.as_deref()) {
            q.append_pair("rsce", v);
        }
        if let Some(v) = opts.and_then(|o| o.content_language.as_deref()) {
            q.append_pair("rscl", v);
        }
        if let Some(v) = opts.and_then(|o| o.content_type.as_deref()) {
            q.append_pair("rsct", v);
        }
        if let Some(id) = opts.and_then(|o| o.correlation_id) {
            q.append_pair("scid", &id.to_string());
        }
        q.append_pair("sig", params.signature);
        drop(q);
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        resource::sealed::Resource as _,
        sas::{SasSigningContext, SasUrlParams},
        test_utils::{ACCOUNT, make_key, url_params},
    };

    const CONTAINER: &str = "testcontainer";
    const BLOB: &str = "testblob.txt";

    fn make_resource() -> BlobResource {
        BlobResource {
            container: CONTAINER.to_string(),
            blob: BLOB.to_string(),
            options: None,
        }
    }

    #[test]
    fn test_blob_string_to_sign_has_24_fields() {
        let key = make_key();
        let resource = make_resource();
        let canon = resource.canonicalized_resource(ACCOUNT);
        let ctx = SasSigningContext {
            permissions: "rw",
            start: "2024-01-01T00:00:00Z",
            expiry: "2024-01-08T00:00:00Z",
            canon: &canon,
            key: &key,
            version: resource.default_api_version(),
            ip: None,
            protocol: Default::default(),
            authorized_user_object_id: None,
            unauthorized_user_object_id: None,
            delegated_user_object_id: None,
        };
        let s2s = resource.string_to_sign(&ctx);
        let parts: Vec<&str> = s2s.split('\n').collect();
        assert_eq!(parts.len(), 24, "blob string-to-sign must have 24 fields");
        assert_eq!(parts[14], "https,http", "[14] signedProtocol");
        assert_eq!(
            parts[15],
            resource.default_api_version(),
            "[15] signedVersion"
        );
        assert_eq!(parts[16], "b", "[16] signedResource");
        assert_eq!(parts[19], "", "[19] rscc — empty");
        assert_eq!(parts[23], "", "[23] rsct — empty");
    }

    #[test]
    fn test_blob_sas_url_has_13_params() {
        let key = make_key();
        let resource = make_resource();
        let canon = resource.canonicalized_resource(ACCOUNT);
        let ctx = SasSigningContext {
            permissions: "cw",
            start: "2024-01-01T00:00:00Z",
            expiry: "2024-01-08T00:00:00Z",
            canon: &canon,
            key: &key,
            version: resource.default_api_version(),
            ip: None,
            protocol: Default::default(),
            authorized_user_object_id: None,
            unauthorized_user_object_id: None,
            delegated_user_object_id: None,
        };
        let s2s = resource.string_to_sign(&ctx);
        let sig = key.compute_signature(&s2s).unwrap();
        let endpoint = Url::parse(&format!("https://{}.blob.core.windows.net", ACCOUNT)).unwrap();
        let url = resource
            .sas_url(
                &endpoint,
                &SasUrlParams {
                    permissions: "cw",
                    start: Some("2024-01-01T00:00:00Z"),
                    expiry: "2024-01-08T00:00:00Z",
                    key: &key,
                    signature: &sig,
                    version: resource.default_api_version(),
                    ip: None,
                    protocol: Default::default(),
                    authorized_user_object_id: None,
                    unauthorized_user_object_id: None,
                    delegated_user_object_id: None,
                    delegated_user_tenant_id: None,
                },
            )
            .unwrap();
        let params = url_params(&url);
        assert_eq!(params.len(), 13, "blob SAS must have 13 parameters");
        assert_eq!(params["sr"], "b");
        assert_eq!(params["sv"], resource.default_api_version());
        assert_eq!(params["spr"], "https,http");
        assert!(url.path().ends_with(BLOB));
    }

    #[test]
    fn test_blob_string_to_sign_with_ip() {
        let key = make_key();
        let resource = make_resource();
        let canon = resource.canonicalized_resource(ACCOUNT);
        let ctx = SasSigningContext {
            permissions: "r",
            start: "2024-01-01T00:00:00Z",
            expiry: "2024-01-08T00:00:00Z",
            canon: &canon,
            key: &key,
            version: resource.default_api_version(),
            ip: Some("192.168.1.1"),
            protocol: Default::default(),
            authorized_user_object_id: None,
            unauthorized_user_object_id: None,
            delegated_user_object_id: None,
        };
        let s2s = resource.string_to_sign(&ctx);
        let parts: Vec<&str> = s2s.split('\n').collect();
        assert_eq!(parts[13], "192.168.1.1", "[13] signedIP");
    }

    #[test]
    fn test_blob_sas_url_with_optional_fields() {
        let key = make_key();
        let resource = BlobResource {
            container: CONTAINER.to_string(),
            blob: BLOB.to_string(),
            options: Some(BlobResourceOptions {
                encryption_scope: Some("myscope".to_string()),
                cache_control: Some("no-cache".to_string()),
                content_type: Some("application/octet-stream".to_string()),
                ..Default::default()
            }),
        };
        let canon = resource.canonicalized_resource(ACCOUNT);
        let ctx = SasSigningContext {
            permissions: "r",
            start: "2024-01-01T00:00:00Z",
            expiry: "2024-01-08T00:00:00Z",
            canon: &canon,
            key: &key,
            version: resource.default_api_version(),
            ip: Some("10.0.0.1"),
            protocol: Default::default(),
            authorized_user_object_id: None,
            unauthorized_user_object_id: None,
            delegated_user_object_id: None,
        };
        let s2s = resource.string_to_sign(&ctx);
        let parts: Vec<&str> = s2s.split('\n').collect();
        assert_eq!(parts[13], "10.0.0.1", "[13] signedIP");
        assert_eq!(parts[18], "myscope", "[18] signedEncryptionScope");
        assert_eq!(parts[19], "no-cache", "[19] rscc");
        assert_eq!(parts[20], "", "[20] rscd — empty");
        assert_eq!(parts[23], "application/octet-stream", "[23] rsct");

        let sig = key.compute_signature(&s2s).unwrap();
        let endpoint = Url::parse(&format!("https://{}.blob.core.windows.net", ACCOUNT)).unwrap();
        let url = resource
            .sas_url(
                &endpoint,
                &SasUrlParams {
                    permissions: "r",
                    start: Some("2024-01-01T00:00:00Z"),
                    expiry: "2024-01-08T00:00:00Z",
                    key: &key,
                    signature: &sig,
                    version: resource.default_api_version(),
                    ip: Some("10.0.0.1"),
                    protocol: Default::default(),
                    authorized_user_object_id: None,
                    unauthorized_user_object_id: None,
                    delegated_user_object_id: None,
                    delegated_user_tenant_id: None,
                },
            )
            .unwrap();
        let params = url_params(&url);
        assert_eq!(params["ses"], "myscope");
        assert_eq!(params["rscc"], "no-cache");
        assert!(!params.contains_key("rscd"));
        assert_eq!(params["rsct"], "application/octet-stream");
        assert_eq!(params["sip"], "10.0.0.1");
    }
}
