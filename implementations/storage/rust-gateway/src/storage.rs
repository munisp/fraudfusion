//! RustFS (S3-compatible) storage client with AWS Signature V4 signing,
//! bucket versioning support, tombstone soft-delete and an audit ring.
//!
//! Implemented directly on reqwest (no AWS SDK) to keep the dependency
//! surface small and auditable.

use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use moka::future::Cache;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::AppConfig;
use crate::error::StorageError;
use crate::models::{
    AuditEntry, BucketInfo, ListObjectsResponse, ObjectMetadata, PresignedUrlResponse,
    UploadResult, TombstoneMetadata, TOMBSTONE_CONTENT_TYPE, TOMBSTONE_SUFFIX,
};

type HmacSha256 = Hmac<Sha256>;

const AUDIT_RING_CAPACITY: usize = 10_000;

pub struct StorageClient {
    http: reqwest::Client,
    endpoint: String,
    region: String,
    access_key: String,
    secret_key: String,
    cache: Cache<String, Vec<u8>>,
    audit_ring: Mutex<std::collections::VecDeque<AuditEntry>>,
    audit_enabled: bool,
}

// ---------------------------------------------------------------------------
// SigV4 helpers
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

impl StorageClient {
    pub async fn new(config: &AppConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;
        let cache = Cache::builder()
            .max_capacity(config.cache_max_size_mb * 1024 * 1024)
            .time_to_live(Duration::from_secs(config.cache_ttl_seconds))
            .weigher(|_k: &String, v: &Vec<u8>| v.len() as u32)
            .build();
        Ok(Self {
            http,
            endpoint: config.rustfs_endpoint.trim_end_matches('/').to_string(),
            region: config.rustfs_region.clone(),
            access_key: config.rustfs_access_key.clone(),
            secret_key: config.rustfs_secret_key.clone(),
            cache,
            audit_ring: Mutex::new(std::collections::VecDeque::with_capacity(AUDIT_RING_CAPACITY)),
            audit_enabled: config.enable_audit_log,
        })
    }

    // ------------------------------------------------------------------
    // Audit ring (backs /metrics; authoritative sink is the external ledger)
    // ------------------------------------------------------------------

    pub fn record_audit(&self, entry: AuditEntry) {
        if !self.audit_enabled {
            return;
        }
        let mut ring = self.audit_ring.lock().expect("audit ring poisoned");
        if ring.len() >= AUDIT_RING_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(entry);
    }

    pub async fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_ring.lock().expect("audit ring poisoned").iter().cloned().collect()
    }

    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache.entry_count(), self.cache.weighted_size())
    }

    // ------------------------------------------------------------------
    // Signed request machinery
    // ------------------------------------------------------------------

    fn signed_headers(
        &self,
        method: &str,
        canonical_uri: &str,
        canonical_query: &str,
        payload_hash: &str,
        extra_headers: &[(String, String)],
        now: DateTime<Utc>,
    ) -> Vec<(String, String)> {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string();

        let mut headers: Vec<(String, String)> = vec![
            ("host".to_string(), host),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        headers.extend(extra_headers.iter().cloned());
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        headers.dedup_by(|a, b| a.0 == b.0);

        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
            .collect();
        let signed_headers: String = headers.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>().join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash
        );

        let scope = format!("{}/{}/s3/aws4_request", date_stamp, self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            scope,
            sha256_hex(canonical_request.as_bytes())
        );

        let k_date = hmac_sha256(format!("AWS4{}", self.secret_key).as_bytes(), &date_stamp);
        let k_region = hmac_sha256(&k_date, &self.region);
        let k_service = hmac_sha256(&k_region, "s3");
        let k_signing = hmac_sha256(&k_service, "aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, &string_to_sign));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, scope, signed_headers, signature
        );

        let mut out: Vec<(String, String)> = headers
            .into_iter()
            .filter(|(k, _)| k != "host")
            .collect();
        out.push(("authorization".to_string(), authorization));
        out
    }

    async fn signed_request(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &str,
        body: Vec<u8>,
        extra_headers: &[(String, String)],
    ) -> Result<reqwest::Response, StorageError> {
        let payload_hash = sha256_hex(&body);
        let canonical_uri = format!("/{}", uri_encode(path.trim_start_matches('/'), false));
        let headers = self.signed_headers(method.as_str(), &canonical_uri, query, &payload_hash, extra_headers, Utc::now());

        let url = if query.is_empty() {
            format!("{}{}", self.endpoint, canonical_uri)
        } else {
            format!("{}{}?{}", self.endpoint, canonical_uri, query)
        };

        let mut req = self.http.request(method, &url).body(body);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| StorageError::StorageBackend(format!("request failed: {e}")))?;
        Ok(resp)
    }

    async fn expect_success(
        &self,
        resp: reqwest::Response,
        context: &str,
    ) -> Result<reqwest::Response, StorageError> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(StorageError::NotFound(format!("{context}: {body}")));
        }
        Err(StorageError::StorageBackend(format!("{context}: HTTP {status}: {body}")))
    }

    // ------------------------------------------------------------------
    // Health / buckets
    // ------------------------------------------------------------------

    pub async fn health_check(&self) -> Result<(bool, Option<u64>), StorageError> {
        let start = Instant::now();
        let resp = self
            .signed_request(reqwest::Method::GET, "", "", Vec::new(), &[])
            .await?;
        let latency = Some(start.elapsed().as_millis() as u64);
        Ok((resp.status().is_success(), latency))
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>, StorageError> {
        let resp = self
            .signed_request(reqwest::Method::GET, "", "", Vec::new(), &[])
            .await?;
        let resp = self.expect_success(resp, "list_buckets").await?;
        let body = resp.text().await.map_err(|e| StorageError::StorageBackend(e.to_string()))?;
        parse_list_buckets(&body)
    }

    pub async fn bucket_exists(&self, bucket: &str) -> bool {
        matches!(
            self.signed_request(reqwest::Method::HEAD, bucket, "", Vec::new(), &[]).await,
            Ok(resp) if resp.status().is_success()
        )
    }

    pub async fn create_bucket(&self, bucket: &str) -> Result<(), StorageError> {
        let resp = self
            .signed_request(reqwest::Method::PUT, bucket, "", Vec::new(), &[])
            .await?;
        self.expect_success(resp, "create_bucket").await?;
        Ok(())
    }

    pub async fn get_bucket_versioning(&self, bucket: &str) -> Result<String, StorageError> {
        let resp = self
            .signed_request(reqwest::Method::GET, bucket, "versioning=", Vec::new(), &[])
            .await?;
        let resp = self.expect_success(resp, "get_bucket_versioning").await?;
        let body = resp.text().await.map_err(|e| StorageError::StorageBackend(e.to_string()))?;
        Ok(parse_versioning_status(&body))
    }

    pub async fn enable_bucket_versioning(&self, bucket: &str) -> Result<(), StorageError> {
        let body = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
        let headers = vec![("content-type".to_string(), "application/xml".to_string())];
        let resp = self
            .signed_request(reqwest::Method::PUT, bucket, "versioning=", body, &headers)
            .await?;
        self.expect_success(resp, "enable_bucket_versioning").await?;
        Ok(())
    }

    pub async fn get_object_lock_configuration(&self, bucket: &str) -> Result<String, StorageError> {
        let resp = self
            .signed_request(reqwest::Method::GET, bucket, "object-lock=", Vec::new(), &[])
            .await?;
        let resp = self.expect_success(resp, "get_object_lock_configuration").await?;
        resp.text().await.map_err(|e| StorageError::StorageBackend(e.to_string()))
    }

    pub async fn put_object_lock_configuration(
        &self,
        bucket: &str,
        mode: &str,
        retention_days: u32,
    ) -> Result<(), StorageError> {
        let body = format!(
            r#"<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>{}</Mode><Days>{}</Days></DefaultRetention></Rule></ObjectLockConfiguration>"#,
            mode, retention_days
        )
        .into_bytes();
        let headers = vec![("content-type".to_string(), "application/xml".to_string())];
        let resp = self
            .signed_request(reqwest::Method::PUT, bucket, "object-lock=", body, &headers)
            .await?;
        self.expect_success(resp, "put_object_lock_configuration").await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Objects
    // ------------------------------------------------------------------

    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        max_keys: Option<i32>,
        continuation_token: Option<&str>,
    ) -> Result<ListObjectsResponse, StorageError> {
        let mut query = "list-type=2".to_string();
        if let Some(p) = prefix {
            query.push_str(&format!("&prefix={}", uri_encode(p, true)));
        }
        if let Some(m) = max_keys {
            query.push_str(&format!("&max-keys={}", m));
        }
        if let Some(t) = continuation_token {
            query.push_str(&format!("&continuation-token={}", uri_encode(t, true)));
        }
        let resp = self
            .signed_request(reqwest::Method::GET, bucket, &query, Vec::new(), &[])
            .await?;
        let resp = self.expect_success(resp, "list_objects").await?;
        let body = resp.text().await.map_err(|e| StorageError::StorageBackend(e.to_string()))?;
        let mut parsed = parse_list_objects(&body)?;
        // hide tombstones and tombstoned objects from listings
        let tombstoned: std::collections::HashSet<String> = parsed
            .objects
            .iter()
            .filter(|o| o.key.ends_with(TOMBSTONE_SUFFIX))
            .map(|o| o.key.trim_end_matches(TOMBSTONE_SUFFIX).to_string())
            .collect();
        parsed.objects.retain(|o| {
            !o.key.ends_with(TOMBSTONE_SUFFIX) && !tombstoned.contains(&o.key)
        });
        parsed.key_count = parsed.objects.len();
        Ok(parsed)
    }

    pub async fn object_exists(&self, bucket: &str, key: &str) -> bool {
        let path = format!("{}/{}", bucket, key);
        matches!(
            self.signed_request(reqwest::Method::HEAD, &path, "", Vec::new(), &[]).await,
            Ok(resp) if resp.status().is_success()
        )
    }

    /// HEAD object; returns (content_length, last_modified, version_id, metadata)
    pub async fn head_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(u64, Option<String>, Option<String>), StorageError> {
        let path = format!("{}/{}", bucket, key);
        let resp = self
            .signed_request(reqwest::Method::HEAD, &path, "", Vec::new(), &[])
            .await?;
        let resp = self.expect_success(resp, "head_object").await?;
        let size = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let last_modified = resp
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let version_id = resp
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        Ok((size, last_modified, version_id))
    }

    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, StorageError> {
        let cache_key = format!("{}/{}", bucket, key);
        if let Some(data) = self.cache.get(&cache_key).await {
            return Ok(data);
        }
        let path = format!("{}/{}", bucket, key);
        let resp = self
            .signed_request(reqwest::Method::GET, &path, "", Vec::new(), &[])
            .await?;
        let resp = self.expect_success(resp, "get_object").await?;
        let data = resp
            .bytes()
            .await
            .map_err(|e| StorageError::StorageBackend(e.to_string()))?
            .to_vec();
        self.cache.insert(cache_key, data.clone()).await;
        Ok(data)
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
        metadata: Option<Vec<(String, String)>>,
    ) -> Result<UploadResult, StorageError> {
        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(ct) = content_type {
            headers.push(("content-type".to_string(), ct.to_string()));
        }
        for (k, v) in metadata.unwrap_or_default() {
            headers.push((format!("x-amz-meta-{k}"), v));
        }
        let path = format!("{}/{}", bucket, key);
        let size = data.len() as u64;
        let resp = self
            .signed_request(reqwest::Method::PUT, &path, "", data, &headers)
            .await?;
        let resp = self.expect_success(resp, "put_object").await?;
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        let version_id = resp
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        self.cache.invalidate(&format!("{}/{}", bucket, key)).await;
        Ok(UploadResult {
            bucket: bucket.to_string(),
            key: key.to_string(),
            etag,
            size,
            version_id,
            content_type: content_type.map(|s| s.to_string()),
        })
    }

    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        let path = format!("{}/{}", bucket, key);
        let resp = self
            .signed_request(reqwest::Method::DELETE, &path, "", Vec::new(), &[])
            .await?;
        self.expect_success(resp, "delete_object").await?;
        self.cache.invalidate(&format!("{}/{}", bucket, key)).await;
        Ok(())
    }

    /// Soft-delete: write a zero-byte tombstone marker object; the original
    /// object (and its versions) is retained.
    pub async fn soft_delete_object(
        &self,
        bucket: &str,
        key: &str,
        deleted_by: &str,
        reason: &str,
        approval_id: Option<&str>,
    ) -> Result<(), StorageError> {
        let tombstone = TombstoneMetadata {
            deleted_by: deleted_by.to_string(),
            deleted_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            reason: reason.to_string(),
            approval_id: approval_id.map(|s| s.to_string()),
        };
        let metadata = vec![
            ("deleted-by".to_string(), tombstone.deleted_by.clone()),
            ("deleted-at".to_string(), tombstone.deleted_at.clone()),
            ("reason".to_string(), tombstone.reason.clone()),
            ("approval-id".to_string(), tombstone.approval_id.clone().unwrap_or_default()),
        ];
        self.put_object(
            bucket,
            &format!("{key}{TOMBSTONE_SUFFIX}"),
            Vec::new(),
            Some(TOMBSTONE_CONTENT_TYPE),
            Some(metadata),
        )
        .await?;
        self.cache.invalidate(&format!("{}/{}", bucket, key)).await;
        Ok(())
    }

    pub async fn is_tombstoned(&self, bucket: &str, key: &str) -> bool {
        self.object_exists(bucket, &format!("{key}{TOMBSTONE_SUFFIX}")).await
    }

    pub async fn presign_url(
        &self,
        bucket: &str,
        key: &str,
        expires_in: u64,
    ) -> Result<PresignedUrlResponse, StorageError> {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let scope = format!("{}/{}/s3/aws4_request", date_stamp, self.region);
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string();
        let canonical_uri = format!("/{}", uri_encode(&format!("{bucket}/{key}"), false));

        let mut query_params: Vec<(String, String)> = vec![
            ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
            ("X-Amz-Credential".into(), format!("{}/{}", self.access_key, scope)),
            ("X-Amz-Date".into(), amz_date.clone()),
            ("X-Amz-Expires".into(), expires_in.to_string()),
            ("X-Amz-SignedHeaders".into(), "host".into()),
        ];
        query_params.sort();
        let canonical_query: String = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_request = format!(
            "GET\n{}\n{}\nhost:{}\n\nhost\nUNSIGNED-PAYLOAD",
            canonical_uri, canonical_query, host
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            scope,
            sha256_hex(canonical_request.as_bytes())
        );
        let k_date = hmac_sha256(format!("AWS4{}", self.secret_key).as_bytes(), &date_stamp);
        let k_region = hmac_sha256(&k_date, &self.region);
        let k_service = hmac_sha256(&k_region, "s3");
        let k_signing = hmac_sha256(&k_service, "aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, &string_to_sign));

        Ok(PresignedUrlResponse {
            url: format!(
                "{}{}?{}&X-Amz-Signature={}",
                self.endpoint, canonical_uri, canonical_query, signature
            ),
            expires_in,
        })
    }
}

// ---------------------------------------------------------------------------
// XML parsing (S3 ListBuckets / ListObjectsV2 / Versioning responses)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(rename = "ListAllMyBucketsResult")]
struct ListBucketsXml {
    #[serde(rename = "Buckets", default)]
    buckets: BucketsXml,
}

#[derive(serde::Deserialize, Default)]
struct BucketsXml {
    #[serde(rename = "Bucket", default)]
    bucket: Vec<BucketXml>,
}

#[derive(serde::Deserialize)]
struct BucketXml {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CreationDate", default)]
    creation_date: Option<String>,
}

fn parse_list_buckets(body: &str) -> Result<Vec<BucketInfo>, StorageError> {
    let parsed: ListBucketsXml = quick_xml::de::from_str(body)
        .map_err(|e| StorageError::StorageBackend(format!("list_buckets parse: {e}")))?;
    Ok(parsed
        .buckets
        .bucket
        .into_iter()
        .map(|b| BucketInfo { name: b.name, creation_date: b.creation_date })
        .collect())
}

#[derive(serde::Deserialize)]
#[serde(rename = "ListBucketResult")]
struct ListObjectsXml {
    #[serde(rename = "Contents", default)]
    contents: Vec<ObjectXml>,
    #[serde(rename = "IsTruncated", default)]
    is_truncated: Option<bool>,
    #[serde(rename = "NextContinuationToken", default)]
    next_token: Option<String>,
}

#[derive(serde::Deserialize)]
struct ObjectXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Size", default)]
    size: u64,
    #[serde(rename = "ETag", default)]
    etag: Option<String>,
    #[serde(rename = "LastModified", default)]
    last_modified: Option<String>,
}

fn parse_list_objects(body: &str) -> Result<ListObjectsResponse, StorageError> {
    let parsed: ListObjectsXml = quick_xml::de::from_str(body)
        .map_err(|e| StorageError::StorageBackend(format!("list_objects parse: {e}")))?;
    let objects = parsed
        .contents
        .into_iter()
        .map(|o| ObjectMetadata {
            key: o.key,
            size: o.size,
            etag: o.etag.unwrap_or_default().trim_matches('"').to_string(),
            last_modified: o.last_modified,
            content_type: None,
            version_id: None,
        })
        .collect::<Vec<_>>();
    Ok(ListObjectsResponse {
        key_count: objects.len(),
        objects,
        is_truncated: parsed.is_truncated.unwrap_or(false),
        next_continuation_token: parsed.next_token,
    })
}

fn parse_versioning_status(body: &str) -> String {
    #[derive(serde::Deserialize)]
    #[serde(rename = "VersioningConfiguration")]
    struct VersioningXml {
        #[serde(rename = "Status", default)]
        status: Option<String>,
    }
    quick_xml::de::from_str::<VersioningXml>(body)
        .ok()
        .and_then(|v| v.status)
        .unwrap_or_else(|| "Disabled".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_encode_basic() {
        assert_eq!(uri_encode("a/b c.pdf", false), "a/b%20c.pdf");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("~ok-._", true), "~ok-._");
    }

    #[test]
    fn parse_list_buckets_xml() {
        let body = r#"<?xml version="1.0"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><Name>evidence</Name><CreationDate>2026-08-01T00:00:00.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>"#;
        let buckets = parse_list_buckets(body).unwrap();
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].name, "evidence");
    }

    #[test]
    fn parse_list_objects_xml() {
        let body = r#"<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Contents><Key>a.pdf</Key><Size>10</Size><ETag>&quot;abc&quot;</ETag></Contents><Contents><Key>a.pdf.tombstone</Key><Size>0</Size></Contents><IsTruncated>false</IsTruncated></ListBucketResult>"#;
        let parsed = parse_list_objects(body).unwrap();
        assert_eq!(parsed.objects.len(), 2);
        assert_eq!(parsed.objects[0].etag, "abc");
    }

    #[test]
    fn parse_versioning_xml() {
        assert_eq!(
            parse_versioning_status(r#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#),
            "Enabled"
        );
        assert_eq!(parse_versioning_status("<VersioningConfiguration/>"), "Disabled");
    }
}
