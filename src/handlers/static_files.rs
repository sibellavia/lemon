use crate::common::{BoxedBody, empty, full};
use crate::handlers::Handler;

use std::{
    io::{self, SeekFrom},
    ops::RangeInclusive,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use async_trait::async_trait;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, BufReader};

use async_compression::Level;
use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder, ZstdEncoder};

use futures::stream::{Stream, StreamExt};
use http_body_util::{BodyExt, StreamBody};
use httpdate::fmt_http_date;
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    header::{self, HeaderValue},
};

use tracing::{debug, error, warn};

// for better MIME type checking
use mime::Mime;

// Caching
use bytes::Bytes;
use moka::future::{Cache, CacheBuilder};
use std::convert::TryInto;

// Compression helpers
use async_compression::tokio::write::{
    BrotliEncoder as WriteBrotliEncoder, GzipEncoder as WriteGzipEncoder,
    ZstdEncoder as WriteZstdEncoder,
};
use tokio::io::AsyncWriteExt;

// Default Cache TTL: 1 hour
const DEFAULT_CACHE_TTL_SECS: u64 = 3600;
const MIN_COMPRESS_SIZE: u64 = 256; // Define constant for minimum compression size

// --- Range Parsing ---
#[derive(Debug)]
enum RangeParseError {
    InvalidFormat,
    Unsatisfiable(u64), // Contains total size
}

// Parses the Range header, handling single byte ranges like:
// bytes=0-499, bytes=500-, bytes=-500
// Returns Ok(Some(start, end)) for valid single range (inclusive)
// Returns Ok(None) if no Range header or not bytes= format
// Returns Err(RangeParseError::InvalidFormat) for malformed ranges/multi-range
// Returns Err(RangeParseError::Unsatisfiable) if range is invalid for the given size
fn parse_range_header(
    range_header: Option<&HeaderValue>,
    total_size: u64,
) -> Result<Option<RangeInclusive<u64>>, RangeParseError> {
    let header_str = match range_header.and_then(|h| h.to_str().ok()) {
        Some(s) => s,
        None => return Ok(None), // No header, no range requested
    };

    if !header_str.starts_with("bytes=") {
        return Ok(None); // Not a byte range request
    }

    // Simple check for multi-range (contains ',') - we don't support it
    if header_str.contains(',') {
        warn!("Multi-range request received, not supported.");
        // Technically allowed, but complex. Treat as invalid for now.
        return Err(RangeParseError::InvalidFormat);
    }

    let range_spec = header_str[6..].trim(); // Skip "bytes="

    let parts: Vec<&str> = range_spec.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(RangeParseError::InvalidFormat);
    }

    let start_str = parts[0].trim();
    let end_str = parts[1].trim();

    if total_size == 0 {
        return Err(RangeParseError::Unsatisfiable(total_size));
    }

    // Calculate start and end (inclusive)
    let (start, end) = match (start_str.is_empty(), end_str.is_empty()) {
        // bytes=-500 (last 500 bytes)
        (true, false) => {
            let suffix_len = end_str
                .parse::<u64>()
                .map_err(|_| RangeParseError::InvalidFormat)?;
            if suffix_len == 0 || suffix_len > total_size {
                return Err(RangeParseError::Unsatisfiable(total_size));
            }
            // Range is total_size - suffix_len to total_size - 1
            (total_size.saturating_sub(suffix_len), total_size - 1)
        }
        // bytes=500- (from byte 500 to end)
        (false, true) => {
            let start_pos = start_str
                .parse::<u64>()
                .map_err(|_| RangeParseError::InvalidFormat)?;
            if start_pos >= total_size {
                return Err(RangeParseError::Unsatisfiable(total_size));
            }
            (start_pos, total_size - 1)
        }
        // bytes=0-499 (specific range)
        (false, false) => {
            let start_pos = start_str
                .parse::<u64>()
                .map_err(|_| RangeParseError::InvalidFormat)?;
            let end_pos = end_str
                .parse::<u64>()
                .map_err(|_| RangeParseError::InvalidFormat)?;
            if start_pos > end_pos {
                return Err(RangeParseError::InvalidFormat);
            }
            if start_pos >= total_size {
                return Err(RangeParseError::Unsatisfiable(total_size));
            }
            // Clamp end_pos to the last valid byte index
            (start_pos, end_pos.min(total_size - 1))
        }
        // bytes=- (invalid)
        (true, true) => return Err(RangeParseError::InvalidFormat),
    };

    Ok(Some(start..=end)) // Return inclusive range
}

// --- Metadata Cache Entry ---
#[derive(Clone, Debug)]
pub struct CachedMetadata {
    // For now, let's assume we only cache validated files, not directories needing index.html resolution.
    // is_dir: bool,
    modified: Option<SystemTime>,
    content_type: Mime,   // For compression, use mime::Mime type
    file_size: u64,       // Store file size for Content-Length and cache decisions
    etag: Option<String>, // Store computed ETag
}

// --- Cache Entry Enum ---
// We store Arc<CachedMetadata> inside the enum variants
// to easily share the metadata part.
#[derive(Clone, Debug)]
pub enum CachedEntry {
    MetadataOnly(Arc<CachedMetadata>),
    FullContent(Arc<CachedMetadata>, Bytes), // Content cached in memory!
}

// Compression: Enum to represent chosen encoding
#[derive(Debug, Clone, Copy, PartialEq)]
enum ContentEncoding {
    Identity,
    Gzip,
    Brotli,
    Zstd, // Added Zstd
}

// Struct to hold the web root path and caches
#[derive(Debug, Clone)]
pub struct StaticFileHandler {
    pub www_root: Arc<PathBuf>,
    // Cache: PathBuf -> CachedEntry
    // We use PathBuf as key, assuming canonical paths resolve correctly.
    pub entry_cache: Cache<PathBuf, CachedEntry>,
    // Configuration for content caching (passed during construction)
    content_cache_max_file_bytes: u64,
    // content_cache_max_total_bytes is used to configure the CacheBuilder, not stored here directly
}

#[async_trait]
impl Handler for StaticFileHandler {
    async fn handle(&self, req: Request<hyper::body::Incoming>) -> Result<Response<BoxedBody>> {
        // Call the internal serve_file method
        match self.serve_file(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                // Centralized error handling for IO errors
                error!("IO error in serve_file: {}", e);
                let status = match e.kind() {
                    io::ErrorKind::NotFound => StatusCode::NOT_FOUND, // 404
                    io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN, // 403
                    _ => StatusCode::INTERNAL_SERVER_ERROR,           // 500 for others
                };
                let body = full(status.canonical_reason().unwrap_or("Error"));
                Ok(Response::builder().status(status).body(body).unwrap())
            }
        }
    }
}

// Implement the file serving logic as a method on the handler
impl StaticFileHandler {
    // --- Constructor ---
    // We need a constructor to initialize the cache with specific limits
    pub fn new(
        www_root: PathBuf,
        content_cache_max_file_bytes: u64,
        content_cache_max_total_bytes: u64,
        // TODO: Add other cache parameters like TTL (Using default for now)
    ) -> Self {
        let entry_cache = CacheBuilder::new(content_cache_max_total_bytes)
            // Define a weigher: weighs CachedEntry based on content size
            .weigher(|_key, value: &CachedEntry| -> u32 {
                match value {
                    CachedEntry::MetadataOnly(_) => 1, // Minimal weight for metadata
                    CachedEntry::FullContent(_, bytes) => {
                        // Calculate weight based on byte length
                        bytes.len().try_into().unwrap_or(u32::MAX)
                    }
                }
            })
            // Add Time-To-Live (TTL) for cache entries
            .time_to_live(Duration::from_secs(DEFAULT_CACHE_TTL_SECS))
            // TODO: add Time-To-Idle (TTI) if needed later?
            // .time_to_idle(Duration::from_secs(DEFAULT_CACHE_TTI_SECS))
            .build();

        StaticFileHandler {
            www_root: Arc::new(www_root),
            entry_cache,
            content_cache_max_file_bytes,
        }
    }

    async fn serve_file(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxedBody>, std::io::Error> {
        debug!(uri = %req.uri(), method = %req.method(), headers = ?req.headers(), "Entered serve_file");
        // --- 1. Method Check ---
        match *req.method() {
            Method::GET | Method::HEAD => (),
            _ => {
                return Ok(Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .header(header::ALLOW, "GET, HEAD")
                    .body(empty())
                    .unwrap());
            }
        }

        // --- 2. Resolve Path & Security Check ---
        let final_path = match self.resolve_physical_path(req.uri().path()).await {
            Ok(path) => path,
            Err(resp_result) => {
                // Error case from resolve_physical_path returns Result<Response, io::Error>
                // If it's Ok(resp), return that (e.g., 403 Forbidden).
                // If it's Err(io_err), propagate the IO error.
                match resp_result {
                    Ok(resp) => return Ok(resp), // Return the pre-built 403 response
                    Err(e) => return Err(e),     // Propagate the IO error (e.g., 404 Not Found)
                }
            }
        };

        // --- 4. Cache Lookup & Computation ---
        // Clone final_path for the function call, so serve_file retains ownership
        let entry_to_use = match self.get_or_compute_cache_entry(final_path.clone()).await {
            // Clone here
            Ok(entry) => entry,
            Err(arc_err) => {
                // Map Arc<io::Error> back to io::Error for the function signature
                // This involves cloning the inner error if it's Arc-ed, or creating a new one.
                // A simple way is to create a new error with the same kind and message.
                return Err(io::Error::new(
                    arc_err.kind(),
                    format!("Failed to get or compute cache entry: {}", arc_err),
                ));
            }
        };

        // --- Extract Metadata ---
        // Extract metadata regardless of cache type for headers/checks
        let metadata = match &entry_to_use {
            CachedEntry::MetadataOnly(meta) => Arc::clone(meta),
            CachedEntry::FullContent(meta, _) => Arc::clone(meta),
        };

        // --- 4.5 Choose Encoding & Handle Conditional Requests FIRST ---
        let chosen_encoding = Self::choose_encoding(&req, &metadata);
        let response_etag = Self::get_response_etag(metadata.etag.as_deref(), chosen_encoding);

        // Check conditional requests (e.g., If-None-Match)
        if let Some(response) = self.check_conditional_requests(&req, &metadata, &response_etag) {
            // If check_conditional_requests returned a response (e.g., 304), return it
            return Ok(response);
        }

        // --- Conditional Check: If-Modified-Since ---
        // TODO: Implement If-Modified-Since check here

        // --- 5. Handle Range Request ---
        // Try handling range request first
        if let Some(response) = self
            .handle_range_request(&req, &entry_to_use, &final_path, &metadata)
            .await?
        {
            // If handle_range_request returned a response (206 or 416), return it
            return Ok(response);
        }
        // Otherwise (Ok(None)), proceed to build full response...

        // --- Build and return the full response ---
        self.build_full_response(
            req.method(),
            &entry_to_use,
            &final_path,
            &metadata,
            chosen_encoding,
            &response_etag,
        )
        .await
    }

    /// Builds the final 200 OK response, handling HEAD requests and GET body generation.
    async fn build_full_response(
        &self,
        method: &Method,
        entry_to_use: &CachedEntry,
        final_path: &PathBuf,
        metadata: &Arc<CachedMetadata>,
        chosen_encoding: ContentEncoding,
        response_etag: &Option<String>,
    ) -> Result<Response<BoxedBody>, std::io::Error> {
        // --- Build Base Response Headers (for 200 OK) ---
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CACHE_CONTROL, "public, max-age=3600") // Example cache control
            .header(header::CONTENT_TYPE, metadata.content_type.to_string()); // Use cached content type

        if let Some(mod_time) = metadata.modified {
            builder = builder.header(header::LAST_MODIFIED, fmt_http_date(mod_time));
        }
        // Always advertise range support for successful GET/HEAD responses
        builder = builder.header(header::ACCEPT_RANGES, "bytes");

        // Vary header depends on compressibility & chosen encoding
        let is_compressible = Self::is_content_compressible(&metadata.content_type);
        if is_compressible {
            builder = builder.header(header::VARY, "Accept-Encoding");
        }

        // --- Handle HEAD request (add specific headers, empty body) ---
        if *method == Method::HEAD {
            match chosen_encoding {
                ContentEncoding::Brotli => {
                    builder = builder.header(header::CONTENT_ENCODING, "br");
                }
                ContentEncoding::Gzip => {
                    builder = builder.header(header::CONTENT_ENCODING, "gzip");
                }
                ContentEncoding::Zstd => {
                    builder = builder.header(header::CONTENT_ENCODING, "zstd");
                }
                ContentEncoding::Identity => {
                    builder = builder.header(header::CONTENT_LENGTH, metadata.file_size);
                }
            }
            if let Some(resp_etag) = response_etag {
                builder = builder.header(header::ETAG, resp_etag.clone());
            }
            return Ok(builder.body(empty()).unwrap());
        }

        // --- Handle GET request body based on Cache Entry ---
        match entry_to_use {
            CachedEntry::FullContent(_, content_bytes) => {
                // --- Serve Full from Memory Cache, compress if needed ---
                match chosen_encoding {
                    ContentEncoding::Identity => {
                        debug!("Serving uncompressed FullContent from cache (Identity requested).");
                        builder = builder.header(header::CONTENT_LENGTH, metadata.file_size);
                        if let Some(resp_etag) = response_etag {
                            builder = builder.header(header::ETAG, resp_etag.clone());
                        }
                        Ok(builder.body(full(content_bytes.clone())).unwrap())
                    }
                    _ => {
                        debug!("Compressing cached content with {:?}.", chosen_encoding);
                        match compress_bytes(content_bytes.clone(), chosen_encoding).await {
                            Ok(compressed_bytes) => {
                                let encoding_str = match chosen_encoding {
                                    ContentEncoding::Brotli => "br",
                                    ContentEncoding::Gzip => "gzip",
                                    ContentEncoding::Zstd => "zstd",
                                    ContentEncoding::Identity => unreachable!(),
                                };
                                builder = builder.header(header::CONTENT_ENCODING, encoding_str);
                                if let Some(resp_etag) = response_etag {
                                    builder = builder.header(header::ETAG, resp_etag.clone());
                                }
                                Ok(builder.body(full(compressed_bytes)).unwrap())
                            }
                            Err(e) => {
                                error!(
                                    "Failed to compress cached bytes: {}. Serving uncompressed.",
                                    e
                                );
                                // Fallback: serve uncompressed from cache
                                builder =
                                    builder.header(header::CONTENT_LENGTH, metadata.file_size);
                                if let Some(resp_etag) = Self::get_response_etag(
                                    metadata.etag.as_deref(),
                                    ContentEncoding::Identity,
                                ) {
                                    builder = builder.header(header::ETAG, resp_etag.clone());
                                }
                                Ok(builder.body(full(content_bytes.clone())).unwrap())
                            }
                        }
                    }
                }
            }
            CachedEntry::MetadataOnly(_) => {
                // --- Serve by Streaming from Disk ---
                debug!(path = ?final_path, encoding = ?chosen_encoding, "Serving MetadataOnly entry, preparing to stream.");
                match File::open(final_path).await {
                    Ok(file) => {
                        let buf_reader = BufReader::new(file);
                        match chosen_encoding {
                            ContentEncoding::Brotli => {
                                debug!("Applying Brotli encoding.");
                                builder = builder.header(header::CONTENT_ENCODING, "br");
                                if let Some(resp_etag) = response_etag {
                                    builder = builder.header(header::ETAG, resp_etag.clone());
                                }
                                let encoder =
                                    BrotliEncoder::with_quality(buf_reader, Level::Precise(4));
                                let stream_body = Self::create_stream_body(encoder);
                                Ok(builder.body(BodyExt::boxed(stream_body)).unwrap())
                            }
                            ContentEncoding::Gzip => {
                                debug!("Applying Gzip encoding.");
                                builder = builder.header(header::CONTENT_ENCODING, "gzip");
                                if let Some(resp_etag) = response_etag {
                                    builder = builder.header(header::ETAG, resp_etag.clone());
                                }
                                let encoder = GzipEncoder::new(buf_reader);
                                let stream_body = Self::create_stream_body(encoder);
                                Ok(builder.body(BodyExt::boxed(stream_body)).unwrap())
                            }
                            ContentEncoding::Zstd => {
                                debug!("Applying Zstd encoding (Level 17).");
                                builder = builder.header(header::CONTENT_ENCODING, "zstd");
                                if let Some(resp_etag) = response_etag {
                                    builder = builder.header(header::ETAG, resp_etag.clone());
                                }
                                let encoder =
                                    ZstdEncoder::with_quality(buf_reader, Level::Precise(17));
                                let stream_body = Self::create_stream_body(encoder);
                                Ok(builder.body(BodyExt::boxed(stream_body)).unwrap())
                            }
                            ContentEncoding::Identity => {
                                debug!("Applying Identity encoding (no compression).");
                                builder =
                                    builder.header(header::CONTENT_LENGTH, metadata.file_size);
                                if let Some(resp_etag) = response_etag {
                                    builder = builder.header(header::ETAG, resp_etag.clone());
                                }
                                let stream_body = Self::create_stream_body(buf_reader);
                                Ok(builder.body(BodyExt::boxed(stream_body)).unwrap())
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to open file {} for streaming: {}",
                            final_path.display(),
                            e
                        );
                        // If opening the file for streaming fails, invalidate cache
                        // Need cache_key - can reconstruct from final_path
                        let cache_key = final_path.clone();
                        self.entry_cache.invalidate(&cache_key).await;
                        Err(e) // Propagate the open error
                    }
                }
            }
        }
    }

    /// Resolves the request path to a physical file path within the www_root,
    /// handling directory checks, index.html resolution, and security checks.
    /// Returns Ok(PathBuf) on success.
    /// Returns Err(Ok(Response)) for logical errors like Forbidden.
    /// Returns Err(Err(io::Error)) for IO errors like Not Found.
    async fn resolve_physical_path(
        &self,
        request_path: &str,
    ) -> Result<PathBuf, Result<Response<BoxedBody>, io::Error>> {
        // Note the nested Result
        let requested_file = request_path.trim_start_matches('/');
        let safe_path = self.www_root.join(requested_file);

        // Security Check: Path Traversal
        if !safe_path.starts_with(self.www_root.as_ref()) {
            return Err(Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(full("Forbidden"))
                .unwrap()));
        }

        // Check initial metadata
        let initial_meta = match tokio::fs::metadata(&safe_path).await {
            Ok(meta) => meta,
            Err(e) => return Err(Err(e)), // Return underlying IO error (likely NotFound)
        };

        if initial_meta.is_dir() {
            // It's a directory, try resolving index.html
            let index_path = safe_path.join("index.html");
            match tokio::fs::metadata(&index_path).await {
                Ok(index_meta) if !index_meta.is_dir() => {
                    Ok(index_path) // index.html exists and is a file
                }
                Ok(_) => {
                    // index.html exists but is a directory - treat as Not Found
                    Err(Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "index.html resolved to a directory",
                    )))
                }
                Err(e) => {
                    // index.html doesn't exist or other error - treat as Not Found
                    Err(Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("index.html not found or error: {}", e),
                    )))
                }
            }
        } else {
            // It's a file directly
            Ok(safe_path)
        }
    }

    /// Gets an entry from the cache or computes it if absent.
    /// Wraps the logic previously inline in the `try_get_with` call.
    async fn get_or_compute_cache_entry(
        &self,
        final_path: PathBuf, // Takes ownership of the path for the key
    ) -> Result<CachedEntry, Arc<io::Error>> {
        // Matches moka's error type
        self.entry_cache.try_get_with(final_path.clone(), async move { // Clone final_path for closure
                // --- Cache Miss: compute metadata and potentially content ---
                let final_meta = tokio::fs::metadata(&final_path).await?;
                // Ensure we are dealing with a file
                if final_meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "Path resolved to a directory unexpectedly",
                    ));
                }

                let file_size = final_meta.len();
                let modified = final_meta.modified().ok();

                // Calculate ETag here
                let etag = if let Some(mod_time) = modified {
                    mod_time
                        .duration_since(UNIX_EPOCH)
                        .map(|d| format!(r#""{}-{}""#, file_size, d.as_secs()))
                        .ok()
                } else {
                    None
                };

                let content_type: Mime = mime_guess::from_path(&final_path)
                    .first_or_octet_stream();

                let metadata = Arc::new(CachedMetadata {
                    modified,
                    content_type: content_type.clone(), // Clone for check below
                    file_size,
                    etag: etag.clone(),
                });

                // --- Decide whether to cache content ---
                let is_compressible = Self::is_content_compressible(&content_type);

                if file_size > 0 && file_size <= self.content_cache_max_file_bytes && is_compressible {
                    debug!(path = %final_path.display(), size = file_size, "Attempting to cache file content.");
                    match tokio::fs::read(&final_path).await {
                        Ok(content_bytes) => {
                             debug!(path = %final_path.display(), size = content_bytes.len(), "Successfully read content for cache.");
                            Ok(CachedEntry::FullContent(metadata, Bytes::from(content_bytes)))
                        }
                        Err(read_err) => {
                            error!("Failed to read file content for caching {}: {}. Caching metadata only.", final_path.display(), read_err);
                            Ok(CachedEntry::MetadataOnly(metadata))
                        }
                    }
                } else {
                     if file_size == 0 {
                         debug!(path = %final_path.display(), "Not caching content: file is empty.");
                     } else if file_size > self.content_cache_max_file_bytes {
                         debug!(path = %final_path.display(), size = file_size, max_size = self.content_cache_max_file_bytes, "Not caching content: file too large.");
                     } else if !is_compressible {
                          debug!(path = %final_path.display(), content_type = %content_type, "Not caching content: not compressible type.");
                     }
                    Ok(CachedEntry::MetadataOnly(metadata))
                }
            })
            .await
    }

    /// Checks conditional request headers (currently If-None-Match).
    /// Returns Some(response) if a 304 Not Modified should be sent, None otherwise.
    fn check_conditional_requests(
        &self,
        req: &Request<Incoming>,
        metadata: &Arc<CachedMetadata>,
        response_etag: &Option<String>, // Pass the calculated ETag for the response
    ) -> Option<Response<BoxedBody>> {
        // --- Conditional Check: If-None-Match ---
        if let Some(resp_etag_val) = response_etag {
            if let Some(if_none_match) = req.headers().get(header::IF_NONE_MATCH) {
                if let Ok(client_etag) = if_none_match.to_str() {
                    // Compare client ETag with the potentially modified ETag
                    if client_etag.trim() == resp_etag_val.trim() {
                        debug!(
                            client_etag,
                            response_etag = resp_etag_val,
                            "ETag match found (If-None-Match), returning 304"
                        );
                        // Match found! Build and return 304 Not Modified
                        let mut builder304 = Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .header(header::ETAG, resp_etag_val.clone()); // Send back the matched ETag

                        // Add Vary header to 304 response if content negotiation happened
                        let is_compressible = Self::is_content_compressible(&metadata.content_type);
                        if is_compressible {
                            builder304 = builder304.header(header::VARY, "Accept-Encoding");
                        }
                        // Range requests also need Accept-Ranges on 304
                        builder304 = builder304.header(header::ACCEPT_RANGES, "bytes");

                        return Some(builder304.body(empty()).unwrap());
                    } else {
                        debug!(
                            client_etag,
                            response_etag = resp_etag_val,
                            "ETag mismatch (If-None-Match)"
                        );
                    }
                }
            }
        } else {
            debug!("No ETag generated for response, skipping If-None-Match check.");
        }

        // --- Conditional Check: If-Modified-Since (can be added here) ---

        // No condition met to return early (e.g., 304)
        None
    }

    /// Handles Range requests, returning a 206 Partial Content, 416 Range Not Satisfiable,
    /// or None if the request should be handled as a full response.
    async fn handle_range_request(
        &self,
        req: &Request<Incoming>,        // Pass request by reference
        entry_to_use: &CachedEntry,     // Pass cache entry by reference
        final_path: &PathBuf,           // Pass final path by reference
        metadata: &Arc<CachedMetadata>, // Pass metadata by reference
    ) -> Result<Option<Response<BoxedBody>>, std::io::Error> {
        // --- Parse Range Header ---
        let requested_range_result =
            parse_range_header(req.headers().get(header::RANGE), metadata.file_size);

        match requested_range_result {
            Err(RangeParseError::Unsatisfiable(total_size)) => {
                debug!(
                    total_size,
                    header = ?req.headers().get(header::RANGE),
                    "Range unsatisfiable"
                );
                // Unsatisfiable range overrides other checks, return 416 wrapped in Ok(Some(...))
                Ok(Some(
                    Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(
                            header::CONTENT_RANGE,
                            format!("bytes */{}", total_size), // Required header for 416
                        )
                        .body(empty())
                        .unwrap(),
                ))
            }
            Err(RangeParseError::InvalidFormat) => {
                debug!(header = ?req.headers().get(header::RANGE), "Range header invalid format, ignoring range.");
                // Treat invalid range header as if it wasn't provided
                Ok(None) // Signal to handle as full response
            }
            Ok(Some(range)) => {
                // --- Handle Valid Range Request (Serve 206 Partial Content) ---
                let start = *range.start();
                let end = *range.end(); // Inclusive end
                debug!(
                    start,
                    end,
                    total = metadata.file_size,
                    "Valid range requested"
                );

                // --- Build 206 Response ---
                let range_content_length = end - start + 1;
                let mut builder = Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(
                        header::CONTENT_RANGE,
                        format!("bytes {}-{}/{}", start, end, metadata.file_size),
                    )
                    .header(header::CONTENT_LENGTH, range_content_length)
                    // Advertise range support always
                    .header(header::ACCEPT_RANGES, "bytes")
                    // Ranges are served uncompressed, so use identity ETag/Last-Modified
                    .header(header::CONTENT_TYPE, metadata.content_type.to_string()); // Original content type

                if let Some(mod_time) = metadata.modified {
                    builder = builder.header(header::LAST_MODIFIED, fmt_http_date(mod_time));
                }
                // Use the base (identity) ETag for range requests
                if let Some(ref identity_etag) = metadata.etag {
                    builder = builder.header(header::ETAG, identity_etag.clone());
                }

                // --- Handle HEAD for Range ---
                if *req.method() == Method::HEAD {
                    debug!("Serving HEAD for range request");
                    // Return 206 response with empty body
                    return Ok(Some(builder.body(empty()).unwrap()));
                }

                // --- Handle GET for Range ---
                debug!("Serving GET for range request");
                match entry_to_use {
                    CachedEntry::FullContent(_, content_bytes) => {
                        // Serve range from Memory Cache (zero-copy slice)
                        debug!(
                            start,
                            end,
                            cache_len = content_bytes.len(),
                            "Serving range from FullContent cache"
                        );
                        // Ensure range is within bounds (should be guaranteed by parse_range_header)
                        if start < content_bytes.len() as u64 {
                            let safe_end = (end + 1).min(content_bytes.len() as u64); // +1 for exclusive bound
                            let range_bytes =
                                content_bytes.slice(start as usize..safe_end as usize);
                            Ok(Some(builder.body(full(range_bytes)).unwrap()))
                        } else {
                            error!(
                                "Range start {} out of bounds for cached content length {}",
                                start,
                                content_bytes.len()
                            );
                            Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "Invalid range for cached content",
                            ))
                        }
                    }
                    CachedEntry::MetadataOnly(_) => {
                        // Serve range by Streaming from Disk with seek + limit
                        debug!(path = ?final_path, start, end, "Serving range by streaming MetadataOnly entry");
                        match File::open(final_path).await {
                            // Use the passed final_path
                            Ok(mut file) => {
                                file.seek(SeekFrom::Start(start)).await?; // Seek to start
                                // Limit the reader to the range length
                                let limited_reader = file.take(range_content_length);
                                // Stream the limited reader directly (no compression)
                                let stream_body = Self::create_stream_body(limited_reader);
                                Ok(Some(builder.body(BodyExt::boxed(stream_body)).unwrap()))
                            }
                            Err(e) => {
                                error!(
                                    "Failed to open file {} for range streaming: {}",
                                    final_path.display(),
                                    e
                                );
                                // Invalidate cache if file opening failed after check
                                // Need cache_key here - recalculate or pass it? Pass it.
                                let cache_key = final_path.clone(); // Reconstruct here for now
                                self.entry_cache.invalidate(&cache_key).await;
                                Err(e) // Propagate error
                            }
                        }
                    }
                } // End match entry_to_use
            } // End Ok(Some(range))
            Ok(None) => {
                // --- No Range Header -> Signal to handle as full response ---
                Ok(None)
            }
        } // End match requested_range_result
    } // End handle_range_request

    // Compression: helper function to choose encoding based on Accept-Encoding header
    fn choose_encoding(req: &Request<Incoming>, metadata: &CachedMetadata) -> ContentEncoding {
        // This function might be called before range handling (for ETag generation),
        // or for full requests. Range requests themselves force Identity later.
        debug!(content_type = %metadata.content_type, file_size = metadata.file_size, "Entering choose_encoding");
        // Check for compressibility based on MIME type AND size
        let is_compressible = Self::is_content_compressible(&metadata.content_type);

        // Avoid compression for small files (< MIN_COMPRESS_SIZE bytes) or non-compressible types
        if !is_compressible || metadata.file_size < MIN_COMPRESS_SIZE {
            if !is_compressible {
                debug!(content_type = %metadata.content_type, "Choosing Identity: Content type not compressible.");
            } else {
                debug!(
                    file_size = metadata.file_size,
                    min_size = MIN_COMPRESS_SIZE,
                    "Choosing Identity: File size too small."
                );
            }
            return ContentEncoding::Identity;
        }

        req.headers()
            .get(header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(|accept_encoding| {
                debug!(accept_encoding, "Processing Accept-Encoding header");
                // Iterate over comma-separated values and check tokens
                let mut accepts_br = false;
                let mut accepts_gzip = false;
                let mut accepts_zstd = false;

                for value in accept_encoding.split(',') {
                    let trimmed = value.trim();
                    // Get the part before any quality factor (;) if present
                    let encoding_part = trimmed.split(';').next().unwrap_or("").trim();
                    match encoding_part {
                        "br" => accepts_br = true,
                        "gzip" => accepts_gzip = true,
                        "zstd" => accepts_zstd = true,
                        "*" => {
                            // Wildcard means accept both (if not specified otherwise)
                            accepts_br = true;
                            accepts_gzip = true;
                            accepts_zstd = true;
                        }
                        _ => {}
                    }
                }

                // Prioritize br > zstd > gzip. Ignore quality factors for simplicity for now.
                // A full q-factor parser would be needed for full RFC compliance.
                let final_encoding = if accepts_br {
                    ContentEncoding::Brotli
                } else if accepts_zstd {
                    ContentEncoding::Zstd
                } else if accepts_gzip {
                    ContentEncoding::Gzip
                } else {
                    ContentEncoding::Identity
                };
                debug!(
                    accepts_br,
                    accepts_zstd,
                    accepts_gzip,
                    ?final_encoding,
                    "Encoding chosen after parsing"
                );
                final_encoding
            })
            .unwrap_or_else(|| {
                debug!("Accept-Encoding header missing or invalid, choosing Identity.");
                ContentEncoding::Identity // Default to identity if header missing/invalid
            })
    }

    // Compression: helper function to create a StreamBody from an AsyncRead source
    fn create_stream_body<R>(
        reader: R,
    ) -> StreamBody<impl Stream<Item = Result<Frame<Bytes>, io::Error>>>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let stream = tokio_util::io::ReaderStream::new(reader);
        // Map the stream items from Result<Bytes, io::Error> to Result<Frame<Bytes>, io::Error>
        let frame_stream = stream.map(|res| res.map(Frame::data));
        StreamBody::new(frame_stream)
    }

    // --- ETag Helper ---
    fn get_response_etag(base_etag: Option<&str>, encoding: ContentEncoding) -> Option<String> {
        base_etag.map(|tag| {
            // Ensure the base tag looks like a valid ETag (starts/ends with quote)
            if tag.len() >= 2 && tag.starts_with('"') && tag.ends_with('"') {
                match encoding {
                    // Append suffix for compressed encodings inside the quotes
                    ContentEncoding::Brotli => format!("{}-br\"", &tag[..tag.len() - 1]),
                    ContentEncoding::Gzip => format!("{}-gz\"", &tag[..tag.len() - 1]),
                    ContentEncoding::Zstd => format!("{}-zst\"", &tag[..tag.len() - 1]),
                    ContentEncoding::Identity => tag.to_string(), // Use original ETag
                }
            } else {
                // Return original if it doesn't look like a standard ETag
                tag.to_string()
            }
        })
    }

    // Helper to determine if content type is generally compressible
    // Extends the previous simple check.
    fn is_content_compressible(mime_type: &Mime) -> bool {
        match mime_type.type_() {
            mime::TEXT => true, // All text/* subtypes
            mime::APPLICATION => {
                // Using essence_str() to compare as lowercase strings
                match mime_type.essence_str() {
                     // Common compressible application types
                    "application/javascript" | "application/json" | "application/xml" |
                    "application/sql" | // Check subtype string directly
                    "application/svg+xml" | "application/geo+json" | // Correct check for subtypes with '+'
                    "application/wasm" // Wasm can sometimes be compressed further, though often pre-compressed
                      => true,

                    // Explicitly non-compressible application types (or types often pre-compressed)
                    "application/pdf" | "application/zip" |
                    "application/gzip" | "application/zstd" | // Check subtype string
                    "application/x-7z-compressed" | "application/x-rar-compressed" |
                    "application/octet-stream" // Usually binary/unknown, don't compress
                     => false,

                    _ => false, // Default to false for other unknown application/*
                }
            }
            // Generally don't compress these top-level types
            mime::IMAGE | mime::AUDIO | mime::VIDEO | mime::FONT => false,
            _ => false, // Default to false for other top-level types (message, model, multipart)
        }
    }
}

// --- Compression Helper for Bytes ---
async fn compress_bytes(bytes: Bytes, encoding: ContentEncoding) -> Result<Bytes, io::Error> {
    if bytes.is_empty() {
        return Ok(bytes);
    }

    // Preallocate with a guess (compression ratio varies wildly)
    // Avoid over-allocating for small inputs.
    let initial_capacity = (bytes.len() / 2).max(64);
    let mut output_buf = Vec::with_capacity(initial_capacity);

    match encoding {
        ContentEncoding::Brotli => {
            // Use Level::Precise(4) for Brotli quality 4
            let mut encoder = WriteBrotliEncoder::with_quality(&mut output_buf, Level::Precise(4));
            encoder.write_all(&bytes).await?; // Write original bytes
            encoder.shutdown().await?; // Finalize the compression stream
        }
        ContentEncoding::Gzip => {
            let mut encoder = WriteGzipEncoder::new(&mut output_buf);
            encoder.write_all(&bytes).await?; // Write original bytes
            encoder.shutdown().await?; // Finalize the compression stream
        }
        ContentEncoding::Zstd => {
            // Use Level::Precise(17) for Zstd quality 17
            let mut encoder = WriteZstdEncoder::with_quality(&mut output_buf, Level::Precise(17));
            encoder.write_all(&bytes).await?; // Write original bytes
            encoder.shutdown().await?; // Finalize the compression stream
        }
        ContentEncoding::Identity => return Ok(bytes), // No compression needed
    }
    Ok(Bytes::from(output_buf))
}
