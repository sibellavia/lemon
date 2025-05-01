# lemon 🍋

`lemon` is a general-purpose web server with a clear, human-readable configuration. It effortlessly supports both HTTP/1.1 and HTTP/2, automated HTTPS provisioning, and versatile request handling.

## Architecture

`lemon` employs a "Shared Acceptor + Tokio Runtime Pool" architecture designed for high concurrency and efficient resource utilization within a single process.

*   **Dedicated Acceptor Thread:** A single, dedicated OS thread (`lemon-acceptor`) runs a lightweight, single-threaded Tokio runtime. Its sole responsibility is to listen on all configured ports and efficiently accept incoming TCP connections using non-blocking I/O.
*   **Tokio Worker Pool:** The main multi-threaded Tokio runtime forms a worker pool. This pool handles the computationally intensive tasks.
*   **Handoff:** When the acceptor thread accepts a new connection (`TcpStream`), it immediately spawns a new asynchronous task onto the main Tokio worker pool. This task receives the connection along with its necessary context (like the appropriate handler, TLS configuration, etc.).
*   **Connection Processing:** Tasks running on the worker pool handle the entire connection lifecycle:
    *   Performing the TLS handshake (if required) using Rustls.
    *   Parsing and processing HTTP requests using Hyper.
    *   Executing the logic defined by the configured handler (e.g., reading a file, proxying a request).
    *   Sending the response back to the client.

This separation isolates the performance-critical `accept()` operation from request processing, allowing the worker threads to focus entirely on handling application logic and TLS, leading to improved throughput under load compared to models where workers might also handle accept calls. The handoff via `tokio::spawn` leverages Tokio's efficient task scheduling.

## Features

*   **LemonConfig:** Uses a clear, human-readable `lemon.toml` file for defining server instances and their behavior.
*   **HTTP/1.1 and HTTP/2 Support:** Automatically negotiates HTTP/1.1 or HTTP/2 based on client capabilities (via ALPN for HTTPS connections).
*   **Automatic HTTPS (ACME):** Built-in integration with Let's Encrypt via `rustls-acme` for automatic TLS certificate acquisition and renewal.
*   **Manual TLS:** Supports configuration using manually provisioned TLS certificate and key files.
*   **Handlers:**
    *   **Static File Serving:** Efficiently serves static content from a specified directory.
    *   **Reverse Proxy:** Forwards requests to upstream backend services.
    *   **HTTPS Redirect:** Automatically redirects HTTP requests to their HTTPS equivalent.
    *   **Health Check:** Provides a simple `GET /` endpoint returning `200 OK`.
*   **HTTP Range Requests:** Supports partial content requests (`Range: bytes=...`) for the static file handler, enabling efficient serving of large files and resumable downloads.
*   **Automatic Content Compression:** Compresses eligible responses using Brotli, Zstd, or Gzip based on client `Accept-Encoding` headers, prioritizing modern, efficient algorithms. Includes intelligent ETag modification for compressed content.
*   **Static Content Caching:** In-memory caching for frequently accessed static files to reduce disk I/O.
*   **Automatic Security Headers:** Adds important security headers like `Strict-Transport-Security`, `X-Frame-Options`, and `X-Content-Type-Options` by default, with configuration options.
*   **Configurable Logging:** Flexible logging powered by `tracing`, supporting different levels, formats (text, JSON), and outputs (stdout, file).

## Getting Started

### Prerequisites

*   Rust Toolchain ([https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install))

### Building

```bash
git clone https://github.com/sibellavia/lemon.git
cd lemon
cargo build --release
```

### Running

1.  Create a `lemon.toml` configuration file (see Section 5).
2.  Run the compiled binary:

    ```bash
    ./target/release/lemon
    ```

The server will start based on the configuration in `lemon.toml`. Logs will be printed to standard output.

### Command-Line Interface (CLI)

The `lemon` executable provides several commands:

*   **`lemon run` (or simply `lemon`)**: This is the default command. It reads the LemonConfig (defaulting to `lemon.toml` in the current directory) and starts the server instance(s) defined within it.
*   **`lemon validate`**: Checks the syntax and validates the configuration file according to `lemon`'s rules. It reports whether the configuration is valid or lists any errors found.
    ```bash
    lemon validate 
    lemon validate --config path/to/your/config.toml
    ```
*   **`lemon create-config`**: Creates a basic `lemon.toml` file in the current directory with commented-out examples for common server types (HTTP static, ACME HTTPS, Reverse Proxy).
    ```bash
    lemon create-config
    ```
    *   Use the `--force` flag to overwrite an existing `lemon.toml` file:
        ```bash
        lemon create-config --force
        ```

**Global Options:**

*   **`--config <FILE>` (or `-c <FILE>`)**: Specifies the path to the configuration file to use. This flag can be used with any command (e.g., `lemon --config myconfig.toml run`, `lemon -c myconfig.toml validate`).
    *   **Default:** `lemon.toml`

## LemonConfig (`lemon.toml`)

`lemon` uses a TOML file named `lemon.toml` located in the working directory where the server runs. This file defines one or more server instances, each with its own listening address, optional TLS settings, and request handler.

**Principles:**

1.  **Explicitness:** required settings are explicit.
2.  **Separation of concerns:** listening (address/port), security (TLS), and functionality (handlers) are distinct configuration sections.
3.  **Simple Cases = Simple Config:** basic HTTP/S servers require minimal boilerplate.
4.  **Discoverability:** structure and naming should guide the user.

### 5.1. Overall Structure

The configuration file consists of one or more `[server.<name>]` tables. Each table defines a distinct server instance. The `<name>` (e.g., `main_site`, `api_proxy`) is chosen by the user and serves as an identifier in logs.

```toml
# Example structure with multiple server instances

[server.main_site]
# Configuration for the 'main_site' HTTPS server...
listen_addr = "0.0.0.0:443"
tls = { type = "acme", domains = ["example.com"], contact = "mailto:admin@example.com" }
handler = { type = "static", www_root = "/var/www/html/main_site" }

[server.http_redirector]
# Configuration for an HTTP redirector server...
listen_addr = "0.0.0.0:80"
# No tls = HTTP
handler = { type = "redirect_https", target_base = "https://example.com" } # Planned handler
```

At least one `[server.<name>]` block is required.

*(optional global settings for logging or timeouts might be introduced later.)*

### Server Block Options

Each `[server.<name>]` block requires `listen_addr` and `handler`, and optionally accepts `tls`.

#### `listen_addr` (Required)

Specifies the IP address and port the server instance should bind to.

*   **Type:** String
*   **Format:** `"IP_ADDRESS:PORT"` (e.g., `"0.0.0.0:443"`, `"127.0.0.1:8080"`, `"[::]:80"` for IPv6)
*   **Validation:** Must be a valid socket address parseable by Rust's `SocketAddr`.

```toml
[server.example]
listen_addr = "0.0.0.0:80"
handler = { type = "healthcheck" }
```

#### `tls` (Optional)

Automatically configures TLS (HTTPS) for the server instance. If this section is omitted, the server will operate over plain HTTP.

*   **Type:** Table
*   **Structure:** Contains a mandatory `type` field and type-specific options.

**Implemented TLS types:**

*   **`type = "acme"`:** Enables automatic certificate management using ACME (Let's Encrypt).
    *   `domains` (Required): An array of strings listing the domain names this certificate should cover.
    *   `contact` (Required): A string specifying the contact email address for the Let's Encrypt account, prefixed with `mailto:`.
    *   `cache_dir` (Optional): A string specifying the path to a directory for storing ACME state.
        *   **Default:** `"./acme-cache"`
    *   `staging` (Optional): A boolean indicating whether to use the Let's Encrypt staging environment (`true`) or production (`false`). Recommended for testing.
        *   **Default:** `false` (Production)
    *   **Validation:** `domains` must not be empty. `contact` must start with `mailto:`. `cache_dir` must not be empty if specified.

```toml
[server.secure_site]
listen_addr = "0.0.0.0:443"
tls = { type = "acme", domains = ["example.com", "www.example.com"], contact = "mailto:admin@example.com", cache_dir = "/var/cache/lemon/acme", staging = true }
handler = { type = "static", www_root = "/var/www/secure" }
```

*   **`type = "manual"`:** Enables TLS using user-provided certificate and private key files. This is necessary when not using ACME, for example, with certificates from an internal Certificate Authority (CA), another provider, or pre-existing certificates.
    *   `certificate_file` (Required): A string specifying the path to the certificate chain file. The file must be in PEM format and should contain the server's certificate followed by any intermediate certificates required to build a trusted chain.
    *   `key_file` (Required): A string specifying the path to the private key file. The file must be in PEM format and contain a compatible private key (PKCS#1 RSA, PKCS#8, or SEC1/RFC5915). `lemon` will use the first valid key found in the file.
    *   **Validation:** Both `certificate_file` and `key_file` must be non-empty strings pointing to readable files containing valid PEM-encoded data.

```toml
[server.manual_tls_site]
listen_addr = "0.0.0.0:443"
tls = { type = "manual", certificate_file = "/etc/lemon/certs/my_site.crt", key_file = "/etc/lemon/certs/my_site.key" }
handler = { type = "reverse_proxy", target_url = "http://localhost:8080" }
```

*   **`type = "local_dev"`:** Automatically generates a temporary, self-signed TLS certificate when the server starts. This is ideal for easily enabling HTTPS during local development and testing without needing to generate or provide certificate files manually.
    *   **Certificate Validity:** The generated certificate includes Subject Alternative Names (SANs) for `localhost` and `127.0.0.1`, making it suitable for testing requests directed to these common local addresses.
    *   **Parameters:** This type requires no additional parameters within the `tls` table.
    *   **Trust:** Since the certificate is self-signed, browsers and tools like `curl` will show trust warnings. You will typically need to explicitly bypass these warnings or configure your client to trust the specific certificate for testing purposes.

```toml
# Example: Run a local development server with auto-generated TLS
[server.dev_server]
listen_addr = "127.0.0.1:8443"
tls = { type = "local_dev" }
handler = { type = "reverse_proxy", target_url = "http://localhost:3000" } # Example proxying to a front-end dev server
```

#### `handler` (Required)

Defines how the server instance should process incoming requests.

*   **Type:** Table
*   **Structure:** Contains a mandatory `type` field and type-specific options.

**Implemented handler types:**

*   **`type = "static"`:** Serves static files from a directory.
    *   `www_root` (Required): Path to the root directory containing the static files.
    *   `content_cache_max_file_bytes` (Optional): Maximum size in bytes for a single file to be cached entirely in memory. Files larger than this will still have metadata cached, but content will be streamed from disk.
        *   **Default:** `1048576` (1 MiB)
    *   `content_cache_max_total_bytes` (Optional): Maximum total size in bytes for the in-memory content cache across all cached files. Uses a weighted eviction strategy (larger files contribute more to the limit).
        *   **Default:** `268435456` (256 MiB)
    *   **Validation:** `www_root` must not be empty. Directory should exist and be readable.

    ```toml
    [server.static_server]
    listen_addr = "0.0.0.0:8080"
    handler = { type = "static", www_root = "./public_html" }
    ```

*   **`type = "reverse_proxy"`:** Forwards incoming requests to a specified backend URL.
    *   `target_url` (Required): The base URL of the backend service. (Note: Renamed from `upstream` in some discussions for clarity in docs).
    *   **Validation:** `target_url` must not be empty and must be a parseable URL.

    ```toml
    [server.api_proxy]
    listen_addr = "127.0.0.1:9000"
    handler = { type = "reverse_proxy", target_url = "http://localhost:5000/api" }
    ```

*   **`type = "healthcheck"`:** Provides a simple health check endpoint. Responds with `200 OK` and "Healthy" body to `GET /`. Accepts no additional configuration parameters.

    ```toml
    [server.health]
    listen_addr = "127.0.0.1:9999"
    handler = { type = "healthcheck" }
    ```

*   **`type = "redirect_https"`:** Redirects incoming HTTP requests (typically on port 80) to their corresponding HTTPS URL. This handler is essential for ensuring users automatically use the secure version of a site.
    *   `target_base` (Required): The base HTTPS URL to redirect to (e.g., `"https://example.com"`). This URL *must* use the `https` scheme and should not include any path, query string, or fragment components. The handler automatically preserves the original request's path and query parameters when constructing the final redirect `Location` header.
    *   **Behavior:** Responds with `301 Moved Permanently` for `GET` and `HEAD` requests. Other request methods will receive `405 Method Not Allowed`.
    *   **Validation:** `target_base` must not be empty and must be a valid base HTTPS URL.

    ```toml
    # Example: Redirect all traffic on port 80 to the HTTPS version
    [server.http_redirector]
    listen_addr = "0.0.0.0:80"
    # No tls = HTTP
    handler = { type = "redirect_https", target_base = "https://my-secure-domain.com" }
    ```

#### `security` (Optional)

Configures automatic addition of common security-related HTTP headers.

*   **Type:** Table
*   **Defaults:** If this section is omitted entirely, or if specific fields are omitted, secure defaults are applied as if `add_default_headers = true`.
*   **Structure:** Contains optional fields to control header behavior.

```toml
[server.my_app]
listen_addr = "0.0.0.0:443"
tls = { type = "acme", domains = ["app.example.com"], contact = "mailto:sec@example.com" }
handler = { type = "reverse_proxy", target_url = "http://localhost:8080" }
# Example security configuration
security = {
  add_default_headers = true,      # Explicitly enable (default is true)
  hsts_max_age = 63072000,       # Override HSTS max-age to 2 years
  hsts_include_subdomains = true,  # Default
  hsts_preload = true,             # Enable HSTS preload
  frame_options = "SAMEORIGIN"     # Override default X-Frame-Options
}
```

**Options within the `security` table:**

*   **`add_default_headers`** (Optional, Boolean): Enables/disables the automatic addition of all security headers controlled by this section (HSTS, X-Content-Type-Options, X-Frame-Options).
    *   **Default:** `true`
*   **`hsts_max_age`** (Optional, Integer): Specifies the `max-age` value in seconds for the `Strict-Transport-Security` (HSTS) header. This header is only added for HTTPS servers.
    *   **Default:** `31536000` (1 year)
*   **`hsts_include_subdomains`** (Optional, Boolean): If `true`, adds the `includeSubDomains` directive to the HSTS header. Only added for HTTPS servers.
    *   **Default:** `true`
*   **`hsts_preload`** (Optional, Boolean): If `true`, adds the `preload` directive to the HSTS header. Only added for HTTPS servers. Use with caution and ensure your site meets preload list requirements.
    *   **Default:** `false`
*   **`frame_options`** (Optional, String): Specifies the value for the `X-Frame-Options` header.
    *   **Allowed Values:** `"DENY"`, `"SAMEORIGIN"`, `"NONE"` (case-insensitive during validation, but canonical values are recommended). `"NONE"` disables the header.
    *   **Default:** `"DENY"` (implicitly, if `add_default_headers` is `true` and `frame_options` is omitted).

**Planned handler types:**

*(more handlers like API gateways, WebSocket proxies, etc., will be added by extending this structure).*

### Configuration Examples

#### Simple HTTP Static Server

```toml
[server.my_http_site]
listen_addr = "0.0.0.0:8080"
handler = { type = "static", www_root = "./public" }
```

#### Simple ACME HTTPS Static Server

```toml
[server.my_https_site]
listen_addr = "0.0.0.0:443"
# cache_dir will default to ./acme-cache, staging defaults to false
tls = { type = "acme", domains = ["mydomain.com"], contact = "mailto:me@mydomain.com" }
handler = { type = "static", www_root = "./public" }
```

#### ACME Server with Explicit Cache & Staging

```toml
[server.my_other_https_site]
listen_addr = "[::]:443" # IPv6 example
tls = { type = "acme", domains = ["other.net"], contact = "mailto:admin@other.net", cache_dir = "/var/lib/lemon/acme", staging = true }
handler = { type = "static", www_root = "/srv/www/other" }
```

#### Static Server with Custom Content Cache Limits

```toml
[server.cached_static]
listen_addr = "0.0.0.0:8081"
handler = {
  type = "static",
  www_root = "./public_assets",
  # Cache files up to 2MB each
  content_cache_max_file_bytes = 2097152,
  # Allow total cache size up to 512MB
  content_cache_max_total_bytes = 536870912
}
```

## Compression

`lemon` automatically handles HTTP response compression to reduce bandwidth usage and improve load times. Currently, this feature is primarily implemented within the `static` file handler.

*   **Content Negotiation:** Compression is applied based on the client's `Accept-Encoding` request header.
*   **Supported Algorithms:** `lemon` supports and prioritizes the following encodings:
    1.  Brotli (`br`) - Quality level 4 (good balance of speed and ratio)
    2.  Zstd (`zstd`) - Quality level 17 (high compression)
    3.  Gzip (`gzip`)
*   **Skipped Compression:** Compression is intelligently skipped when:
    *   The client does not support any of the above encodings.
    *   The content's MIME type is typically already compressed or not suitable for compression (e.g., `image/jpeg`, `image/png`, `video/mp4`, `application/pdf`, `application/zip`, font types).
    *   The content size is very small (< 256 bytes), where compression overhead might outweigh benefits.
*   **Header Handling:**
    *   The `Content-Encoding` header is added to indicate the chosen compression method (e.g., `Content-Encoding: br`).
    *   The `Vary: Accept-Encoding` header is added to responses for compressible content types, signaling to caches that the response may differ based on the client's accepted encodings.
    *   The `Content-Length` header is omitted for compressed responses as the size is determined dynamically during streaming.
*   **ETag Modification:** When compression is applied, the `ETag` header value is modified with a suffix (e.g., `"base-etag-br"`, `"base-etag-zst"`, `"base-etag-gz"`) to ensure cache validators correctly distinguish between different encodings of the same resource.
*   **Range Requests Interaction:** HTTP Range requests (`Range: bytes=...`) requesting partial content are served uncompressed (identity encoding) even if the content type is normally compressible and the client accepts compression. This ensures compatibility and simplifies partial content delivery.

## Logging

`lemon` uses the `tracing` library for logging. You can configure logging behavior through the optional `[logging]` section in your `lemon.toml` file or via the `RUST_LOG` environment variable.

**Configuration Precedence:**

1.  **`RUST_LOG` Environment Variable:** If set, this overrides any level settings in the config file. It uses the standard `tracing_subscriber::EnvFilter` format (e.g., `RUST_LOG=info`, `RUST_LOG=lemon=debug,hyper=info`).
2.  **`[logging]` section in `lemon.toml`:** Defines level, format, and output if `RUST_LOG` is not set.
3.  **Default:** If neither `RUST_LOG` nor `[logging]` is specified, logs default to `INFO` level, `text` format, and `stdout` output.

**`[logging]` Section Options:**

```toml
[logging]
# Log level. Overridden by RUST_LOG env var if set.
# Valid levels: "trace", "debug", "info", "warn", "error"
# Default: "info"
level = "debug"

# Log output format.
# Valid formats: "text", "json"
# Default: "text"
format = "text"

# Log output destination.
# Default: { type = "stdout" }
# output = { type = "stdout" }
# output = { type = "file", path = "/var/log/lemon/lemon.log" }
output = { type = "file", path = "./lemon.log" }
```

*   **`level`** (Optional, String): Sets the minimum log level. Defaults to `"info"`. Ignored if `RUST_LOG` is set.
*   **`format`** (Optional, String): Sets the log output format. `"text"` is human-readable, while `"json"` produces structured JSON logs. Defaults to `"text"`.
*   **`output`** (Optional, Table): Determines where logs are written.
    *   **`type = "stdout"`**: Logs to the standard output (console). This is the default.
    *   **`type = "file"`**: Logs to a file.
        *   **`path`** (Required, String): The path to the log file. `lemon` uses daily rotation for log files created with this option.

## Security Headers

`lemon` automatically adds several important security-related HTTP headers to responses to help protect against common web vulnerabilities. This is done by default to promote secure configurations.

*   **Mechanism:** Headers are added via an internal middleware wrapper that processes the response generated by the configured handler (`static`, `reverse_proxy`, etc.) before it's sent to the client.
*   **Non-Overwriting:** The wrapper uses `HeaderMap::entry().or_insert()` logic. This means if your backend application (in `reverse_proxy` mode) or a future custom handler sets one of these headers itself, `lemon` will **not** overwrite the value provided by the handler.
*   **Performance:** Header names and common values (`nosniff`, `DENY`, `SAMEORIGIN`) are defined as static constants to avoid per-request allocations. The `Strict-Transport-Security` header value is pre-computed based on the configuration when the server starts.

**Default Headers Added:**

*   **`X-Content-Type-Options: nosniff`**: Prevents browsers from MIME-sniffing the content-type away from the declared one.
*   **`X-Frame-Options: DENY`**: Prevents the site from being embedded within an `<iframe>` or `<object>`, mitigating clickjacking attacks. (Can be changed to `SAMEORIGIN` or disabled via configuration).
*   **`Strict-Transport-Security` (HSTS)**: For **HTTPS servers only**. Tells browsers to always connect using HTTPS for the configured duration. The exact value depends on the configuration.

**Configuration:**

This feature is controlled by the optional `[server.<name>.security]` section in your `lemon.toml` file. See Section 5.2 under `security` for details on the available options (`add_default_headers`, `hsts_max_age`, `hsts_include_subdomains`, `hsts_preload`, `frame_options`) and their defaults.

By default (`add_default_headers = true`), all the headers listed above are added (with HSTS only applying to HTTPS servers).