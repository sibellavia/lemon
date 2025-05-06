# lemon 🍋

`lemon` is a general-purpose web server with a clear, human-readable configuration. It effortlessly supports both HTTP/1.1 and HTTP/2, automated HTTPS provisioning, and versatile request handling.

    Note: lemon is under active development, not intended to be production-ready.

## Features

*   **lemonConfig:** lemon uses a clear, human-readable `lemon.toml` file for defining server instances and their behavior.
*   **HTTP/1.1 and HTTP/2 Support:** lemon automatically negotiates HTTP/1.1 or HTTP/2 based on client capabilities (via ALPN for HTTPS connections).
*   **Automatic HTTPS (ACME):** built-in integration with Let's Encrypt via `rustls-acme` for automatic TLS certificate acquisition and renewal.
*   **Manual TLS:** supports configuration using manually provisioned TLS certificate and key files.
*   **Handlers:**
    *   **Static File Serving:** efficiently serves static content from a specified directory.
    *   **Reverse Proxy:** forwards requests to upstream backend services.
    *   **HTTPS Redirect:** automatically redirects HTTP requests to their HTTPS equivalent.
    *   **Health Check:** provides a simple `GET /` endpoint returning `200 OK`.
*   **HTTP Range Requests:** supports partial content requests (`Range: bytes=...`) for the static file handler, enabling efficient serving of large files and resumable downloads.
*   **Automatic Content Compression:** lemon compresses eligible responses using Brotli, Zstd, or Gzip based on client `Accept-Encoding` headers, prioritizing modern, efficient algorithms. Includes intelligent ETag modification for compressed content.
*   **Static Content Caching:** in-memory caching for frequently accessed static files is present to reduce disk I/O.
*   **Automatic Security Headers:** lemon adds important security headers like `Strict-Transport-Security`, `X-Frame-Options`, and `X-Content-Type-Options` by default, with configuration options.
*   **Configurable Logging:** flexible logging powered by `tracing`, supporting different levels, formats (text, JSON), and outputs (stdout, file).

## Getting Started

### Prerequisites

*   Rust Toolchain ([https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install))

### Building

```bash
git clone https://github.com/sibellavia/lemon.git
cd lemon
cargo build --release
```

The compiled binary will be located at `./target/release/lemon`.

### Running lemon

`lemon` can be controlled via command-line arguments. Here's how to get started:

1.  **Create a lemonConfig:**
    `lemon` requires a configuration file (`lemonConfig`), typically named `lemon.toml`, to define server behavior. You can create a starter file with examples:
    ```bash
    ./target/release/lemon create-config
    ```
    This creates `lemon.toml` in the current directory. Edit this file according to your needs (see the [LemonConfig](#lemonconfig-lemontoml) section below). Use `--force` to overwrite an existing file.

2.  **Validate the configuration (Optional):**
    Before running, you can check if your configuration file is valid:
    ```bash
    ./target/release/lemon validate
    # Or specify a different path:
    ./target/release/lemon validate --config path/to/your/config.toml
    ```

3.  **Run `lemon`:**
    Once your `lemon.toml` is ready, start the server:
    ```bash
    ./target/release/lemon run
    # 'run' is the default command, so you can also just use:
    ./target/release/lemon
    ```
    The server will start based on the configuration found in `lemon.toml` (or the file specified with `--config`). Logs will be printed to standard output by default.

4.  **Setup as a Systemd Service (Linux - Recommended for Servers):**
    To run `lemon` persistently as a background service on Linux, use the `setup-systemd` command. This requires `sudo` privileges.
    ```bash
    sudo ./target/release/lemon setup-systemd
    ```
    This command automates the creation of a `lemon` system user, copies the binary, sets up necessary directories, installs a `systemd` unit file, and starts the service. See the dedicated section "[Running `lemon` as a Systemd Service (Linux)](#running-lemon-as-a-systemd-service-linux)" for full details.

**Global Options:**

*   **`--config <FILE>` (or `-c <FILE>`)**: Specifies the path to the configuration file to use instead of the default `lemon.toml`. This flag can be used with `run` and `validate`.
    *   Example: `./target/release/lemon --config /etc/lemon/prod.toml`

### Running `lemon` as a Systemd Service (Linux)

For running `lemon` persistently on a Linux server, integrating with `systemd` is the recommended approach. `lemon` provides a command to help automate this setup.

**Prerequisites:**

*   **`lemon` installed:** You should have the `lemon` binary installed. The common way is via `cargo`:
    ```bash
    cargo install lemon-server 
    ```
    This typically installs the binary to `$HOME/.cargo/bin/`.
*   **Binary accessible in `PATH` (for convenience) or direct path usage:**
    *   If `$HOME/.cargo/bin` is in your user's `PATH` (common if Rust was installed with `rustup`), you can proceed.
    *   If not, or if `sudo` doesn't find `lemon` (see below), you'll need to use the full path to the binary.
*   **`sudo` privileges:** Required to run the `setup-systemd` command for system-wide changes.

**Setup Command:**

Execute the following command with `sudo`. If `lemon` was just installed via `cargo install` and `$HOME/.cargo/bin` is not in `sudo`'s secure path, you'll need to provide the full path to the `lemon` binary (typically `$HOME/.cargo/bin/lemon`):

```bash
# If $HOME/.cargo/bin/lemon is accessible to sudo via its PATH (less common for sudo):
sudo lemon setup-systemd

# More reliably, especially after a fresh 'cargo install':
sudo $HOME/.cargo/bin/lemon setup-systemd

# Or, if you copied it to /usr/local/bin/ yourself first:
# sudo /usr/local/bin/lemon setup-systemd
```

This command will perform the following actions:

1.  **Create `lemon` User and Group:** A dedicated system user and group named `lemon` are created to run the server with minimal privileges.
2.  **Copy Binary:** The `lemon` executable that runs the command is copied to `/usr/local/bin/lemon`.
3.  **Set Capabilities:** The `CAP_NET_BIND_SERVICE` capability is set on `/usr/local/bin/lemon`, allowing it to bind to privileged ports (like 80 and 443) without running the entire process as root.
4.  **Create Directories:**
    *   `/opt/lemon`: Default working directory for the service.
    *   `/etc/lemon/`: Default location for `lemon.toml` configuration file.
    *   `/var/lib/lemon/acme-cache/`: Default directory for storing ACME (Let's Encrypt) certificates and state.
    *   `/var/log/lemon/`: Directory for potential future file-based logging (though `journald` is primary with systemd).
    All these directories will be owned by the `lemon` user/group.
5.  **Install Systemd Unit File:** A `lemon.service` file is created and placed in `/etc/systemd/system/`. This file configures how `systemd` manages the `lemon` process.
6.  **Enable and Start Service:**
    *   `systemctl daemon-reload` is run to make `systemd` aware of the new service.
    *   `systemctl enable lemon.service` is run to ensure `lemon` starts automatically on system boot.
    *   `systemctl start lemon.service` is run to start `lemon` immediately.

**Configuration:**

After running `setup-systemd`, you **must** create or place your `lemon.toml` configuration file at:

*   `/etc/lemon/lemon.toml`

The `lemon` service will use this configuration file by default.

**Managing the `lemon` Service:**

Once set up, you can manage the `lemon` service using standard `systemctl` commands:

*   **Check Status:** `sudo systemctl status lemon.service`
*   **Start Service:** `sudo systemctl start lemon.service`
*   **Stop Service:** `sudo systemctl stop lemon.service`
*   **Restart Service:** `sudo systemctl restart lemon.service`
*   **Enable on Boot:** `sudo systemctl enable lemon.service`
*   **Disable on Boot:** `sudo systemctl disable lemon.service`

**Logging with Systemd:**

*   When `lemon` runs as a `systemd` service, its standard output (`stdout`) and standard error (`stderr`) are captured by the systemd journal.
*   You can view these logs using: `journalctl -u lemon.service -f` (to follow live logs) or `journalctl -u lemon.service` (to see recent logs).
*   **Recommendation:** For seamless integration with `journalctl`, it's recommended to use `lemon`'s default `stdout` logging output in your `/etc/lemon/lemon.toml` (i.e., either omit the `[logging.output]` section or set `output = { type = "stdout" }`).
*   If you configure `lemon`'s `logging.output` to be of type `file` (e.g., `output = { type = "file", path = "/var/log/lemon/app.log" }`), `lemon`'s application logs will be written to that specified file directly and will **not** appear in the `journalctl` output for the service.

## Architecture

`lemon` employs a *Shared Acceptor + Tokio Runtime Pool* architecture designed for high concurrency and efficient resource utilization within a single process.

At its core, a single, dedicated OS thread (`lemon-acceptor`) runs a lightweight, single-threaded Tokio runtime. Its sole responsibility is to listen on all configured ports and efficiently accept incoming TCP connections using non-blocking I/O. Concurrently, the main multi-threaded Tokio runtime forms a worker pool dedicated to handling the computationally intensive tasks.

When the acceptor thread accepts a new connection (`TcpStream`), it immediately performs a handoff by spawning a new asynchronous task onto the main Tokio worker pool. This new task receives the connection along with its necessary context, such as the appropriate handler and TLS configuration.

Tasks running on the worker pool then manage the entire connection lifecycle. This includes performing the TLS handshake (if required) using Rustls, parsing and processing HTTP requests via Hyper, executing the logic defined by the configured handler (like serving a static file or proxying a request), and finally sending the response back to the client.

This architectural separation isolates the performance-critical `accept()` operation from the complexities of request processing. It allows the worker threads to focus entirely on handling application logic and TLS operations, leading to improved throughput under load compared to models where workers might also handle accept calls. The handoff mechanism leverages Tokio's efficient task scheduling via `tokio::spawn`.

## lemonConfig (`lemon.toml`)

`lemon` uses a TOML file named `lemon.toml` located in the working directory where the server runs. This file defines one or more server instances, each with its own listening address, optional TLS settings, and request handler.

**Principles:**

1.  **Explicitness:** required settings are explicit.
2.  **Separation of concerns:** listening (address/port), security (TLS), and functionality (handlers) are distinct configuration sections.
3.  **Simple Cases = Simple Config:** basic HTTP/S servers require minimal boilerplate.
4.  **Discoverability:** structure and naming should guide the user.

### Overall Structure

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
    *   **Permissions when running as a service:** When `lemon` is managed by `systemd` (see "Running `lemon` as a Systemd Service" section), the server process runs as a dedicated `lemon` system user. This `lemon` user **must** have read access (and execute access for directories) to the path specified in `www_root` and all its contents.
        *   You can use absolute paths for `www_root` (e.g., `/var/www/my_site/public` or `/opt/lemon/www/my_site_docs`).
        *   If using a relative path, it will be relative to the service's `WorkingDirectory` (which defaults to `/opt/lemon` when set up by `lemon setup-systemd`).
        *   Ensure you set appropriate ownership (e.g., `sudo chown -R lemon:lemon /path/to/your/www_root`) or permissions (e.g., `sudo chmod -R a+rX /path/to/your/www_root`) for the `lemon` user.

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
    *   **Default:** `