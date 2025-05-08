# zest 🍋⚡️

so `zest` is my little experiment to build a super-fast TCP listening layer for `lemon` (and potentially other Tokio-based Rust apps). the main idea is to squeeze out as much performance as possible when it comes to just accepting new connections, especially on beefy multi-core machines.

## Core Idea

We all know that a single listener can become a bottleneck, right? So, `zest` tries to tackle this by:

1.  **`SO_REUSEPORT`**: on Unix-y systems, `zest` will try to create one listening socket per CPU core (or a configurable number of threads) on the same IP address and port. The OS kernel then will load-balance incoming connections across these sockets. This means multiple threads can be accepting connections simultaneously, which should be way faster under heavy load.
2.  **Dedicated Acceptor Threads**: each of these `SO_REUSEPORT` sockets (or a single traditional socket in fallback mode) is managed by its own dedicated OS thread. 
3.  **Minimal Tokio Runtimes**: inside each of these OS threads, we spin up a lightweight, `current_thread` Tokio runtime. Its only job is to `accept()` connections and sling them over an MPSC channel.
4.  **Fallback Mode**: if `SO_REUSEPORT` isn't available or a good fit (e.g., on Windows, or if forced by config), `zest` can fall back to the traditional single-listener setup per configured address. Still uses a dedicated thread and its own Tokio runtime for accepting.

## How It Works (Roughly)

When you tell `ZestService` to `listen()`:

1.  It looks at all the `ZestListenerConfig`s you give it.
2.  For each config, it figures out if it should go full `SO_REUSEPORT` or just use a single listener.
3.  It then spawns the necessary number of OS threads. These are named like `zest-acceptor-<ip>-<port>-<index>` so you can spot them in `htop` or whatever.
4.  **Inside each OS thread**:
    *   A new `current_thread` Tokio runtime is born.
    *   This runtime tries to create the actual `tokio::net::TcpListener`:
        *   if `SO_REUSEPORT` is active for this listener configuration, it uses the `socket2` crate to create a socket, sets `SO_REUSEADDR` and `SO_REUSEPORT`, binds it, and then converts it into a Tokio-compatible listener. this is the tricky bit, especially making sure it's non-blocking for Tokio.
        *   if it's single-listener mode, it just does a normal `TcpListener::bind()`.
    *   The thread sends its setup status (success/failure) back to the main `listen` function using a `oneshot` channel.
    *   If setup was OK, it enters the main `accept()` loop, `tokio::select!` between new connections and a shutdown signal.
    *   When a connection comes in, it packages it up into an `AcceptedTcpConnection` (which includes the stream, remote/local addrs, and the `listener_id` you originally provided) and sends it down an MPSC channel.
5.  The main `listen` function waits for all the spawned threads to report their setup status. If at least one thread was successful for any of the initial listener configs, it gives you back the receiving end of that MPSC channel.
6.  Your application (in our case, `lemon`) then just pulls `AcceptedTcpConnection`s from this channel and does its thing (TLS, HTTP processing, etc.).

## API Snippets

(check `src/lib.rs`)

```rust
// What you give to zest:
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZestProtocol {
    Tcp,
    // Quic, // Placeholder for future QUIC support
}

pub struct ZestListenerConfig {
    pub listen_address: SocketAddr,
    pub listener_id: u64, // So you know which of your configs this connection belongs to
    pub protocol: ZestProtocol,
}

pub struct ZestGlobalSettings {
    pub force_single_listener_mode: bool, // skip SO_REUSEPORT
    pub listener_threads_per_address: Option<usize>, // default: num_cpus
    pub tcp_listen_backlog: Option<u32>,
}

// What zest gives you back:
#[derive(Debug)]
pub enum ZestTransportStream {
    Tcp(TcpStream),
    // Placeholder for future QUIC support
    // Udp(tokio::net::UdpSocket), // Or a QUIC connection/stream type from a library
}

#[derive(Debug)]
pub struct AcceptedConnection {
    pub stream: ZestTransportStream,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub listener_id: u64,
}

// How you start it (more or less):
pub struct ZestService;
impl ZestService {
    pub async fn listen(
        listener_configs: Vec<ZestListenerConfig>,
        global_settings: ZestGlobalSettings,
        global_shutdown_rx: watch::Receiver<()>, 
    ) -> anyhow::Result<mpsc::Receiver<AcceptedConnection>> { /* ... */ }
}
```

## Error Handling

Currently using `anyhow::Result` for convenience, just like `lemon` does. If a thread can't set up its listener (e.g., port already in use without `SO_REUSEPORT`, permission denied for port 80), it reports this back. `ZestService::listen` will only return `Ok` if at least one listener thread *somewhere* starts up successfully.

## Current Status & TODO

the basic multi-threaded acceptor logic with `SO_REUSEPORT` and single-listener fallback seems to be taking shape. tests are passing for the core setup paths!

**TODO List / Ideas for Future Me:**

*   **Robustness & Edge Cases**: 
    *   What if a spawned OS thread panics after successful setup? How should `ZestService` or the main app know/react? (Currently, the MPSC channel would just close when all senders are dropped).
    *   Better error propagation from `create_tokio_listener` if it fails in some subtle way that isn't caught by the `oneshot` status channel immediately (even if current setup seems okay).
*   **Configuration**: 
    *   Make MPSC channel buffer size configurable via `ZestGlobalSettings`?
    *   TCP socket options for the listening socket (e.g., `SO_RCVBUF`, `SO_SNDBUF` via `socket2`)? Or is this overkill for just the listener? (Note: `tcp_listen_backlog` is already in `ZestGlobalSettings`).
    *   Should accepted sockets have `TCP_NODELAY` or `SO_KEEPALIVE` set by `zest`, or leave that entirely to the app that receives the `TcpStream`?
*   **Performance**: 
    *   Benchmark this thing properly against a simple single-threaded Tokio acceptor
    *   Explore pinning acceptor OS threads to specific CPU cores (`core_affinity`)
*   **Windows `SO_REUSEPORT` equivalent?**: I don't care about Windows honesly.
*   **UDP Support**: the API has been updated to include `ZestProtocol` in `ZestListenerConfig` and `AcceptedConnection` now uses a `ZestTransportStream` enum. This lays some groundwork for potentially supporting UDP listeners (e.g. for QUIC) in the future, which would involve adding new variants and dedicated setup/accept logic.
*   **Graceful Shutdown of Accept Loops**: the `watch::channel` for shutdown is passed in. Need to ensure all OS threads and their Tokio runtimes honor this promptly and cleanly, especially if `accept()` is somehow stuck (though `tokio::select!` should prevent that).
*   **Documentation**: more comments in the code, and maybe expand this `README` with usage examples once it's integrated into `lemon`.
*   **Collect and Join `thread_handles`?**: in `ZestService::listen`, we collect `thread_handles` but don't currently join them. For a library, it might be cleaner to let the OS clean them up when the main process exits, or if `lemon` needs to ensure `zest` threads are fully stopped *before* `lemon` itself exits, we might need a separate `ZestService::shutdown()` method that joins these handles.
