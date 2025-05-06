use std::net::SocketAddr;
use std::thread;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use anyhow::{Context, Result, bail};

/// Configuration for a single listener that zest will manage.
#[derive(Debug, Clone)]
pub struct ZestListenerConfig {
    pub listen_address: SocketAddr,
    pub listener_id: u64, // Opaque ID for lemon to map back to its config
    // pub protocol_type: ZestProtocol, // Future: TCP, UDP
}

/// Represents an accepted TCP connection from zest.
#[derive(Debug)]
pub struct AcceptedTcpConnection {
    pub stream: TcpStream,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub listener_id: u64,
}

/// Global settings for zest's behavior.
#[derive(Debug, Clone, Default)]
pub struct ZestGlobalSettings {
    pub force_single_listener_mode: bool,
    pub listener_threads_per_address: Option<usize>,
    pub tcp_listen_backlog: Option<u32>,
    // pub pin_listener_threads_to_cores: bool, // Future
}

pub struct ZestService;

impl ZestService {
    /// Creates and starts the Zest listening service.
    pub async fn listen(
        listener_configs: Vec<ZestListenerConfig>,
        global_settings: ZestGlobalSettings,
        global_shutdown_rx: watch::Receiver<()>, 
    ) -> Result<mpsc::Receiver<AcceptedTcpConnection>> {
        if listener_configs.is_empty() {
            bail!("No listener configurations were provided");
        }

        tracing::info!(
            num_configs = listener_configs.len(),
            settings = ?global_settings,
            "ZestService starting to listen"
        );

        let (connection_tx, connection_rx) = mpsc::channel(1024);
        let mut thread_handles = Vec::new();
        // for collecting setup status from each spawned OS thread
        let mut setup_status_receivers = Vec::new();

        for listener_config in &listener_configs { 
            let num_os_threads_for_listener = if global_settings.force_single_listener_mode {
                1
            } else {
                global_settings
                    .listener_threads_per_address
                    .unwrap_or_else(num_cpus::get)
                    .max(1) 
            };
            
            let use_reuseport_for_current_config = !global_settings.force_single_listener_mode && num_os_threads_for_listener > 1;

            tracing::debug!(
                listen_addr = %listener_config.listen_address,
                listener_id = listener_config.listener_id,
                requested_os_threads = num_os_threads_for_listener,
                computed_reuseport = use_reuseport_for_current_config,
                "Preparing OS threads for listener_config"
            );

            for i in 0..num_os_threads_for_listener {
                let lc = listener_config.clone();
                let settings_clone = global_settings.clone();
                let thread_conn_tx = connection_tx.clone();
                let mut thread_shutdown_rx = global_shutdown_rx.clone();
                let thread_name = format!(
                    "zest-acceptor-{}-{}-{}",
                    lc.listen_address.ip(),
                    lc.listen_address.port(),
                    i
                );
                
                // channel for this thread to report its setup status
                let (status_tx, status_rx) = oneshot::channel::<Result<()>>();
                setup_status_receivers.push(status_rx);

                let handle = thread::Builder::new()
                    .name(thread_name.clone())
                    .spawn(move || { // OS thread - note: not returning Result directly to spawn anymore
                        // create tokio runtime for this thread
                        let runtime_result = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .thread_name(format!("tokio-{}", thread_name))
                            .build();                       

                        let runtime = match runtime_result {
                            Ok(rt) => rt,
                            Err(e) => {
                                let err_msg = format!("Failed to start Tokio current-thread runtime for {}: {:?}", thread_name, e);
                                tracing::error!(err_msg);
                                let _ = status_tx.send(Err(anyhow::anyhow!(err_msg)));
                                return;
                            }
                        };
                        
                        // this block_on will run the async logic on the current OS thread's new tokio runtime
                        runtime.block_on(async move { 
                            let listener_result = create_tokio_listener(&lc, &settings_clone, use_reuseport_for_current_config).await;

                            let listener = match listener_result {
                                Ok(l) => {
                                    tracing::info!(thread_name = %thread_name, local_addr = ?l.local_addr().ok(), "Listener started successfully.");
                                    // send Ok status only after listener is confirmed
                                    if status_tx.send(Ok(())).is_err() {
                                        tracing::warn!(thread_name = %thread_name, "Failed to send Ok setup status, main thread may have given up.");
                                        return; 
                                    }
                                    l
                                }
                                Err(e) => {
                                    let err_msg = format!("Failed to create listener in thread {}: {:?}", thread_name, e);
                                    tracing::error!(err_msg);
                                    
                                    let _ = status_tx.send(Err(anyhow::anyhow!(err_msg)));
                                    return; 
                                }
                            };
                            
                            // --- Accept Loop --- 
                            loop {
                                tokio::select! {
                                    biased;
                                    _ = thread_shutdown_rx.changed() => {
                                        tracing::info!(thread_name = %thread_name, "Shutdown signal received. Exiting accept loop.");
                                        break;
                                    }
                                    accepted = listener.accept() => {
                                        match accepted {
                                            Ok((stream, remote_addr)) => {
                                                let local_addr = stream.local_addr().unwrap_or(lc.listen_address); 
                                                let accepted_conn = AcceptedTcpConnection {
                                                    stream,
                                                    local_addr,
                                                    remote_addr,
                                                    listener_id: lc.listener_id,
                                                };
                                                if thread_conn_tx.send(accepted_conn).await.is_err() {
                                                    tracing::warn!(thread_name = %thread_name, "Connection receiver dropped. Exiting accept loop.");
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(thread_name = %thread_name, error = ?e, "Error accepting connection.");
                                            }
                                        }
                                    }
                                }
                            }
                        }); 
                    })
                    .with_context(|| format!("Failed to spawn OS thread for {}", listener_config.listen_address))?;
                
                thread_handles.push(handle);
            }
        }

        // check setup statuses
        let mut successful_setups = 0;
        for status_rx in setup_status_receivers {
            match status_rx.await { 
                Ok(Ok(())) => successful_setups += 1,
                Ok(Err(e)) => tracing::error!("Listener thread setup failed: {}", e), 
                Err(_) => tracing::error!("Listener thread status sender was dropped before sending status (panic?)"),
            }
        }

        if successful_setups == 0 {
            // ensure main connection_tx is dropped if we bail, so receiver doesn't hang
            drop(connection_tx);
            bail!("No listener threads were successfully initialized.");
        }
        
        // drop the connection_tx that ZestService holds.
        // the mpsc channel will remain open as long as at least one spawned thread holds a clone of connection_tx
        // when all spawned threads exit and drop their clones, connection_rx.recv() will return None
        drop(connection_tx); 

        tracing::info!(successful_threads = successful_setups, total_attempted_os_threads = thread_handles.len(), "ZestService listen setup partially/fully complete.");
        Ok(connection_rx)
    }
}

async fn create_tokio_listener(
    config: &ZestListenerConfig,
    settings: &ZestGlobalSettings,
    use_reuseport_flag: bool,
) -> Result<TcpListener> {
    let addr = config.listen_address;
    let backlog = settings.tcp_listen_backlog.unwrap_or(1024) as i32; 

    if use_reuseport_flag {
        #[cfg(unix)]
        {
            use socket2::{Domain, Protocol, Socket, Type};
            let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
                .with_context(|| format!("Failed to create socket2 socket for {}", addr))?;
            
            socket.set_reuse_address(true)
                .with_context(|| format!("Failed to set SO_REUSEADDR for {}", addr))?;
            
            // SO_REUSEPORT allows multiple sockets to bind to the same address and port
            // the kernel then distributes incoming connections among them
            socket.set_reuse_port(true)
                .with_context(|| format!("Failed to set SO_REUSEPORT for {}", addr))?;
            
            // bind must happen before converting to std::net::TcpListener when using socket2 for setup
            socket.bind(&addr.into())
                .with_context(|| format!("socket2::Socket failed to bind to {} with SO_REUSEPORT", addr))?;
            
            socket.listen(backlog)
                .with_context(|| format!("socket2::Socket failed to listen on {}", addr))?;
            
            let std_listener = std::net::TcpListener::from(socket);
            // tokio TcpListener::from_std will handle setting non-blocking internally if needed
            std_listener.set_nonblocking(true)
                .with_context(|| format!("Failed to set non-blocking on std::net::TcpListener for {}", addr))?;
            
            TcpListener::from_std(std_listener)
                .with_context(|| format!("Failed to convert std::net::TcpListener to tokio::net::TcpListener for {}", addr))
        }
        #[cfg(not(unix))]
        {
            tracing::warn!(
                listen_addr = %addr,
                "SO_REUSEPORT is requested but not supported/implemented for this target. Each thread for this address will use a standard listener."
            );
            // we just bind normally
            TcpListener::bind(addr).await
                .with_context(|| format!("tokio::net::TcpListener failed to bind to {} (non-unix SO_REUSEPORT path)", addr))
        }
    } else {
        // single listener mode 
        TcpListener::bind(addr).await
            .with_context(|| format!("tokio::net::TcpListener failed to bind to {} (single listener mode)", addr))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_zest_service_init_no_configs() {
        let settings = ZestGlobalSettings::default();
        let (_tx, rx) = watch::channel(());
        let result = ZestService::listen(vec![], settings, rx).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("No listener configurations were provided"));
        }
    }

    fn test_listener_config(port: u16, id: u64) -> ZestListenerConfig {
        ZestListenerConfig {
            listen_address: SocketAddr::from(([127, 0, 0, 1], port)),
            listener_id: id,
        }
    }

    #[tokio::test]
    async fn test_zest_service_single_listener_success() {
        let port = portpicker::pick_unused_port().expect("No ports free");
        let configs = vec![test_listener_config(port, 1)]; 
        let settings = ZestGlobalSettings {
            force_single_listener_mode: true,
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        let listen_result = ZestService::listen(configs, settings, shutdown_rx).await;
        assert!(listen_result.is_ok(), "Expected Ok, got Err: {:?}", listen_result.err());
        
        if let Ok(mut _receiver) = listen_result { 
            tracing::info!("Test with single listener config returned Ok, receiver created.");
        } 
        let _ = shutdown_tx.send(()); 
        tokio::time::sleep(Duration::from_millis(50)).await; 
    }

    #[tokio::test]
    #[cfg(unix)] 
    async fn test_zest_service_reuseport_listener_success() {
        let port = portpicker::pick_unused_port().expect("No ports free");
        let configs = vec![test_listener_config(port, 1)]; 
        let settings = ZestGlobalSettings {
            force_single_listener_mode: false,
            listener_threads_per_address: Some(2),
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        let listen_result = ZestService::listen(configs, settings, shutdown_rx).await;
        assert!(listen_result.is_ok(), "Expected Ok for reuseport, got Err: {:?}", listen_result.err());
        if let Ok(_receiver) = listen_result {
            tracing::info!("Reuseport test returned Ok.");
        }
        let _ = shutdown_tx.send(());
        tokio::time::sleep(Duration::from_millis(50)).await; 
    }

    #[tokio::test]
    async fn test_zest_service_fail_to_spawn_any_threads_due_to_no_configs() {
        let settings = ZestGlobalSettings::default();
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let result = ZestService::listen(vec![], settings, shutdown_rx).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("No listener configurations were provided"));
        }
        let _ = shutdown_tx.send(());
    }
    
    #[tokio::test]
    async fn test_zest_service_fail_all_listener_setups(){
        let configs = vec![test_listener_config(80, 1)]; 
        let settings = ZestGlobalSettings { 
            force_single_listener_mode: false, 
            listener_threads_per_address: Some(1), 
            ..Default::default() 
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        // Initialize tracing for this test to see logs from threads
        // let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let result = ZestService::listen(configs, settings, shutdown_rx).await;
        assert!(result.is_err(), "Expected an error when all listener setups fail, got Ok. Result: {:?}", result.ok());
        if let Err(e) = result {
            tracing::info!("Got expected error for failed listener setup: {}", e);
            assert!(e.to_string().contains("No listener threads were successfully initialized"));
        }
        let _ = shutdown_tx.send(());
        tokio::time::sleep(Duration::from_millis(100)).await; 
    }
} 