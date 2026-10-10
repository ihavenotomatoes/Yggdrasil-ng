use std::fs::{File, OpenOptions};
use std::path::Path;
use ed25519_dalek::SigningKey;
use getopts::Options;
use time::macros::format_description;
use tracing_subscriber::{fmt, EnvFilter};

use yggdrasil::address::{addr_for_key, subnet_for_key};
use yggdrasil::admin::AdminSocket;
use yggdrasil::config::{expand_config_includes, Config};
use yggdrasil::core::Core;
use yggdrasil::ipv6rwc::ReadWriteCloser;

#[cfg(feature = "tun")]
use yggdrasil::tun::TunAdapter;

#[cfg(windows)]
mod service;

/// Tokio worker threads for the daemon.
///
/// tokio defaults to one worker per core, which is counter-productive here: the
/// data path is a chain of small per-packet tasks, so spreading it over every
/// core buys nothing but a cross-thread wakeup per hop. Measured with two peered
/// daemons at MTU 1400 on a 32-core box (see `benchmarks/datapath-throughput`):
/// 32 workers cost 23.7 us of CPU per packet for 1218 Mbit/s, while 3 workers
/// cost 18.9 us for 1300 Mbit/s -- more throughput for less CPU. Dropping to 1
/// worker is cheaper still (10.4 us/pkt) but caps throughput at ~910 Mbit/s.
const WORKER_THREADS: usize = 3;

/// Build the daemon's tokio runtime. Used by both console and service mode.
fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().min(WORKER_THREADS))
        .unwrap_or(1);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_runtime()?.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let opts = make_cli_options();

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("{}", opts.usage(&usage_string()));
            std::process::exit(1);
        }
    };

    if matches.opt_present("help") {
        println!("{}", opts.usage(&usage_string()));
        #[cfg(feature = "ctl")]
        print_ctl_commands();
        return Ok(());
    }

    if matches.opt_present("version") {
        println!("yggdrasil {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Resolve prefix/port early from binary/symlink/hardlink name suffix
    // so --address / --subnet and control-mode endpoint see the correct values.
    // Config mutation and the info message happen later (after logging is ready).
    if let Some((prefix, port)) = resolve_prefix_port() {
        yggdrasil::address::set_address_prefix(prefix);
        yggdrasil::multicast::set_multicast_port(port);
    }

    // If there are free (positional) arguments, treat as a control command
    #[cfg(feature = "ctl")]
    if !matches.free.is_empty() {
        let endpoint = matches.opt_str("endpoint")
            .unwrap_or_else(|| format!("tcp://localhost:{}", yggdrasil::multicast::multicast_port()));
        let json_output = matches.opt_present("json");
        let command = matches.free[0].clone();

        // Parse key=value arguments
        let mut arguments = serde_json::Map::new();
        for arg in &matches.free[1..] {
            if let Some((k, v)) = arg.split_once('=') {
                arguments.insert(k.to_string(), serde_json::Value::String(v.to_string()));
            }
        }

        return yggdrasil::ctl::run_ctl(&endpoint, json_output, &command, arguments).await;
    }

    // --service: run as Windows service
    #[cfg(windows)]
    if matches.opt_present("service") {
        return service::run_as_service();
    }

    let config_path = resolve_config_path(&matches);
    let autoconf = matches.opt_present("autoconf");
    let address = matches.opt_present("address");
    let subnet = matches.opt_present("subnet");
    let loglevel = matches.opt_str("loglevel").unwrap_or_else(|| "info".to_string());
    let logto = matches.opt_str("logto");

    // --genconf [FILE]: generate config, save to file or print to stdout
    if matches.opt_present("base") && !matches.opt_present("genconf") {
        eprintln!("Error: --base can only be used together with --genconf");
        std::process::exit(1);
    }
    if matches.opt_present("base")
        && matches.opt_str("base").unwrap_or_default().is_empty()
    {
        eprintln!("Error: --base requires a FILE path");
        std::process::exit(1);
    }
    if matches.opt_present("genconf") {
        if let Some(path) = matches.opt_str("genconf") {
            let path = expand_genconf_path(&path);
            let path_ref = Path::new(&path);
            if matches.opt_present("no-replace") && path_ref.exists() {
                eprintln!("Configuration file {} already exists, skipping", display_abs_path(path_ref));
                return Ok(());
            }
            if let Some(parent) = config_parent_dir(path_ref) {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)?;
                    eprintln!("Created folder {}", display_abs_path(parent));
                }
            }
            let text = generate_config_text_maybe_from_base(matches.opt_str("base").as_deref())?;
            {
                use std::io::Write;
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                opts.open(path_ref)?.write_all(text.as_bytes())?;
            }
            eprintln!("Configuration saved to {}", display_abs_path(path_ref));
        } else {
            print!("{}", generate_config_text_maybe_from_base(matches.opt_str("base").as_deref())?);
        }
        return Ok(());
    }

    // --normalize [FILE]: read existing config (file or stdin), splice in
    // any new fields with their template comments, print to stdout.
    if matches.opt_present("normalize") {
        use std::io::Read;
        let mut buf = String::new();
        match matches.opt_str("normalize") {
            Some(path) if path != "-" => {
                File::open(&path)?.read_to_string(&mut buf)?;
            }
            _ => {
                std::io::stdin().read_to_string(&mut buf)?;
            }
        }
        match Config::normalize_config_text(&buf) {
            Ok(out) => {
                print!("{}", out);
                if !out.ends_with('\n') {
                    println!();
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Initialize logging
    init_logging(&loglevel, logto.as_deref());

    if address || subnet {
        // Load config
        let config = if autoconf {
            Config::default()
        } else {
            load_config_file(&config_path)?
        };

        // Parse or generate signing key
        // Priority: config file > YGGDRASIL_PRIVATE_KEY env var > ephemeral
        let signing_key = if !config.private_key.is_empty() {
            config
                .signing_key()
                .map_err(|e| format!("invalid private key: {}", e))?
        } else if let Ok(env_key) = std::env::var("YGGDRASIL_PRIVATE_KEY") {
            tracing::info!("Using private key from YGGDRASIL_PRIVATE_KEY environment variable");
            let bytes = hex::decode(&env_key)
                .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY hex: {}", e))?;
            let key_bytes: [u8; 64] = bytes.try_into()
                .map_err(|v: Vec<u8>| format!("YGGDRASIL_PRIVATE_KEY should be 64 bytes, got {}", v.len()))?;
            SigningKey::from_keypair_bytes(&key_bytes)
                .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY: {}", e))?
        } else {
            tracing::warn!("No private key configured, generating ephemeral key");
            SigningKey::generate(&mut rand::rngs::OsRng)
        };

        let public_key = signing_key.verifying_key().to_bytes();

        // --address: print address and exit
        if address {
            let addr = addr_for_key(&public_key);
            println!("{}", addr);
            return Ok(());
        }

        // --subnet: print subnet and exit
        if subnet {
            let subnet = subnet_for_key(&public_key);
            println!("{}", subnet);
            return Ok(());
        }
    }

    // Shutdown on Ctrl+C, or on SIGTERM from a service manager.
    let (watch_tx, watch_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
            let mut sigint =
                signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
            tokio::select! {
                _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
                _ = sigint.recv()  => tracing::info!("Received SIGINT"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = watch_tx.send(true);
    });

    run_node(watch_rx).await
}

/// Run the Yggdrasil node, blocking until the shutdown signal fires.
/// Called from both console mode (Ctrl+C) and Windows service mode (SCM stop).
async fn run_node(
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    // When called from service mode, logging + config aren't set up yet.
    // Re-read CLI args to get config path / autoconf / loglevel.
    let args: Vec<String> = std::env::args().collect();
    let opts = make_cli_options();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => opts.parse(Vec::<String>::new()).unwrap(),
    };

    let config_path = resolve_config_path(&matches);
    let autoconf = matches.opt_present("autoconf");
    let loglevel = matches.opt_str("loglevel").unwrap_or_else(|| "info".to_string());
    let logto = matches.opt_str("logto");

    // Initialize logging (idempotent — if already initialized in console mode, this is a no-op)
    init_logging(&loglevel, logto.as_deref());

    // Load config
    let mut config = if autoconf {
        Config::default()
    } else {
        load_config_file(&config_path)?
    };

    if let Some((prefix, port)) = resolve_prefix_port() {
        apply_prefix_port(prefix, port, &mut config);
    }

    if let Some(val) = matches.opt_str("peers") {
        let extra = parse_peers_list(&val);
        if !extra.is_empty() {
            tracing::info!(
                "Adding {} peer(s) from --peers: {:?}",
                extra.len(),
                extra
            );
            config.peers.extend(extra);
        }
    }

    // Parse or generate signing key
    let signing_key = if !config.private_key.is_empty() {
        config
            .signing_key()
            .map_err(|e| format!("invalid private key: {}", e))?
    } else if let Ok(env_key) = std::env::var("YGGDRASIL_PRIVATE_KEY") {
        tracing::info!("Using private key from YGGDRASIL_PRIVATE_KEY environment variable");
        let bytes = hex::decode(&env_key)
            .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY hex: {}", e))?;
        let key_bytes: [u8; 64] = bytes.try_into()
            .map_err(|v: Vec<u8>| format!("YGGDRASIL_PRIVATE_KEY should be 64 bytes, got {}", v.len()))?;
        SigningKey::from_keypair_bytes(&key_bytes)
            .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY: {}", e))?
    } else {
        tracing::warn!("No private key configured, generating ephemeral key");
        SigningKey::generate(&mut rand::rngs::OsRng)
    };

    // Create core
    let core = Core::new(signing_key, config.clone());
    tracing::info!("Your IPv6 address is {}", core.address());
    tracing::info!("Your IPv6 subnet is {}", core.subnet());
    tracing::info!("Your public key is {}", hex::encode(core.public_key()));
    tracing::info!("Salsa20 backend: {}", salsa20::active_backend());

    // Initialize links with core reference
    core.init_links().await;

    // Start listeners and connect to peers
    core.start().await;

    // Construct firewall (if enabled). Default-off; existing setups are untouched.
    let firewall = if config.firewall.enable {
        match yggdrasil::firewall::Firewall::new(&config.firewall) {
            Ok(fw) => {
                let fw = std::sync::Arc::new(fw);
                fw.spawn_gc();
                tracing::info!(
                    "Firewall enabled: {} TCP open, {} UDP open, {} bypass subnets, icmp_echo={}",
                    config.firewall.open_tcp.len(),
                    config.firewall.open_udp.len(),
                    config.firewall.open_all_for.len(),
                    config.firewall.allow_icmp_echo
                );
                Some(fw)
            }
            Err(e) => {
                tracing::error!("Firewall configuration error: {}", e);
                return Err(e.into());
            }
        }
    } else {
        None
    };

    // Create IPv6 RWC bridge
    let mtu = core.mtu();
    let rwc = ReadWriteCloser::new(
        core.clone(),
        mtu,
        #[cfg(feature = "ckr")]
        Some(&config.tunnel_routing),
        firewall,
    );

    // Wire up path_notify: when ironwood discovers a new path, update the key store
    core.set_path_notify(rwc.clone());

    // Seed the key store with the keys of directly-connected peers. We authenticated
    // those keys during the link handshake, so their address/subnet mapping is already
    // derivable locally -- no reason to buffer the first packet and wait for a lookup
    // to tell us what we know. Combined with the router's direct-peer shortcut this
    // takes the first packet to a direct peer from three round trips down to two
    // (the remaining one being the session Init/Ack).
    //
    // Re-run on a timer rather than hooking link setup: it picks up peers that connect
    // later, survives reconnects, and refreshes `last_seen` so entries can't age out
    // while the peer is up. `update_key` returns early for entries that are still
    // fresh, so a tick over an unchanged peer set is a couple of hashmap lookups.
    let seed_core = core.clone();
    let seed_rwc = rwc.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            ticker.tick().await;
            for key in seed_core.get_peer_keys().await {
                seed_rwc.update_key(key).await;
            }
        }
    });

    // Create TUN adapter
    #[cfg(feature = "tun")]
    let mut tun = if config.if_name != "none" {
        let addr_str = core.address().to_string();
        let subnet_str = core.subnet().to_string();
        let tun_mtu = config.if_mtu.min(mtu).min(65535) as u16;

        match TunAdapter::new(
            &config.if_name,
            rwc.clone(),
            &addr_str,
            &subnet_str,
            tun_mtu,
            #[cfg(windows)]
            &config.if_dns_servers,
            #[cfg(target_os = "linux")]
            config.if_gso,
            #[cfg(feature = "ckr")]
            Some(&config.tunnel_routing),
            #[cfg(feature = "ckr")]
            core.public_key(),
        ).await {
            Ok(tun) => {
                tracing::info!("TUN adapter started");
                core.set_tun_info(tun.name(), tun.mtu() as u64);
                Some(tun)
            }
            Err(e) => {
                // A TUN was requested (if_name != "none") but could not be
                // created. Fail loudly rather than continuing in a degraded,
                // TUN-less state: under systemd Type=notify this surfaces as a
                // failed start (then Restart=always retries) instead of a
                // silently broken node that still reports "ready".
                tracing::error!("Failed to create TUN adapter: {}", e);
                return Err(e.into());
            }
        }
    } else {
        tracing::info!("TUN adapter disabled");
        None
    };

    // Start admin socket
    let admin = match AdminSocket::new(&config.admin_listen, core.clone()).await {
        Ok(admin) => Some(admin),
        Err(e) => {
            tracing::warn!("Failed to start admin socket: {}", e);
            None
        }
    };

    // Start multicast peer discovery
    if let Err(e) = core.start_multicast().await {
        tracing::warn!("Multicast peer discovery disabled: {}", e);
    }

    // Download any HTTP/HTTPS route lists declared in tunnel_routing.remote_subnets.
    // Must happen immediately after multicast peer discovery started and must
    // complete before we proceed to CKR initialization / route installation.
    // Passes shutdown receiver so Ctrl+C aborts the blocking downloads/waits promptly.
    #[cfg(feature = "ckr-advanced")]
    yggdrasil::ckr::download_route_lists(&config.tunnel_routing, &core, &shutdown_rx);

    // Prepare peer IP exclusions from config.peers *after* Yggdrasil network is
    // running (core.start() but *before* init_crypto_key() and install_routes(). 
    // This guarantees that tokio::net::lookup_host can succeed for domains 
    // (DNS often lives in Yggdrasil) and that the resulting "!IP" exclusions 
    // are present in effective_entries for all remote_subnets entries.
    #[cfg(all(feature = "ckr", not(target_os = "android")))]
    yggdrasil::ckr::prepare_peer_exclusions(&config.tunnel_routing, &core, &config.peers, &shutdown_rx);

    // Visible to both install_routes and the later remove_routes. None keeps the main table.
    #[cfg(target_os = "linux")]
    let route_table = match config.ip_rule.effective() {
        Some((pref, lookup)) => {
            if let Err(e) = ensure_linux_ip_rule(pref, lookup) {
                tracing::error!("Failed to ensure ip rule pref {} lookup {}: {}", pref, lookup, e);
            }
            Some(lookup)
        }
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    let route_table = None;

    // JoinHandle must outlive the startup block so shutdown can stop the retry loop.
    #[cfg(target_os = "linux")]
    let mut local_subnet_route_task: Option<tokio::task::JoinHandle<()>> = None;

    // If Ctrl+C arrived during download / peer-exclusion prep, skip the remaining
    // CKR init / IP assignment / route install so shutdown can proceed immediately.
    if !*shutdown_rx.borrow() {
        // Initialize CKR routing table (CryptoKey) after multicast has started.
        // This moves the "CKR: ignoring ..." and "Active CKR routes" logs
        // to the position before TUN IP assignment.
        #[cfg(feature = "ckr")]
        rwc.init_crypto_key(&config.tunnel_routing, core.public_key());

        // Assign additional CKR IP addresses (from ip_addresses / legacy ipv4_address)
        // to the already running TUN interface. This is done after multicast peer
        // discovery so the "CKR: assigning ..." logs appear in the required order
        // (between "Multicast peer discovery started" and system route installation).
        // We call the new method on the TunAdapter that was created earlier.
        #[cfg(feature = "ckr")]
        if config.if_name != "none" {
            if let Some(ref tun_adapter) = tun {
                if config.tunnel_routing.enable {
                    if let Err(e) = tun_adapter.assign_ckr_ip_addresses(&config.tunnel_routing) {
                        tracing::error!("Failed to assign CKR IP addresses to TUN: {}", e);
                    }
                }
            }
        }

        // Install CKR system routes late — after multicast peer discovery has started.
        // This moves "Installed route" logs to the very end of startup (between
        // "Multicast peer discovery started" and "Yggdrasil NG started").
        // Routes are now added only when the Yggdrasil network is fully operational.
        // The early installation block was removed from TunAdapter::new.
        // We reuse the exact same tun_name computation and error handling pattern
        // that already exists in the shutdown/remove_routes block below.
        // Move the kernel overlay route (200::/7, or the configured prefix) into
        // the same table as CKR routes. Independent of tunnel_routing.enable.
        #[cfg(all(target_os = "linux", feature = "tun"))]
        if let Some(table) = route_table {
            if let Some(adapter) = tun.as_ref() {
                if let Err(e) = install_overlay_route(adapter.name(), table) {
                    tracing::error!("Failed to install overlay route: {}", e);
                }
            }
        }
        #[cfg(feature = "ckr")]
        if config.tunnel_routing.enable && config.tunnel_routing.install_system_routes && config.if_name != "none" {
            // Prefer the real interface name reported by TunAdapter
            // (utunN on macOS, tunN on BSD when if_name was "auto").
            let tun_name = match &tun {
                Some(t) => t.name(),
                None => {
                    // Fallback (should not happen when if_name != "none")
                    if config.if_name == "auto" {
                        if cfg!(windows) {
                            "Yggdrasil"
                        } else if cfg!(any(
                            target_os = "macos",
                            target_os = "freebsd",
                            target_os = "netbsd",
                            target_os = "openbsd",
                        )) {
                            // Last-resort label only; the live adapter name is preferred.
                            if cfg!(any(target_os = "freebsd")) {
                                "ygg0"
                            } else {
                                "tun0"
                            }
                        } else {
                            "ygg0"
                        }
                    } else {
                        config.if_name.as_str()
                    }
                }
            };
            if let Err(e) = yggdrasil::ckr::install_routes(
                &config.tunnel_routing,
                tun_name,
                core.public_key(),
                route_table,
            ) {
                tracing::error!("Failed to install CKR routes: {}", e);
            }
        }

        // Node /64 via the LAN interface that holds <subnet>::1, into the same
        // table as the overlay route. Independent of tunnel_routing.enable.
        #[cfg(target_os = "linux")]
        if let Some(table) = route_table {
            let subnet = subnet_for_key(core.public_key());
            let mut retry_shutdown = shutdown_rx.clone();
            local_subnet_route_task = Some(tokio::spawn(async move {
                install_local_subnet_route_with_retries(subnet, table, &mut retry_shutdown).await;
            }));
        }

        // Wait for shutdown signal
        tracing::info!("Yggdrasil NG started");
    }

    // Tell systemd we're ready (Type=notify). By this point the TUN interface
    // (if any) has been created and the admin socket/multicast started, so
    // ExecStartPost hooks that touch the interface can rely on it existing.
    // This is a no-op when not running under systemd (NOTIFY_SOCKET unset).
    #[cfg(all(feature = "systemd", target_os = "linux"))]
    {
        if let Err(e) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
            tracing::warn!("Failed to notify systemd of readiness: {}", e);
        }
    }

    shutdown_rx.changed().await.ok();
    tracing::info!("Shutting down...");

    #[cfg(target_os = "linux")]
    if let Some(task) = local_subnet_route_task.take() {
        task.abort();
        let _ = task.await;
    }
    #[cfg(target_os = "linux")]
    if let Some(table) = route_table {
        let subnet = subnet_for_key(core.public_key());
        remove_local_subnet_route(&subnet.to_string(), table);
    }

    // Cleanup
    // Remove CKR routes before TUN is destroyed (critical on Windows where
    // routes don't auto-dissolve when the interface goes away).
    #[cfg(all(target_os = "linux", feature = "tun"))]
    if let Some(table) = route_table {
        if let Some(adapter) = tun.as_ref() {
            remove_overlay_route(adapter.name(), table);
        }
    }
    #[cfg(feature = "ckr")]
    if config.tunnel_routing.enable && config.if_name != "none" {
        // Prefer the real interface name reported by TunAdapter
        // (on macOS this is the kernel-assigned utunN).
        let tun_name = match &tun {
            Some(t) => t.name(),
            None => {
                // Fallback (should not happen when if_name != "none")
                if config.if_name == "auto" {
                    if cfg!(windows) {
                        "Yggdrasil"
                    } else if cfg!(any(
                        target_os = "macos",
                        target_os = "freebsd",
                        target_os = "netbsd",
                        target_os = "openbsd",
                    )) {
                        // Last-resort label only; the live adapter name is preferred.
                        "tun0"
                    } else {
                        "ygg0"
                    }
                } else {
                    config.if_name.as_str()
                }
            }
        };
        yggdrasil::ckr::remove_routes(
            &config.tunnel_routing,
            tun_name,
            core.public_key(),
            route_table,
        );
    }

    // Tear down TUN explicitly so the OS interface is removed before this
    // function returns. Dropping TunAdapter alone is not enough: its tokio
    // tasks each hold an Arc<AsyncDevice>, and dropping a JoinHandle does
    // not abort the task — it only detaches it. Without an explicit close
    // we'd rely on the runtime drop to abort the tasks, which is too late
    // in Windows service mode (the SCM may kill the process after we report
    // Stopped, leaving an orphaned Wintun adapter).
    #[cfg(feature = "tun")]
    if let Some(t) = tun.take() {
        t.close().await;
    }

    core.close_multicast().await;
    if let Some(admin) = &admin {
        admin.close();
    }
    core.close().await.ok();

    tracing::info!("Goodbye!");
    Ok(())
}

fn init_logging(loglevel: &str, logto: Option<&str>) {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = EnvFilter::try_new(loglevel)
            .unwrap_or_else(|_| EnvFilter::new("info"));
        let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
        let timer = fmt::time::LocalTime::new(format);

        // When running under systemd, the journal already provides timestamps.
        let under_systemd = std::env::var_os("JOURNAL_STREAM").is_some();

        if let Some(path) = logto {
            // Log files always get timestamps
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to open log file {}: {}", path, e);
                    std::process::exit(1);
                });
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_timer(timer)
                .with_writer(file)
                .init();
        } else if under_systemd {
            // Under systemd: skip timestamps, journal adds them
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .without_time()
                .init();
        } else {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_timer(timer)
                .init();
        }
    });
}

/// Expand `%VAR%` on Windows (e.g. `%ALLUSERSPROFILE%`, `%ProgramData%`).
/// Unknown names and `%%` are left unchanged. On other OS the path is unchanged.
fn expand_genconf_path(path: &str) -> String {
    #[cfg(windows)]
    {
        let mut out = String::with_capacity(path.len());
        let mut rest = path;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            if let Some(end) = after.find('%') {
                let name = &after[..end];
                if !name.is_empty() {
                    if let Ok(val) = std::env::var(name) {
                        out.push_str(&val);
                        rest = &after[end + 1..];
                        continue;
                    }
                }
            }
            out.push('%');
            rest = after;
        }
        out.push_str(rest);
        out
    }
    #[cfg(not(windows))]
    {
        path.to_string()
    }
}

/// Rewrite the historic default admin_listen URI inside generated
/// config text so the commented template line uses the port taken
/// from the binary/symlink/hardlink name.
///
/// The template ships with `tcp://localhost:9001` (commented).
/// Only that exact default URI is replaced; a custom URI would
/// not appear in freshly generated text.
fn rewrite_admin_listen_in_genconf_text(text: &str, port: u16) -> String {
    let from = format!("tcp://localhost:{}", DEFAULT_ADMIN_PORT);
    let to = format!("tcp://localhost:{}", port);
    text.replace(&from, &to)
}

/// Build genconf text. If `base_path` is set, reuse `private_key` from that
/// TOML file (after splicing its `include` lines); otherwise mint a new
/// keypair (existing generate_config_text()). Other fields from the base
/// file and from its includes are not copied into the new template.
fn generate_config_text_maybe_from_base(
    base_path: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let text = match base_path {
        None => Config::generate_config_text(),
        Some(path) => {
            let path = expand_genconf_path(path);
            match File::open(&path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(format!("base configuration file not found: {}", path).into());
                }
                Err(e) => return Err(e.into()),
            }
            let (text, warnings) = expand_config_includes(Path::new(&path));
            for warning in warnings {
                eprintln!("Warning: {}", warning);
            }
            let key = Config::private_key_from_toml(&text)
                .map_err(|e| format!("invalid --base file {}: {}", path, e))?;
            Config::generate_config_text_from_private_key(&key)
        }
    };
    let port = resolve_prefix_port()
        .map(|(_, port)| port)
        .unwrap_or(DEFAULT_ADMIN_PORT);
    Ok(rewrite_admin_listen_in_genconf_text(&text, port))
}

/// Parent directory of a config file path, if one should be considered
/// for creation. `yggdrasil.toml` and `./yggdrasil.toml` have no folder.
fn config_parent_dir(path: &Path) -> Option<&Path> {
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() || parent == Path::new(".") {
        None
    } else {
        Some(parent)
    }
}

/// Absolute path for messages. Does not call canonicalize() (avoids `\\?\` on Windows).
fn display_abs_path(path: &Path) -> String {
    if path.is_absolute() {
        path.display().to_string()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path).display().to_string()
    } else {
        path.display().to_string()
    }
}

/// CLI flags for the daemon. Shared by argument parsing and by the
/// "config file not found" error so both print the same Usage text.
fn make_cli_options() -> Options {
    let mut opts = Options::new();
    opts.optflagopt("g", "genconf", "Generate a new configuration (optionally save to FILE)", "FILE");
    opts.optflagopt("", "normalize", "Normalize a config: read from FILE (or stdin if absent), add any missing fields with defaults while preserving user values and comments, and print to stdout", "FILE");
    opts.optopt("c", "config", "Config file path (default: yggdrasil.toml, then system path)", "FILE");
    opts.optflag("", "autoconf", "Run without a configuration file (use ephemeral keys)");
    opts.optflag("a", "address", "Print the IPv6 address for the given config and exit");
    opts.optflag("s", "subnet", "Print the IPv6 subnet for the given config and exit");
    opts.optopt("l", "loglevel", "Log level: error, warn, info, debug, trace (default: info)", "LEVEL");
    opts.optflag("n", "no-replace", "With --genconf FILE, skip if the file already exists");
    opts.optopt("b", "base", "With --genconf, copy private_key from this existing config file instead of generating a new key", "FILE");
    opts.optopt("", "logto", "Log to a file instead of stderr", "FILE");
    #[cfg(feature = "ctl")]
    opts.optopt("e", "endpoint", "Admin socket address (default: tcp://localhost:9001)", "URI");
    #[cfg(feature = "ctl")]
    opts.optflag("j", "json", "Output control command results as raw JSON");
    #[cfg(windows)]
    opts.optflag("", "service", "Run as a Windows service (launched by the Service Control Manager)");
    opts.optopt("p", "peers", "Comma-separated list of additional peer URIs to connect to (appended to config peers)", "PEERS");
    opts.optflag("h", "help", "Print this help");
    opts.optflag("v", "version", "Print version");
    opts
}

fn usage_string() -> String {
    #[cfg(feature = "ctl")]
    return "Usage: yggdrasil [options] [command [key=value ...]]".to_string();
    #[cfg(not(feature = "ctl"))]
    return "Usage: yggdrasil [options]".to_string();
}

/// Parse a comma-separated peer list.
/// Supports optional single/double quotes around individual peers
/// or around the whole list.
/// Empty entries after splitting are ignored.
fn parse_peers_list(s: &str) -> Vec<String> {
    let mut s = s.trim();

    // Strip outer quotes if the whole value is quoted
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        let first = bytes[0];
        let last = bytes[s.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            s = &s[1..s.len() - 1];
        }
    }

    s.split(',')
        .filter_map(|part| {
            let mut p = part.trim();
            if p.is_empty() {
                return None;
            }
            // Strip optional quotes around a single peer
            if p.len() >= 2 {
                let bytes = p.as_bytes();
                let first = bytes[0];
                let last = bytes[p.len() - 1];
                if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
                    p = &p[1..p.len() - 1];
                }
            }
            let p = p.trim();
            if p.is_empty() {
                None
            } else {
                Some(p.to_string())
            }
        })
        .collect()
}

/// Hex offset added to prefix/2 when the name carries a prefix but no port.
/// `00` → 0x2328 = 9000, `02` → 0x2329 = 9001, `fc` → 0x23A6 = 9126.
const DERIVED_PORT_OFFSET: u16 = 0x2328;

/// Admin/multicast port derived from a `*00::/7` prefix when the filename
/// suffix has no explicit port (`ygg_02`, `yggdrasil_fc`).
fn port_from_prefix(prefix: u8) -> u16 {
    (prefix as u16 / 2) + DERIVED_PORT_OFFSET
}

/// Parse a prefix-port value according to the required format.
/// Used for the suffix after the last '_' in the binary/symlink/hardlink name.
///
/// Accepted forms:
/// - prefix + port: "029001", "02-9001", "02.9001", "02:9001"
/// - prefix only:   "02", "fc"  (port = prefix/2 + 0x2328)
///
/// Returns (prefix_u8, port_u16) on success, None on failure.
fn parse_prefix_port(s: &str) -> Option<(u8, u16)> {
    // Manual implementation of the given regex (no extra dependency).
    if s.len() < 2 {
        return None;
    }
    let bytes = s.as_bytes();
    // First two characters must be a valid prefix from the allowed set
    let p0 = bytes[0] as char;
    let p1 = bytes[1] as char;
    let valid_prefix = matches!(
        (p0, p1),
        ('0'..='9' | 'a'..='e' | 'A'..='E', '0' | '2' | '4' | '6' | '8' | 'a' | 'c' | 'e' | 'A' | 'C' | 'E')
            | ('f' | 'F', '0' | '2' | '4' | '6' | '8' | 'a' | 'c' | 'A' | 'C')
    );
    if !valid_prefix {
        return None;
    }
    let prefix = u8::from_str_radix(&s[..2], 16).ok()?;

    // Optional separator: any char that is not space and not hex digit
    let rest = &s[2..];
    let numeric_start = if rest.is_empty() {
        // Suffix is only the prefix (`ygg_02`, `yggdrasil_fc`).
        return Some((prefix, port_from_prefix(prefix)));
    } else if rest.as_bytes()[0].is_ascii_hexdigit() {
        0
    } else if rest.as_bytes()[0].is_ascii() && rest.as_bytes()[0] != b' ' {
        1
    } else {
        return None;
    };
    let num_str: String = rest[numeric_start..]
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if num_str.is_empty() {
        return None;
    }
    let port: u16 = num_str.parse().ok()?;
    if !(1024..=65535).contains(&port) {
        return None;
    }
    Some((prefix, port))
}

const DEFAULT_ADMIN_PORT: u16 = 9001;

/// Rewrite a default-style TCP admin URI so its port matches the prefix-port
/// taken from the binary name. Only loopback hosts with the historic port
/// 9001 are treated as "still default". The host is preserved.
///
/// Recognized: tcp://localhost:9001, tcp://127.0.0.1:9001, tcp://[::1]:9001.
fn rewrite_default_admin_listen(listen: &str, port: u16) -> Option<String> {
    let rest = listen.strip_prefix("tcp://")?;
    let (host, listen_port) = if let Some(inner) = rest.strip_prefix('[') {
        let (host_inner, after) = inner.split_once(']')?;
        let p = after.strip_prefix(':')?.parse::<u16>().ok()?;
        (format!("[{}]", host_inner), p)
    } else {
        let (host, pstr) = rest.rsplit_once(':')?;
        (host.to_string(), pstr.parse::<u16>().ok()?)
    };
    if listen_port != DEFAULT_ADMIN_PORT {
        return None;
    }
    match host.as_str() {
        "localhost" | "127.0.0.1" | "[::1]" => {
            Some(format!("tcp://{}:{}", host, port))
        }
        _ => None,
    }
}

fn apply_prefix_port(prefix: u8, port: u16, config: &mut Config) {
    yggdrasil::address::set_address_prefix(prefix);
    yggdrasil::multicast::set_multicast_port(port);

    tracing::info!(
        "Using address prefix 0x{:02x} and port {}",
        prefix, port
    );

    // Override admin_listen only when it still looks like the historic
    // default (loopback + port 9001). Preserve the configured host.
    if let Some(rewritten) = rewrite_default_admin_listen(&config.admin_listen, port) {
        config.admin_listen = rewritten;
    }

    // Override if_name only when it is the default "auto"
    // (absent/commented in config). macOS and BSD stay "auto" so the
    // TUN backend can allocate utunN / tunN. FreeBSD then rename
    // that tunN to the Linux-like alias inside tun.rs.
    if config.if_name == "auto" {
        let suffix = format!("{:02x}{}", prefix, port);
        if cfg!(windows) {
            config.if_name = format!("Yggdrasil{}", suffix);
        } else if cfg!(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
        )) {
            // Keep "auto" — backend assigns utunN (macOS) or tunN (BSD).
            // FreeBSD rename tunN after creation (see tun.rs), for 
            // "auto" and for an explicit if_name alias.
        } else {
            // Linux: strip the trailing "0" from "ygg0"
            config.if_name = format!("ygg{}", suffix);
        }
    }
}

/// Return the basename of the program as invoked (argv[0]).
/// Works for renamed binaries, symlinks and hardlinks.
fn program_basename() -> String {
    std::env::args()
        .next()
        .map(|a| {
            Path::new(&a)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&a)
                .to_string()
        })
        .unwrap_or_default()
}

/// Strip a trailing Windows ".exe" (any ASCII case). Any other suffix,
/// including a dotted prefix-port like "02.9001", is kept so two
/// networks do not collapse onto one config file.
#[cfg(windows)]
fn strip_exe_suffix(name: &str) -> &str {
    let bytes = name.as_bytes();
    if bytes.len() >= 4 && bytes[bytes.len() - 4..].eq_ignore_ascii_case(b".exe") {
        // ".exe" is ASCII, so len-4 is always a char boundary here.
        &name[..name.len() - 4]
    } else {
        name
    }
}

/// On non-Windows the binary name has no `.exe`; return it unchanged.
#[cfg(not(windows))]
fn strip_exe_suffix(name: &str) -> &str {
    name
}

/// Config filename derived from argv[0] when `--config` is absent.
fn config_filename_from_program_name(name: &str) -> String {
    if prefix_port_from_name(name).is_some() {
        format!("{}.toml", strip_exe_suffix(name))
    } else {
        "yggdrasil.toml".to_string()
    }
}

/// Extract prefix and port from the binary/symlink/hardlink name.
/// The last '_' in the name is the marker; everything after it is parsed
/// with parse_prefix_port (e.g. "029001", "02-9001", "02.9001", "02").
/// A trailing Windows ".exe" is stripped first so "ygg_02.exe" is "ygg_02".
fn prefix_port_from_name(name: &str) -> Option<(u8, u16)> {
    let name = strip_exe_suffix(name);
    let idx = name.rfind('_')?;
    let suffix = &name[idx + 1..];
    parse_prefix_port(suffix)
}

/// Compile-time system config directory on Linux and Termux.
/// `YGGDRASIL_CONFIG_DIR` is read when the binary is built. Unset or empty
/// keeps the historic Linux default. Android keeps "no system directory"
/// unless the variable is set. A trailing slash is stripped.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn compile_time_config_dir() -> Option<&'static str> {
    match option_env!("YGGDRASIL_CONFIG_DIR") {
        Some(dir) if !dir.is_empty() => Some(dir.trim_end_matches('/')),
        _ => {
            #[cfg(target_os = "linux")]
            {
                Some("/etc/yggdrasil")
            }
            #[cfg(target_os = "android")]
            {
                None
            }
        }
    }
}

/// System default location for `filename` (the second of the two default
/// paths). Used both to look the file up and to name it in the "not found"
/// error when neither default exists.
///
/// On Windows this returns the `%ALLUSERSPROFILE%` form rather than the
/// resolved ProgramData directory: that is what the error message should
/// show. The actual existence check still uses `windows_program_data_dir()`.
fn system_config_path(filename: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        format!("{}/{}", compile_time_config_dir().unwrap(), filename)
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    {
        format!("/etc/yggdrasil/{}", filename)
    }
    #[cfg(windows)]
    {
        format!("%ALLUSERSPROFILE%\\Yggdrasil-ng\\{}", filename)
    }
    #[cfg(target_os = "android")]
    {
        match compile_time_config_dir() {
            Some(dir) => format!("{}/{}", dir, filename),
            None => filename.to_string(),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        filename.to_string()
    }
}

/// Open and parse a TOML config file.
///
/// `NotFound` is rewritten so the user sees the path that was looked up
/// (the path they passed with `-c`/`--config`, or the system default when
/// no path was given). Other I/O and TOML errors are left unchanged.
fn load_config_file(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let open_path = expand_genconf_path(path);
    match File::open(&open_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "Error: Can't find the configuration file. Create a configuration file with:\n    {} --genconf={}\n\n{}",
                program_basename(),
                path,
                make_cli_options().usage(&usage_string())
            );
            // Short Err for SCM Stopped / main() Termination (Debug escapes newlines).
            return Err(format!("configuration file not found: {}", path).into());
        }
        Err(e) => return Err(e.into()),
    };
    let (text, warnings) = expand_config_includes(Path::new(&open_path));
    for warning in warnings {
        tracing::warn!("{}", warning);
    }
    Ok(toml::from_str::<Config>(&text)?)
}

/// Resolve the configuration file path.
///
/// When `--config` / `-c` is not given:
/// 1. Determine the config filename:
///    - If the binary/symlink/hardlink name contains a recognised prefix+port
///      suffix (via `prefix_port_from_name`), use `<name>.toml`, stripping only
///      a trailing `.exe` (e.g. `ygg_029001.exe` → `ygg_029001.toml`,
///      `yggdrasil_02.9001` → `yggdrasil_02.9001.toml`).
///    - Otherwise fall back to the historic default `yggdrasil.toml`.
/// 2. Try that filename in the current working directory.
/// 3. If absent, try the OS-specific system directory with the same filename:
///    - Linux: `$YGGDRASIL_CONFIG_DIR/<filename>` if that variable was set at
///      build time, otherwise `/etc/yggdrasil/<filename>`
///    - Android/Termux: `$YGGDRASIL_CONFIG_DIR/<filename>` only when that
///      variable was set at build time; otherwise the bare filename
///    - Other Unix (BSD, macOS, …): `/etc/yggdrasil/<filename>`
///    - Windows: `<ProgramData>\Yggdrasil-ng\<filename>`, where ProgramData is
///      the `ProgramData` environment variable, then `ALLUSERSPROFILE`, then
///      `C:\ProgramData`. `SHGetKnownFolderPath` is not used: the `windows`
///      crate links it as a raw-dylib import of shell32.dll, which does not
///      link on the `*-win7-windows-gnu` targets.
/// 4. If still not found, return the system path from step 3 (not the
///    working-directory filename) so the subsequent open() error names
///    the location the user is expected to create.
fn resolve_config_path(matches: &getopts::Matches) -> String {
    if let Some(path) = matches.opt_str("config") {
        if !path.is_empty() {
            return path;
        }
        // Empty --config / -c: same lookup as when the flag is omitted.
    }

    // Compute the config filename based on the binary name (if prefix/port recognised)
    let name = program_basename();
    let local = config_filename_from_program_name(&name);

    if Path::new(&local).exists() {
        return local;
    }

    #[cfg(all(unix, not(target_os = "android")))]
    {
        let system = system_config_path(&local);
        if Path::new(&system).exists() {
            return system;
        }
    }

    #[cfg(target_os = "android")]
    {
        if let Some(dir) = compile_time_config_dir() {
            let system = format!("{}/{}", dir, local);
            if Path::new(&system).exists() {
                return system;
            }
        }
    }

    #[cfg(windows)]
    {
        if let Some(program_data) = windows_program_data_dir() {
            let system = program_data.join("Yggdrasil-ng").join(&local);
            if system.exists() {
                return system.to_string_lossy().into_owned();
            }
        }
    }

    // Neither default exists. Name the system path in the error that follows.
    system_config_path(&local)
}

/// Return the ProgramData directory without linking shell32 or ole32.
///
/// `SHGetKnownFolderPath` / `CoTaskMemFree` are not called. The `windows` crate
/// imports them as raw-dylibs (`shell32.dll`, `ole32.dll`), and that import
/// does not link for `x86_64-win7-windows-gnu` / `i686-win7-windows-gnu`
/// (`cargo zigbuild`). On Windows 7 the same folder is already published as
/// `ProgramData` (Vista+) and `ALLUSERSPROFILE`.
#[cfg(windows)]
fn windows_program_data_dir() -> Option<std::path::PathBuf> {
    for key in ["ProgramData", "ALLUSERSPROFILE"] {
        if let Some(dir) = std::env::var_os(key) {
            if !dir.is_empty() {
                return Some(std::path::PathBuf::from(dir));
            }
        }
    }
    Some(std::path::PathBuf::from(r"C:\ProgramData"))
}

/// Resolve (prefix, port) from the binary/symlink/hardlink name.
/// Valid suffix after the last '_' is used; otherwise None (keep defaults).
fn resolve_prefix_port() -> Option<(u8, u16)> {
    prefix_port_from_name(&program_basename())
}

#[cfg(feature = "ctl")]
fn print_ctl_commands() {
    println!("Commands (control mode):");
    println!("  Local queries:");
    println!("    list, getSelf, getPeers, getTree, getPaths, getSessions, getTUN, getMulticastInterfaces");
    println!("  Debug:");
    println!("    getDebug  (routing stats: tree size, broken paths, queue depth, etc.)");
    println!("  Peer management:");
    println!("    addPeer uri=<URI>, removePeer uri=<URI>");
    println!("  Remote queries:");
    println!("    getNodeInfo key=<hex>, debug_remoteGetSelf key=<hex>");
    println!("    debug_remoteGetPeers key=<hex>, debug_remoteGetTree key=<hex>");
    println!("  Path diagnostics:");
    println!("    getLookup key=<hex>, forceLookup key=<hex>");
}

/// True when an `ip rule show` line is exactly `<pref>: from all lookup <lookup>`.
#[cfg(target_os = "linux")]
fn ip_rule_line_matches(line: &str, pref: i64, lookup: u8) -> bool {
    let mut parts = line.split_whitespace();
    let head = match parts.next() {
        Some(head) => head,
        None => return false,
    };
    if head != format!("{pref}:") {
        return false;
    }
    let rest: Vec<&str> = parts.collect();
    rest.len() == 4
        && rest[0] == "from"
        && rest[1] == "all"
        && rest[2] == "lookup"
        && rest[3] == lookup.to_string()
}

/// Add `pref: from all lookup <table>` for IPv4 and IPv6 if it is not already present.
/// Does not delete the rule on shutdown.
#[cfg(target_os = "linux")]
fn ensure_linux_ip_rule(pref: i64, lookup: u8) -> Result<(), String> {
    for ipv6 in [false, true] {
        let mut show = std::process::Command::new("ip");
        if ipv6 {
            show.arg("-6");
        }
        let shown = show
            .args(["rule", "show"])
            .output()
            .map_err(|e| format!("failed to run ip rule show: {e}"))?;
        if !shown.status.success() {
            return Err(format!(
                "ip rule show failed: {}",
                String::from_utf8_lossy(&shown.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&shown.stdout);
        if text.lines().any(|line| ip_rule_line_matches(line, pref, lookup)) {
            continue;
        }
        let mut add = std::process::Command::new("ip");
        if ipv6 {
            add.arg("-6");
        }
        let added = add
            .args([
                "rule",
                "add",
                "pref",
                &pref.to_string(),
                "from",
                "all",
                "lookup",
                &lookup.to_string(),
            ])
            .output()
            .map_err(|e| format!("failed to run ip rule add: {e}"))?;
        if !added.status.success() {
            return Err(format!(
                "ip rule add failed: {}",
                String::from_utf8_lossy(&added.stderr).trim()
            ));
        }
        tracing::info!(
            "Ensured {} ip rule {pref}: from all lookup {lookup}",
            if ipv6 { "IPv6" } else { "IPv4" }
        );
    }
    Ok(())
}

/// Install `<prefix>/7 dev <tun> table <table>`, then drop the kernel copy from main.
#[cfg(all(target_os = "linux", feature = "tun"))]
fn install_overlay_route(tun_name: &str, table: u8) -> Result<(), String> {
    let (addr, len) = yggdrasil::address::overlay_network();
    let cidr = format!("{addr}/{len}");
    let table_id = table.to_string();
    let added = std::process::Command::new("ip")
        .args(["-6", "route", "replace", &cidr, "dev", tun_name, "table", &table_id])
        .output()
        .map_err(|e| format!("failed to run ip route replace: {e}"))?;
    if !added.status.success() {
        return Err(format!(
            "ip route replace {cidr} table {table} failed: {}",
            String::from_utf8_lossy(&added.stderr).trim()
        ));
    }
    tracing::info!("Installed overlay route {cidr} dev {tun_name} table {table}");

    let deleted = std::process::Command::new("ip")
        .args(["-6", "route", "del", &cidr, "dev", tun_name])
        .output()
        .map_err(|e| format!("failed to run ip route del: {e}"))?;
    if !deleted.status.success() {
        tracing::debug!(
            "Overlay route {cidr} was not removed from main: {}",
            String::from_utf8_lossy(&deleted.stderr).trim()
        );
    }
    Ok(())
}

/// Remove only the extra-table overlay route. The ip rule stays.
#[cfg(all(target_os = "linux", feature = "tun"))]
fn remove_overlay_route(tun_name: &str, table: u8) {
    let (addr, len) = yggdrasil::address::overlay_network();
    let cidr = format!("{addr}/{len}");
    let table_id = table.to_string();
    match std::process::Command::new("ip")
        .args(["-6", "route", "del", &cidr, "dev", tun_name, "table", &table_id])
        .output()
    {
        Ok(out) if out.status.success() => {
            tracing::info!("Removed overlay route {cidr} dev {tun_name} table {table}");
        }
        Ok(out) => {
            tracing::debug!(
                "Overlay route {cidr} table {table} not removed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => tracing::debug!("failed to run ip route del: {e}"),
    }
}

#[cfg(target_os = "linux")]
const LOCAL_SUBNET_ROUTE_RETRIES: u32 = 10;
#[cfg(target_os = "linux")]
const LOCAL_SUBNET_ROUTE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// `<subnet>::1`. The first 8 bytes are the node subnet; the host part is `::1`.
#[cfg(target_os = "linux")]
fn local_subnet_gateway(subnet: &yggdrasil::address::Subnet) -> std::net::Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&subnet.0);
    bytes[15] = 1;
    std::net::Ipv6Addr::from(bytes)
}

/// Interfaces from `ip -6 -o addr show` that have `wanted` with prefix 64..=128.
/// The same name twice counts once. `lo` is never a target. `tentative` /
/// `dadfailed` are skipped so a later retry can see the address after DAD.
#[cfg(target_os = "linux")]
fn local_subnet_gateway_ifaces(text: &str, wanted: std::net::Ipv6Addr) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        if line.contains("tentative") || line.contains("dadfailed") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _index = parts.next();
        let iface = match parts.next() {
            Some(name) => name.split('@').next().unwrap_or(name),
            None => continue,
        };
        if iface.is_empty() || iface == "lo" {
            continue;
        }
        let addr_tok = loop {
            match parts.next() {
                Some("inet6") => break parts.next(),
                Some(_) => continue,
                None => break None,
            }
        };
        let Some(addr_tok) = addr_tok else { continue };
        let Some((addr_str, prefix_str)) = addr_tok.split_once('/') else { continue };
        let Ok(prefix) = prefix_str.parse::<u8>() else { continue };
        if !(64..=128).contains(&prefix) {
            continue;
        }
        let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() else { continue };
        if addr == wanted && !found.iter().any(|name: &String| name == iface) {
            found.push(iface.to_string());
        }
    }
    found
}

#[cfg(target_os = "linux")]
fn list_local_subnet_gateway_ifaces(wanted: std::net::Ipv6Addr) -> Result<Vec<String>, String> {
    let output = std::process::Command::new("ip")
        .args(["-6", "-o", "addr", "show"])
        .output()
        .map_err(|e| format!("failed to run ip -6 addr show: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "ip -6 addr show failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(local_subnet_gateway_ifaces(&text, wanted))
}

#[cfg(target_os = "linux")]
fn install_local_subnet_route(cidr: &str, iface: &str, table: u8) -> Result<(), String> {
    let table_id = table.to_string();
    let added = std::process::Command::new("ip")
        .args(["-6", "route", "replace", cidr, "dev", iface, "table", &table_id])
        .output()
        .map_err(|e| format!("failed to run ip route replace: {e}"))?;
    if !added.status.success() {
        return Err(format!(
            "ip route replace {cidr} dev {iface} table {table} failed: {}",
            String::from_utf8_lossy(&added.stderr).trim()
        ));
    }
    tracing::info!("Installed local subnet route {cidr} dev {iface} table {table}");
    Ok(())
}

/// Delete only the extra-table /64. Missing route is not an error.
#[cfg(target_os = "linux")]
fn remove_local_subnet_route(cidr: &str, table: u8) {
    let table_id = table.to_string();
    match std::process::Command::new("ip")
        .args(["-6", "route", "del", cidr, "table", &table_id])
        .output()
    {
        Ok(out) if out.status.success() => {
            tracing::info!("Removed local subnet route {cidr} table {table}");
        }
        Ok(out) => {
            tracing::debug!(
                "Local subnet route {cidr} table {table} not removed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => tracing::debug!("failed to run ip route del: {e}"),
    }
}

/// First look is immediate. Up to 10 more looks, 60s apart. Stop once the route
/// is installed, or when shutdown is signalled. Ambiguous interfaces install nothing.
#[cfg(target_os = "linux")]
async fn install_local_subnet_route_with_retries(
    subnet: yggdrasil::address::Subnet,
    table: u8,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    let cidr = subnet.to_string();
    let wanted = local_subnet_gateway(&subnet);
    for attempt in 0..=LOCAL_SUBNET_ROUTE_RETRIES {
        if *shutdown_rx.borrow() {
            return;
        }
        match list_local_subnet_gateway_ifaces(wanted) {
            Ok(ifaces) if ifaces.len() == 1 => {
                match install_local_subnet_route(&cidr, &ifaces[0], table) {
                    Ok(()) => return,
                    Err(e) => tracing::error!("Failed to install local subnet route: {e}"),
                }
            }
            Ok(ifaces) if ifaces.len() > 1 => {
                tracing::debug!(
                    "Local subnet gateway {wanted} is on multiple interfaces ({}); not installing {cidr} table {table}",
                    ifaces.join(", ")
                );
            }
            Ok(_) => {
                tracing::debug!(
                    "Local subnet gateway {wanted} not found; not installing {cidr} table {table}"
                );
            }
            Err(e) => tracing::debug!("Failed to list IPv6 addresses: {e}"),
        }
        if attempt == LOCAL_SUBNET_ROUTE_RETRIES {
            tracing::debug!(
                "Stopped looking for local subnet gateway {wanted} after {LOCAL_SUBNET_ROUTE_RETRIES} retries"
            );
            return;
        }
        tracing::debug!(
            "Retrying local subnet route {cidr} table {table} in 60s ({}/{})",
            attempt + 1,
            LOCAL_SUBNET_ROUTE_RETRIES
        );
        tokio::select! {
            _ = shutdown_rx.changed() => return,
            _ = tokio::time::sleep(LOCAL_SUBNET_ROUTE_INTERVAL) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prefix_port_existing_cases() {
        assert_eq!(parse_prefix_port("02:9001"), Some((0x02, 9001)));
        assert_eq!(parse_prefix_port("02-9001"), Some((0x02, 9001)));
        assert_eq!(parse_prefix_port("029001"), Some((0x02, 9001)));
        assert_eq!(parse_prefix_port("fc.65535"), Some((0xfc, 65535)));
        assert_eq!(parse_prefix_port("02"), Some((0x02, 9001)));
        assert_eq!(parse_prefix_port("fc"), Some((0xfc, 9126)));
        assert_eq!(parse_prefix_port("02:1023"), None); // port too low
        assert_eq!(parse_prefix_port("gg:9001"), None); // invalid prefix
        // Multi-byte separator must not panic; it is not a valid suffix.
        assert_eq!(parse_prefix_port("02€9001"), None);
        assert_eq!(parse_prefix_port("02—9001"), None);
        assert_eq!(parse_prefix_port("02я9001"), None);
    }

    #[test]
    fn test_port_from_prefix() {
        assert_eq!(port_from_prefix(0x00), 9000);
        assert_eq!(port_from_prefix(0x02), 9001);
        assert_eq!(port_from_prefix(0xfc), 9126);
        // prefix/2 + 0x2328, then decimal
        assert_eq!(port_from_prefix(0x02), (0x02u16 / 2) + 0x2328);
        assert_eq!(port_from_prefix(0xfc), (0xfcu16 / 2) + 0x2328);
    }

    #[test]
    fn test_prefix_port_from_name() {
        assert_eq!(prefix_port_from_name("yggdrasil_029001"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("yggdrasil_02-9001"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("yggdrasil_02.9001"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("yggdrasil_02-9001.exe"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("Yggdrasil_0a.12345"), Some((0x0a, 12345)));
        assert_eq!(prefix_port_from_name("yggdrasil"), None);
        assert_eq!(prefix_port_from_name("yggdrasil_"), None);
        assert_eq!(prefix_port_from_name("yggdrasil_foo"), None);
        assert_eq!(prefix_port_from_name("yggdrasil_02"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("ygg_02"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("ygg_fc"), Some((0xfc, 9126)));
        assert_eq!(prefix_port_from_name("yggdrasil_00"), Some((0x00, 9000)));
        assert_eq!(prefix_port_from_name("yggdrasil_02-999"), None); // port < 1024
        // last '_' is the marker
        assert_eq!(prefix_port_from_name("my_ygg_02-9001"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("yggdrasil_02€9001"), None);
        #[cfg(windows)]
        {
            assert_eq!(prefix_port_from_name("ygg_02.exe"), Some((0x02, 9001)));
            assert_eq!(prefix_port_from_name("yggdrasil_fc.EXE"), Some((0xfc, 9126)));
        }
    }

    #[test]
    fn prefix_port_does_not_override_auto_if_name_on_macos_or_bsd() {
        let keep_auto = cfg!(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
        ));
        let force_windows_name = cfg!(windows);
        if keep_auto {
            assert!(
                !force_windows_name,
                "macOS/BSD must keep if_name=auto when the binary has a prefix/port suffix"
            );
        }
    }

    #[test]
    fn test_config_filename_from_program_name() {
        assert_eq!(
            config_filename_from_program_name("yggdrasil"),
            "yggdrasil.toml"
        );
        assert_eq!(
            config_filename_from_program_name("ygg_02"),
            "ygg_02.toml"
        );
        assert_eq!(
            config_filename_from_program_name("yggdrasil_fc"),
            "yggdrasil_fc.toml"
        );
        assert_eq!(
            config_filename_from_program_name("ygg_029001"),
            "ygg_029001.toml"
        );
        assert_eq!(
            config_filename_from_program_name("yggdrasil_02.9001"),
            "yggdrasil_02.9001.toml"
        );
        assert_eq!(
            config_filename_from_program_name("yggdrasil_02.9002"),
            "yggdrasil_02.9002.toml"
        );
        #[cfg(windows)]
        {
            assert_eq!(
                config_filename_from_program_name("yggdrasil_02-9001.exe"),
                "yggdrasil_02-9001.toml"
            );
            assert_eq!(
                config_filename_from_program_name("yggdrasil_02.9001.exe"),
                "yggdrasil_02.9001.toml"
            );
            assert_eq!(
                config_filename_from_program_name("YGGDRASIL_02.9001.EXE"),
                "YGGDRASIL_02.9001.toml"
            );
            // Non-ASCII tail: must not panic, and must not strip anything.
            assert_eq!(
                config_filename_from_program_name("yggdrasil_029001é€"),
                "yggdrasil_029001é€.toml"
            );
            assert_eq!(
                config_filename_from_program_name("yggdrasil_029001é€.exe"),
                "yggdrasil_029001é€.toml"
            );
            assert_eq!(
                config_filename_from_program_name("yggdrasil_029001é€.EXE"),
                "yggdrasil_029001é€.toml"
            );
            assert_eq!(
                config_filename_from_program_name("ygg_02.exe"),
                "ygg_02.toml"
            );
        }
        #[cfg(not(windows))]
        {
            assert_eq!(
                config_filename_from_program_name("yggdrasil_02-9001.exe"),
                "yggdrasil_02-9001.exe.toml"
            );
            assert_eq!(
                config_filename_from_program_name("yggdrasil_02.9001.exe"),
                "yggdrasil_02.9001.exe.toml"
            );
            assert_eq!(
                config_filename_from_program_name("YGGDRASIL_02.9001.EXE"),
                "YGGDRASIL_02.9001.EXE.toml"
            );
            assert_eq!(
                config_filename_from_program_name("yggdrasil_029001é€"),
                "yggdrasil_029001é€.toml"
            );
        }
    }

    #[test]
    fn test_system_config_path() {
        #[cfg(target_os = "linux")]
        {
            let dir = compile_time_config_dir().unwrap();
            assert_eq!(
                system_config_path("yggdrasil.toml"),
                format!("{}/yggdrasil.toml", dir)
            );
            assert_eq!(
                system_config_path("ygg_0615001.toml"),
                format!("{}/ygg_0615001.toml", dir)
            );
            assert_eq!(
                system_config_path("yggdrasil_02.9001.toml"),
                format!("{}/yggdrasil_02.9001.toml", dir)
            );
        }
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        {
            assert_eq!(
                system_config_path("yggdrasil.toml"),
                "/etc/yggdrasil/yggdrasil.toml"
            );
            assert_eq!(
                system_config_path("ygg_0615001.toml"),
                "/etc/yggdrasil/ygg_0615001.toml"
            );
            assert_eq!(
                system_config_path("yggdrasil_02.9001.toml"),
                "/etc/yggdrasil/yggdrasil_02.9001.toml"
            );
        }
        #[cfg(target_os = "android")]
        {
            match compile_time_config_dir() {
                Some(dir) => {
                    assert_eq!(
                        system_config_path("yggdrasil.toml"),
                        format!("{}/yggdrasil.toml", dir)
                    );
                    assert_eq!(
                        system_config_path("ygg_0615001.toml"),
                        format!("{}/ygg_0615001.toml", dir)
                    );
                }
                None => {
                    assert_eq!(system_config_path("yggdrasil.toml"), "yggdrasil.toml");
                    assert_eq!(system_config_path("ygg_0615001.toml"), "ygg_0615001.toml");
                }
            }
        }
        #[cfg(windows)]
        {
            assert_eq!(
                system_config_path("yggdrasil.toml"),
                "%ALLUSERSPROFILE%\\Yggdrasil-ng\\yggdrasil.toml"
            );
            assert_eq!(
                system_config_path("ygg_0615001.toml"),
                "%ALLUSERSPROFILE%\\Yggdrasil-ng\\ygg_0615001.toml"
            );
            assert_eq!(
                system_config_path("yggdrasil_02.9001.toml"),
                "%ALLUSERSPROFILE%\\Yggdrasil-ng\\yggdrasil_02.9001.toml"
            );
        }
        #[cfg(not(any(all(unix, not(target_os = "android")), windows)))]
        {
            assert_eq!(system_config_path("yggdrasil.toml"), "yggdrasil.toml");
            assert_eq!(system_config_path("ygg_0615001.toml"), "ygg_0615001.toml");
        }
    }

    #[test]
    fn test_rewrite_default_admin_listen() {
        assert_eq!(
            rewrite_default_admin_listen("tcp://localhost:9001", 15001).as_deref(),
            Some("tcp://localhost:15001")
        );
        assert_eq!(
            rewrite_default_admin_listen("tcp://127.0.0.1:9001", 15001).as_deref(),
            Some("tcp://127.0.0.1:15001")
        );
        assert_eq!(
            rewrite_default_admin_listen("tcp://[::1]:9001", 15001).as_deref(),
            Some("tcp://[::1]:15001")
        );
        // Not the historic default port, or not loopback: leave as-is.
        assert_eq!(rewrite_default_admin_listen("tcp://localhost:15001", 16000), None);
        assert_eq!(rewrite_default_admin_listen("tcp://0.0.0.0:9001", 15001), None);
        assert_eq!(rewrite_default_admin_listen("none", 15001), None);
        assert_eq!(rewrite_default_admin_listen("unix:///var/run/ygg.sock", 15001), None);
    }

    #[test]
    fn test_config_parent_dir() {
        assert!(config_parent_dir(Path::new("yggdrasil.toml")).is_none());
        assert!(config_parent_dir(Path::new("./yggdrasil.toml")).is_none());
        assert_eq!(
            config_parent_dir(Path::new("/etc/yggdrasil/yggdrasil.toml"))
                .map(|p| p.to_str().unwrap()),
            Some("/etc/yggdrasil")
        );
        assert_eq!(
            config_parent_dir(Path::new("foo/bar.toml")).map(|p| p.to_str().unwrap()),
            Some("foo")
        );
        assert_eq!(
            config_parent_dir(Path::new("/yggdrasil.toml")).map(|p| p.to_str().unwrap()),
            Some("/")
        );
    }

    #[test]
    fn test_expand_genconf_path_leaves_plain_paths() {
        assert_eq!(expand_genconf_path("/etc/yggdrasil/yggdrasil.toml"), "/etc/yggdrasil/yggdrasil.toml");
        assert_eq!(expand_genconf_path("yggdrasil.toml"), "yggdrasil.toml");
    }

    #[cfg(windows)]
    #[test]
    fn test_expand_genconf_path_windows_env() {
        let val = std::env::var("ALLUSERSPROFILE")
            .unwrap_or_else(|_| r"C:\ProgramData".to_string());
        assert_eq!(
            expand_genconf_path(r"%ALLUSERSPROFILE%\Yggdrasil-ng\yggdrasil.toml"),
            format!(r"{}\Yggdrasil-ng\yggdrasil.toml", val)
        );
        assert_eq!(
            expand_genconf_path(r"%YGG_TEST_GENCONF_DOES_NOT_EXIST%\x.toml"),
            r"%YGG_TEST_GENCONF_DOES_NOT_EXIST%\x.toml"
        );
        // Unknown names and a lone percent stay unchanged.
        assert_eq!(expand_genconf_path(r"%"), r"%");
        assert_eq!(expand_genconf_path(r"%%"), r"%%");
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_program_data_dir_uses_env_not_shell32() {
        let dir = windows_program_data_dir().expect("program data dir");
        assert!(!dir.as_os_str().is_empty());
        if let Some(from_env) = std::env::var_os("ProgramData") {
            if !from_env.is_empty() {
                assert_eq!(dir, std::path::PathBuf::from(from_env));
                return;
            }
        }
        if let Some(from_env) = std::env::var_os("ALLUSERSPROFILE") {
            if !from_env.is_empty() {
                assert_eq!(dir, std::path::PathBuf::from(from_env));
                return;
            }
        }
        assert_eq!(dir, std::path::PathBuf::from(r"C:\ProgramData"));
    }
    
    #[test]
    fn generate_from_base_reuses_key_and_ignores_other_fields() {
        let base_key = {
            let generated = yggdrasil::config::Config::generate_config_text();
            yggdrasil::config::Config::private_key_from_toml(&generated).unwrap()
        };
        // Base file has a custom listen/peers; those must NOT be copied.
        let base_toml = format!(
            "private_key = \"{base_key}\"\npeers = [\"tcp://198.51.100.7:23456\"]\nlisten = [\"tcp://198.51.100.8:23456\"]\n"
        );
        let dir = std::env::temp_dir();
        let base_path = dir.join(format!(
            "ygg-base-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&base_path, base_toml).unwrap();
        let text = generate_config_text_maybe_from_base(Some(base_path.to_str().unwrap())).unwrap();
        let _ = std::fs::remove_file(&base_path);
        assert!(text.contains(&format!("private_key = \"{base_key}\"")));
        assert!(
            !text.contains("tcp://198.51.100.7:23456"),
            "peers from the base file must not be copied:\n{text}"
        );
        assert!(
            !text.contains("tcp://198.51.100.8:23456"),
            "listen from the base file must not be copied:\n{text}"
        );
    }

    #[test]
    fn generate_from_base_reads_private_key_from_include() {
        let base_key = {
            let generated = yggdrasil::config::Config::generate_config_text();
            yggdrasil::config::Config::private_key_from_toml(&generated).unwrap()
        };
        let dir = std::env::temp_dir().join(format!(
            "ygg-base-include-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("key.toml");
        let base_path = dir.join("base.toml");
        std::fs::write(&key_path, format!("private_key = \"{base_key}\"\n")).unwrap();
        std::fs::write(
            &base_path,
            "include = \"key.toml\"\npeers = [\"tcp://198.51.100.9:23456\"]\n",
        )
        .unwrap();

        let text = generate_config_text_maybe_from_base(Some(base_path.to_str().unwrap())).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            text.contains(&format!("private_key = \"{base_key}\"")),
            "private_key from the include file must be reused:\n{text}"
        );
        assert!(
            !text.contains("tcp://198.51.100.9:23456"),
            "peers from the base file must not be copied:\n{text}"
        );
    }
    
    #[test]
    fn generate_from_missing_base_is_error() {
        let err = generate_config_text_maybe_from_base(Some("/no/such/ygg-base-file.toml"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("base configuration file not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn generate_without_base_still_mints_a_key() {
        let text = generate_config_text_maybe_from_base(None).unwrap();
        let key = yggdrasil::config::Config::private_key_from_toml(&text).unwrap();
        assert_eq!(key.len(), 128);
    }

    #[test]
    fn rewrite_admin_listen_in_genconf_text_keeps_historic_port() {
        let input = "# admin_listen = \"tcp://localhost:9001\"\n";
        let out = rewrite_admin_listen_in_genconf_text(input, DEFAULT_ADMIN_PORT);
        assert_eq!(out, input);
    }

    #[test]
    fn rewrite_admin_listen_in_genconf_text_uses_explicit_port() {
        let input = "# admin_listen = \"tcp://localhost:9001\"\n";
        let out = rewrite_admin_listen_in_genconf_text(input, 15001);
        assert_eq!(out, "# admin_listen = \"tcp://localhost:15001\"\n");
        assert!(!out.contains("tcp://localhost:9001"));
    }

    #[test]
    fn rewrite_admin_listen_in_genconf_text_uses_derived_prefix_only_port() {
        // Same formula as ygg_fc / ygg_06: suffix is only the prefix.
        let input = "# admin_listen = \"tcp://localhost:9001\"\n";
        let fc = rewrite_admin_listen_in_genconf_text(input, port_from_prefix(0xfc));
        assert_eq!(port_from_prefix(0xfc), 9126);
        assert_eq!(fc, "# admin_listen = \"tcp://localhost:9126\"\n");

        let p06 = rewrite_admin_listen_in_genconf_text(input, port_from_prefix(0x06));
        assert_eq!(port_from_prefix(0x06), 9003);
        assert_eq!(p06, "# admin_listen = \"tcp://localhost:9003\"\n");

        let p02 = rewrite_admin_listen_in_genconf_text(input, port_from_prefix(0x02));
        assert_eq!(port_from_prefix(0x02), DEFAULT_ADMIN_PORT);
        assert_eq!(p02, input);
    }

    #[test]
    fn generate_config_text_maybe_from_base_contains_commented_admin_listen() {
        let text = generate_config_text_maybe_from_base(None).unwrap();
        // Cargo test binary has no prefix/port suffix, so the historic
        // commented default must still be present.
        assert!(
            text.contains("# admin_listen = \"tcp://localhost:9001\""),
            "expected commented default admin_listen in generated text:\n{text}"
        );
        let rewritten = rewrite_admin_listen_in_genconf_text(&text, 9126);
        assert!(
            rewritten.contains("# admin_listen = \"tcp://localhost:9126\""),
            "expected rewritten commented admin_listen:\n{rewritten}"
        );
        assert!(
            !rewritten.contains("tcp://localhost:9001"),
            "historic default URI must not remain after rewrite:\n{rewritten}"
        );
    }

    #[cfg(all(test, target_os = "linux"))]
    #[test]
    fn ip_rule_show_line_match() {
        assert!(ip_rule_line_matches("9000:\tfrom all lookup 200", 9000, 200));
        assert!(ip_rule_line_matches("9000:   from all lookup 200", 9000, 200));
        assert!(!ip_rule_line_matches("9001: from all lookup 200", 9000, 200));
        assert!(!ip_rule_line_matches("9000: from all lookup 201", 9000, 200));
        assert!(!ip_rule_line_matches("9000: from 10.0.0.0/8 lookup 200", 9000, 200));
    }

    #[cfg(all(test, target_os = "linux"))]
    #[test]
    fn local_subnet_gateway_iface_parse() {
        let subnet = yggdrasil::address::Subnet([0x03, 0x00, 0x00, 0x10, 0x00, 0x20, 0x00, 0x30]);
        let wanted = local_subnet_gateway(&subnet);
        assert_eq!(wanted, "300:10:20:30::1".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(subnet.to_string(), "300:10:20:30::/64");

        let text = "\
1: lo    inet6 300:10:20:30::1/128 scope host \n\
2: br0    inet6 300:10:20:30::1/64 scope global \n\
3: eth0    inet6 300:10:20:30::1/128 scope global \n\
4: eth1    inet6 300:10:20:30::2/64 scope global \n\
5: eth2    inet6 300:10:20:31::1/64 scope global \n\
6: eth3    inet6 300:10:20:30::1/63 scope global \n\
7: eth4    inet6 300:10:20:30::1/64 scope global tentative \n\
8: mac0@eth5    inet6 300:10:20:30::1/96 scope global \n\
2: br0    inet6 300:10:20:30::1/64 scope global \n";

        assert_eq!(
            local_subnet_gateway_ifaces(text, wanted),
            vec!["br0".to_string(), "eth0".to_string(), "mac0".to_string()]
        );

        let one = "3: br0    inet6 300:10:20:30::1/64 scope global \n";
        assert_eq!(local_subnet_gateway_ifaces(one, wanted), vec!["br0".to_string()]);

        let none = "3: br0    inet6 300:10:20:30::2/64 scope global \n";
        assert!(local_subnet_gateway_ifaces(none, wanted).is_empty());
        
        let only_lo = "1: lo    inet6 300:10:20:30::1/128 scope host \n";
        assert!(local_subnet_gateway_ifaces(only_lo, wanted).is_empty());
    }
}
