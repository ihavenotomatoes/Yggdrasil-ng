// TUN support is behind the "tun" feature (enabled by default).
// Disable it with --no-default-features for library/VpnService builds.
#![cfg(feature = "tun")]

#[cfg(feature = "ckr")]
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::sync::OnceLock;

use tun_rs::AsyncDevice;

use crate::ipv6rwc::ReadWriteCloser;

/// Base GUID we register the wintun adapter with. The current address prefix
/// is added so multiple instances with different prefix/port can coexist.
/// Reused to target the same interface when assigning DNS servers via
/// `SetInterfaceDnsSettings`.
#[cfg(windows)]
const TUN_DEVICE_GUID_BASE: u128 = 0x8f59971a78724aa6b2eb061fc4e9d0a7;

#[cfg(windows)]
static SET_INTERFACE_DNS_PTR: OnceLock<
    Option<
        unsafe extern "system" fn(
            windows::core::GUID,
            *const windows::Win32::NetworkManagement::IpHelper::DNS_INTERFACE_SETTINGS,
        ) -> windows::core::HRESULT,
    >,
> = OnceLock::new();

/// Requested TUN name when `if_name` is `"auto"`.
///
/// An empty string means "do not call `DeviceBuilder::name()`":
/// - macOS/Darwin: the kernel allocates the next free `utunN`;
/// - FreeBSD/GhostBSD, NetBSD, OpenBSD: tun-rs scans
///   `/dev/tun0`..`/dev/tun255` and takes the first free node.
///   On FreeBSD/GhostBSD the allocated `tunN` is then renamed:
///   `if_name = "auto"` → Linux-like alias (`ygg0` / `ygg{prefix}{port}`);
///   any other `if_name` is used as the alias as-is.
/// Windows and Linux keep their historic fixed defaults.
fn auto_requested_name() -> String {
    if cfg!(windows) {
        "Yggdrasil".to_string()
    } else if cfg!(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
    )) {
        String::new()
    } else {
        "ygg0".to_string()
    }
}

/// Stock TUN MTU used at DeviceBuilder time on NetBSD / OpenBSD.
///
/// tun-rs applies `SIOCSIFMTU` during `build_async()`. Passing the
/// configured `if_mtu` (default 65535) fails with EINVAL on a stock
/// kernel: NetBSD `tun(4)` caps at `TUNMTU` (1500), OpenBSD at
/// `TUNMRU` (16384). Custom kernels may raise those compile-time
/// limits, so after a successful create we probe upward separately.
#[cfg(target_os = "netbsd")]
const BSD_TUN_CREATE_MTU: u16 = 1500;
#[cfg(target_os = "openbsd")]
const BSD_TUN_CREATE_MTU: u16 = 16384;

/// MTU passed to `DeviceBuilder::mtu()` so create cannot fail with
/// EINVAL on a stock NetBSD/OpenBSD tun(4). Other platforms keep the
/// caller-supplied value unchanged.
fn tun_create_mtu(requested: u16) -> u16 {
    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    {
        requested.min(BSD_TUN_CREATE_MTU)
    }
    #[cfg(not(any(target_os = "netbsd", target_os = "openbsd")))]
    {
        requested
    }
}

/// Highest MTU in `(floor, requested]` that `try_set` accepts.
///
/// `try_set(v)` must return true only when the kernel accepted `v`
/// as the interface MTU. The last successful value is left applied
/// by the caller of `try_set`; this helper does not emit logs.
#[cfg(any(test, target_os = "netbsd", target_os = "openbsd"))]
fn probe_highest_mtu(floor: u16, requested: u16, mut try_set: impl FnMut(u16) -> bool) -> u16 {
    if requested <= floor {
        return floor;
    }
    if try_set(requested) {
        return requested;
    }
    let mut lo = floor;
    let mut hi = requested - 1;
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if try_set(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Linux-like TUN name used as the FreeBSD alias when
/// `if_name` is `"auto"`.
///
/// Matches `apply_prefix_port` on Linux:
/// - custom prefix/port from the binary/symlink/hardlink suffix
///   (`ygg_0615001` → `ygg0615001`);
/// - otherwise the historic default `ygg0`.
#[cfg(any(target_os = "freebsd"))]
fn linux_like_auto_tun_name() -> String {
    if crate::address::prefix_port_set() {
        linux_like_auto_tun_name_from(Some((
            crate::address::address_prefix(),
            crate::multicast::multicast_port(),
        )))
    } else {
        linux_like_auto_tun_name_from(None)
    }
}

/// Same naming rule with explicit inputs so unit tests do not touch
/// the process-wide prefix/port atomics.
#[cfg(target_os = "freebsd")]
fn linux_like_auto_tun_name_from(prefix_port: Option<(u8, u16)>) -> String {
    match prefix_port {
        Some((prefix, port)) => format!("ygg{:02x}{}", prefix, port),
        None => "ygg0".to_string(),
    }
}

/// TUN adapter: bridges a TUN network device with the IPv6 RWC.
pub struct TunAdapter {
    device: Arc<AsyncDevice>,
    /// Actual OS-level name of the interface.
    /// On macOS with "auto" this is the kernel-assigned utunN
    /// (e.g. "utun3"). On NetBSD/OpenBSD with "auto" this is the
    /// allocated tunN (e.g. "tun0"). On FreeBSD this is the alias
    /// after rename (`ygg0` / `ygg{prefix}{port}` when `if_name`
    /// is `"auto"`, otherwise the configured `if_name`), or the
    /// original tunN if rename failed.
    name: String,
    /// MTU the interface ended up with, which the OS may have clamped.
    mtu: u16,
    read_handle: tokio::task::JoinHandle<()>,
    write_handle: tokio::task::JoinHandle<()>,
}

impl TunAdapter {
    /// Create and start the TUN adapter.
    /// `name`: interface name ("auto" for automatic, "none" to disable)
    /// `rwc`: the IPv6 ReadWriteCloser bridge
    /// `addr`: the Yggdrasil IPv6 address string
    /// `subnet`: the /64 subnet string (for routing)
    /// `mtu`: the MTU for the TUN interface
    /// `dns_servers`: DNS server IPs to assign to the interface (Windows only)
    /// `ckr_config`: optional CKR tunnel routing config (for route installation)
    pub async fn new(
        name: &str,
        rwc: Arc<ReadWriteCloser>,
        addr: &str,
        _subnet: &str,
        mtu: u16,
        #[cfg(windows)] dns_servers: &[String],
        #[cfg(feature = "ckr")] _ckr_config: Option<&crate::config::TunnelRoutingConfig>,
        #[cfg(feature = "ckr")] _self_key: &[u8; 32],
    ) -> Result<Self, String> {
        if name == "none" {
            return Err("TUN disabled".to_string());
        }

        // Determine the requested interface name.
        // On macOS and BSD "auto" must leave the name empty so that tun-rs
        // does not call DeviceBuilder::name() and the backend can allocate
        // utunN / tunN. On FreeBSD a non-"auto" if_name is also left empty here:
        // tun-rs still allocates tunN, and if_name is applied afterwards as
        // an alias. Windows and Linux keep the historic defaults.
        // `mut` is needed because we overwrite an empty name with the real
        // interface name after device creation.
        #[allow(unused_mut)]
        let mut tun_name: String = if name == "auto" {
            auto_requested_name()
        } else if cfg!(any(target_os = "freebsd")) {
            String::new()
        } else {
            name.to_string()
        };

        // Parse the address - strip any /prefix and get just the IP
        let ip_str = addr.split('/').next().unwrap_or(addr);
        let ip: Ipv6Addr = ip_str
            .parse()
            .map_err(|e| format!("invalid address '{}': {}", ip_str, e))?;

        // Create TUN device using tun-rs DeviceBuilder (only primary Yggdrasil IPv6).
        // On NetBSD/OpenBSD pass the stock tun(4) MTU first; a later probe
        // raises it to whatever this kernel actually accepts.
        let create_mtu = tun_create_mtu(mtu);
        #[allow(unused_mut)]
        let mut builder = tun_rs::DeviceBuilder::new()
            .ipv6(ip, 7u8)
            .mtu(create_mtu);

        // Only set an explicit name when we have one.
        // On macOS + "auto" the name stays empty → kernel auto-selects utunN.
        if !tun_name.is_empty() {
            builder = builder.name(tun_name.as_str());
        }

        #[cfg(windows)]
        {
            // Add the current address prefix to the base GUID so multiple
            // instances with different --prefix-port can coexist.
            let guid = TUN_DEVICE_GUID_BASE.wrapping_add(crate::address::address_prefix() as u128);
            builder = builder.device_guid(guid);
        }

        let device = builder
            .build_async()
            .map_err(|e| format!("failed to create TUN device: {}", e))?;

        let device = Arc::new(device);

        // When the name was left empty ("auto" on macOS/BSD) the backend has
        // allocated utunN or tunN. Read the real name for logs, getTUN, and
        // CKR route installation.
        if tun_name.is_empty() {
            tun_name = device
                .name()
                .map_err(|e| format!("failed to get assigned TUN interface name: {}", e))?;
        }

        // FreeBSD cannot create /dev/<arbitrary>. After tun-rs has
        // allocated tunN, rename it to the requested alias.
        // `"auto"` uses the Linux-like name; any other if_name is used
        // as-is. `self.name` must become the alias so close() destroys it.
        // Rename failure is non-fatal: keep the allocated tunN. Do not
        // warn when a caller-supplied if_name cannot be applied.
        #[cfg(any(target_os = "freebsd"))]
        if tun_name.starts_with("tun") {
            let alias = if name == "auto" {
                linux_like_auto_tun_name()
            } else {
                name.to_string()
            };
            if alias != tun_name {
                match rename_tun_interface(&tun_name, &alias) {
                    Ok(()) => {
                        tracing::info!(
                            "Renamed TUN interface '{}' to '{}'",
                            tun_name,
                            alias
                        );
                        tun_name = alias;
                    }
                    Err(err) => {
                        if name == "auto" {
                            tracing::warn!(
                                "Failed to rename TUN interface '{}' to '{}': {}",
                                tun_name,
                                alias,
                                err
                            );
                        }
                    }
                }
            }
        }

        // On NetBSD/OpenBSD the builder used the stock tun(4) MTU so
        // create could not fail with EINVAL. Ask this kernel for the
        // highest MTU it will accept, capped by the requested value.
        // Failures stay on `create_mtu`; do not log the probe itself.
        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        let _ = probe_highest_mtu(create_mtu, mtu, |candidate| {
            device.set_mtu(candidate).is_ok()
        });

        let actual_mtu = device.mtu().unwrap_or(create_mtu);
        tracing::info!("TUN device '{}' created with address {} and MTU {}", tun_name, addr, actual_mtu);
        // Overlay MTU must follow the kernel-clamped interface MTU.
        // Otherwise inbound packets larger than tun(4) TUNMTU pass the
        // RWC check, fail tunwrite (EIO on NetBSD) and never produce
        // an ICMPv6 Packet Too Big for the sender.
        rwc.set_mtu(actual_mtu as u64);

        // CKR system route installation moved to main.rs (after multicast)
        // to ensure routes are added only after Yggdrasil network is fully up.
        // Early call removed to support correct startup ordering (Stage 1+).

        // Assign DNS servers to the interface (Windows only). Non-fatal on error.
        #[cfg(windows)]
        if !dns_servers.is_empty() {
            if is_set_interface_dns_settings_supported() {
                match set_interface_dns(dns_servers) {
                    Ok(()) => tracing::info!("Set DNS servers on TUN interface: {}", dns_servers.join(", ")),
                    Err(e) => tracing::error!("Failed to set DNS servers on TUN interface: {}", e),
                }
            } else {
                tracing::warn!(
                    "This Windows version does not support per-interface DNS settings \
                     (SetInterfaceDnsSettings not found in iphlpapi.dll), skipping"
                );
            }
        }

        // Task 1: TUN → network (read from TUN, write to RWC)
        let device_read = device.clone();
        let rwc_read = rwc.clone();
        let read_handle = tokio::spawn(async move {
            tun_read_loop(device_read, rwc_read).await;
        });

        // Task 2: network → TUN (read from RWC directly into TUN; no intermediate queue)
        let device_write = device.clone();
        let rwc_write = rwc.clone();
        let write_handle = tokio::spawn(async move {
            tun_write_loop(device_write, rwc_write).await;
        });

        Ok(Self {
            device,
            name: tun_name,
            mtu: actual_mtu,
            read_handle,
            write_handle,
        })
    }

    /// Returns the actual name of the TUN network interface as seen by the OS.
    /// On macOS this is the kernel-assigned utunN when "auto" was requested.
    /// On NetBSD/OpenBSD this is the allocated tunN when "auto" was requested.
    /// On FreeBSD this is the alias after a successful rename (`ygg0` /
    /// `ygg{prefix}{port}` for `"auto"`, otherwise the configured if_name),
    /// or the allocated tunN if rename failed.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// MTU the interface ended up with.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Tear down the TUN adapter explicitly: abort the I/O tasks, wait for
    /// them to drop their `Arc<AsyncDevice>` references, then drop the device
    /// so the OS-level interface is removed before this function returns.
    ///
    /// On Windows this is critical when running as a service: the SCM may
    /// terminate the process shortly after we report `ServiceState::Stopped`,
    /// before tokio's runtime drop has a chance to abort the I/O tasks. If
    /// the Wintun adapter isn't closed by then, it gets orphaned in the
    /// device tree and the next startup can't recreate it.
    
    /// Assign additional CKR IP addresses (from legacy `ipv4_address` and `ip_addresses`)
    /// to an already running TUN interface. Called from main.rs after multicast
    /// to achieve the required startup ordering (Stage 2).
    /// Uses post-creation add_address_v* methods which are supported by tun_rs.
    #[cfg(feature = "ckr")]
    pub fn assign_ckr_ip_addresses(&self, ckr_config: &crate::config::TunnelRoutingConfig) -> Result<(), String> {
        if !ckr_config.enable {
            return Ok(());
        }

        // Legacy ipv4_address path (only if ip_addresses is empty)
        if !ckr_config.ipv4_address.is_empty() && ckr_config.ip_addresses.iter().all(|s| s.is_empty()) {
            let (v4_addr, v4_prefix) = parse_ipv4_cidr(&ckr_config.ipv4_address)?;
            self.device
                .add_address_v4(v4_addr, v4_prefix)
                .map_err(|e| format!("failed to add IPv4 address to TUN: {}", e))?;
            tracing::info!("CKR: assigning IPv4 address {} to TUN", ckr_config.ipv4_address);
        }

        let mut ipv4_addrs: Vec<(Ipv4Addr, u8)> = Vec::new();

        for cidr in &ckr_config.ip_addresses {
            if !cidr.is_empty() {
                if cidr.contains(':') {
                    // IPv6 path
                    let parts: Vec<&str> = cidr.split('/').collect();
                    if parts.len() == 1 || parts.len() == 2 {
                        let ip_str = parts[0];
                        let prefix: u8 = if parts.len() == 1 {
                            128
                        } else {
                            parts[1].parse().map_err(|e| format!("invalid IPv6 prefix in ip_addresses '{}': {}", cidr, e))?
                        };
                        let ip: Ipv6Addr = ip_str.parse().map_err(|e| format!("invalid IPv6 in ip_addresses '{}': {}", cidr, e))?;
                        self.device
                            .add_address_v6(ip, prefix)
                            .map_err(|e| format!("failed to add IPv6 address to TUN: {}", e))?;
                        tracing::info!("CKR: assigning IPv6 address {} to TUN", cidr);
                    } else {
                        return Err(format!("invalid IPv6 CIDR in ip_addresses '{}': expected addr or addr/prefix", cidr));
                    }
                } else {
                    // IPv4 path - reuse the exact existing parse_ipv4_cidr function
                    let (v4_addr, v4_prefix) = parse_ipv4_cidr(cidr)?;
                    ipv4_addrs.push((v4_addr, v4_prefix));
                    tracing::info!("CKR: assigning IPv4 address {} to TUN", cidr);
                }
            }
        }

        for (v4_addr, v4_prefix) in ipv4_addrs {
            self.device
                .add_address_v4(v4_addr, v4_prefix)
                .map_err(|e| format!("failed to add IPv4 address to TUN: {}", e))?;
        }

        Ok(())
    }

    pub async fn close(self) {
        let TunAdapter { device, name, mtu: _, read_handle, write_handle } = self;
        read_handle.abort();
        write_handle.abort();
        let _ = read_handle.await;
        let _ = write_handle.await;
        // Tasks have released their Arc clones; drop the last one so
        // AsyncDevice::Drop runs WintunCloseAdapter (or platform equivalent).
        //
        // On FreeBSD/GhostBSD and NetBSD the last close of /dev/tunN
        // only marks the clone interface down. The kernel keeps the iface
        // until SIOCIFDESTROY. tun-rs Drop may try destroy while
        // the fd is still open; that ioctl is then ignored or can stall.
        // Close the fd first, then destroy by name.
        drop(device);
        destroy_tun_interface(&name);
    }
}

/// BSD systems where a cloned TUN iface survives `close(/dev/tunN)`
/// and must be removed with `SIOCIFDESTROY` (`ifconfig tunN destroy`).
///
/// GhostBSD is `target_os = "freebsd"`. OpenBSD auto-destroys ifaces
/// created by opening `/dev/tunN`; a second destroy is then ENXIO/EINVAL
/// and is treated as success.
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
))]
fn destroy_tun_interface(name: &str) {
    if name.is_empty() {
        return;
    }

    match destroy_tun_interface_inner(name) {
        Ok(()) => {
            tracing::info!("Destroyed TUN interface '{}'", name);
        }
        Err(err) => {
            // Already gone: OpenBSD last-close destroy, or tun-rs Drop
            // managed to destroy before we got here.
            match err.raw_os_error() {
                Some(code) if code == libc::ENXIO || code == libc::ENODEV || code == libc::EINVAL => {
                    tracing::debug!("TUN interface '{}' already destroyed: {}", name, err);
                }
                _ => {
                    tracing::warn!("Failed to destroy TUN interface '{}': {}", name, err);
                }
            }
        }
    }
}

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
)))]
fn destroy_tun_interface(_name: &str) {}

/// `SIOCIFDESTROY` is `_IOW('i', 121, struct ifreq)` on FreeBSD,
/// NetBSD and OpenBSD. `libc` only exports the named constant
/// reliably on FreeBSD, so other targets build the request
/// from the same encoding and `size_of::<libc::ifreq>()`.
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
))]
fn siocifdestroy_request() -> libc::c_ulong {
    // SIOCIFDESTROY = _IOW('i', 121, struct ifreq) on FreeBSD/GhostBSD,
    // NetBSD, OpenBSD. Do not use libc::SIOCIFDESTROY: the named
    // constant is missing from some libc versions even on FreeBSD.
    const IOC_IN: libc::c_ulong = 0x8000_0000;
    const IOCPARM_MASK: libc::c_ulong = 0x1fff;
    let len = std::mem::size_of::<libc::ifreq>() as libc::c_ulong;
    IOC_IN | ((len & IOCPARM_MASK) << 16) | ((b'i' as libc::c_ulong) << 8) | 121
}

/// `SIOCSIFNAME` is `_IOW('i', 40, struct ifreq)` on FreeBSD.
/// Encoded the same way as `siocifdestroy_request` so we do not depend
/// on `libc::SIOCSIFNAME` being present.
#[cfg(any(target_os = "freebsd"))]
fn siocsifname_request() -> libc::c_ulong {
    const IOC_IN: libc::c_ulong = 0x8000_0000;
    const IOCPARM_MASK: libc::c_ulong = 0x1fff;
    let len = std::mem::size_of::<libc::ifreq>() as libc::c_ulong;
    IOC_IN | ((len & IOCPARM_MASK) << 16) | ((b'i' as libc::c_ulong) << 8) | 40
}

/// Copy `name` into `ifr_name` with a trailing NUL. Returns false if
/// the name is empty or does not fit in `IFNAMSIZ-1` bytes.
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
))]
fn fill_ifr_name(ifr: &mut libc::ifreq, name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let max = (libc::IFNAMSIZ as usize).saturating_sub(1);
    if bytes.len() > max {
        return false;
    }
    ifr.ifr_name[..bytes.len()].copy_from_slice(unsafe {
        // c_char is i8 on these targets; the bytes are ASCII ("tun0").
        &*(bytes as *const [u8] as *const [libc::c_char])
    });
    true
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
))]
fn destroy_tun_interface_inner(name: &str) -> std::io::Result<()> {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if !fill_ifr_name(&mut ifr, name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TUN interface name empty or longer than IFNAMSIZ-1",
        ));
    }

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let rc = unsafe { libc::ioctl(sock, siocifdestroy_request(), &mut ifr) };
    let ioctl_err = std::io::Error::last_os_error();
    unsafe { libc::close(sock) };

    if rc != 0 {
        Err(ioctl_err)
    } else {
        Ok(())
    }
}

/// Rename a cloned TUN iface (`tunN` → `ygg0` / `ygg{prefix}{port}`).
///
/// `ifr_name` is the current name; `ifr_ifru.ifru_data` points at a
/// NUL-terminated buffer with the new name (FreeBSD `SIOCSIFNAME`
/// convention).
#[cfg(any(target_os = "freebsd"))]
fn rename_tun_interface(current: &str, new_name: &str) -> std::io::Result<()> {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if !fill_ifr_name(&mut ifr, current) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current TUN interface name empty or longer than IFNAMSIZ-1",
        ));
    }

    let new_bytes = new_name.as_bytes();
    let max = (libc::IFNAMSIZ as usize).saturating_sub(1);
    if new_bytes.is_empty() || new_bytes.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "new TUN interface name empty or longer than IFNAMSIZ-1",
        ));
    }

    let mut new_buf = [0 as libc::c_char; libc::IFNAMSIZ as usize];
    new_buf[..new_bytes.len()].copy_from_slice(unsafe {
        // c_char is i8 on these targets; the bytes are ASCII.
        &*(new_bytes as *const [u8] as *const [libc::c_char])
    });

    ifr.ifr_ifru.ifru_data = new_buf.as_mut_ptr();

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let rc = unsafe { libc::ioctl(sock, siocsifname_request(), &mut ifr) };
    let ioctl_err = std::io::Error::last_os_error();
    unsafe { libc::close(sock) };

    if rc != 0 {
        Err(ioctl_err)
    } else {
        Ok(())
    }
}

/// Read packets from the TUN device and send them to the network via RWC.
async fn tun_read_loop(device: Arc<AsyncDevice>, rwc: Arc<ReadWriteCloser>) {
    let mut buf = vec![0u8; 65535];
    loop {
        match device.recv(&mut buf).await {
            Ok(n) if n > 0 => {
                if let Err(e) = rwc.write(&buf[..n]).await {
                    tracing::trace!("Unable to send packet to network: {}", e);
                }
            }
            Ok(_) => continue,
            Err(e) => {
                tracing::error!("TUN read error: {}", e);
                return;
            }
        }
    }
}

/// Returns true for transient TUN write failures caused by kernel buffer exhaustion
/// (ENOBUFS / WouldBlock, and EQFULL on Apple).
/// In these cases the packet should
/// be dropped instead of tearing down the write path.
#[cfg(unix)]
fn is_tun_write_overflow(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    match err.raw_os_error() {
        Some(code) if code == libc::ENOBUFS => true,
        // macOS-only: the interface output queue is full.
        #[cfg(target_vendor = "apple")]
        Some(code) if code == libc::EQFULL => true,
        _ => false,
    }
}

/// Windows counterpart: wintun reports a full ring buffer as ERROR_BUFFER_OVERFLOW,
/// which tun-rs translates into `ErrorKind::WouldBlock`. Its blocking send swallows
/// that internally and retries with backoff for 5 seconds before giving up with
/// `ErrorKind::TimedOut`, so in practice a full ring reaches us as the latter. A
/// disabled adapter surfaces as a different error, so it still tears down the loop.
#[cfg(not(unix))]
fn is_tun_write_overflow(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Read packets from the network (RWC) and write them straight into the TUN device.
async fn tun_write_loop(device: Arc<AsyncDevice>, rwc: Arc<ReadWriteCloser>) {
    // One byte larger than the largest payload: the session frame is read in
    // place, so it needs room for the leading session type byte too.
    let mut buf = vec![0u8; 65536];
    // Rate-limit overflow warnings so a sustained overload does not flood the log,
    // but count the drops in between so the warning says how bad it actually is.
    let mut last_overflow_log = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    let mut dropped_since_log: u64 = 0;
    const OVERFLOW_LOG_INTERVAL: Duration = Duration::from_secs(5);

    loop {
        match rwc.read(&mut buf).await {
            Ok(packet) => {
                tracing::debug!("TUN write {} bytes, version={:#x}", packet.len(), packet[0] >> 4);
                if let Err(e) = device.send(packet).await {
                    if is_tun_write_overflow(&e) {
                        // Drop on overflow: better to lose some packets under load
                        // than to stop delivering traffic entirely.
                        dropped_since_log += 1;
                        let now = Instant::now();
                        if now.duration_since(last_overflow_log) >= OVERFLOW_LOG_INTERVAL {
                            tracing::warn!(
                                "TUN write overflow, dropped {} packet(s) since last report: {}",
                                dropped_since_log,
                                e
                            );
                            last_overflow_log = now;
                            dropped_since_log = 0;
                        }
                        continue;
                    }
                    tracing::error!("TUN write error: {}", e);
                    return;
                }
            }
            Err(e) => {
                tracing::error!("Exiting TUN write loop due to RWC read error: {}", e);
                return;
            }
        }
    }
}

/// Parse an IPv4 CIDR string like "10.99.0.1/24" into (Ipv4Addr, prefix_len).
#[cfg(feature = "ckr")]
fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    let (addr_str, prefix_str) = if parts.len() == 1 {
        (parts[0], "32")
    } else if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        return Err(format!("invalid IPv4 CIDR '{}': expected addr or addr/prefix", cidr));
    };
    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|e| format!("invalid IPv4 address '{}': {}", addr_str, e))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| format!("invalid prefix length '{}': {}", prefix_str, e))?;
    if prefix > 32 {
        return Err(format!("prefix length {} exceeds 32", prefix));
    }
    Ok((addr, prefix))
}

#[cfg(windows)]
fn get_set_interface_dns_settings_ptr() -> Option<
    unsafe extern "system" fn(
        windows::core::GUID,
        *const windows::Win32::NetworkManagement::IpHelper::DNS_INTERFACE_SETTINGS,
    ) -> windows::core::HRESULT,
> {
    *SET_INTERFACE_DNS_PTR.get_or_init(|| {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        let dll_name: Vec<u16> = OsStr::new("iphlpapi.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let hmod_result = unsafe { GetModuleHandleW(windows::core::PCWSTR(dll_name.as_ptr())) };
        let hmod = match hmod_result {
            Ok(h) => h,
            Err(_) => return None,
        };
        if hmod.is_invalid() {
            return None;
        }

        let proc_name = b"SetInterfaceDnsSettings\0";
        let proc = unsafe { GetProcAddress(hmod, windows::core::PCSTR(proc_name.as_ptr())) };
        proc.map(|addr| unsafe { std::mem::transmute(addr) })
    })
}

#[cfg(windows)]
fn is_set_interface_dns_settings_supported() -> bool {
    get_set_interface_dns_settings_ptr().is_some()
}

#[cfg(windows)]
fn call_set_interface_dns_settings(
    guid: windows::core::GUID,
    settings: *const windows::Win32::NetworkManagement::IpHelper::DNS_INTERFACE_SETTINGS,
) -> windows::core::Result<()> {
    match get_set_interface_dns_settings_ptr() {
        Some(func) => {
            let hr = unsafe { func(guid, settings) };
            if hr.is_ok() {
                Ok(())
            } else {
                Err(windows::core::Error::from(hr))
            }
        }
        None => Err(windows::core::Error::from(
            windows::Win32::Foundation::ERROR_PROC_NOT_FOUND,
        )),
    }
}

/// Assign DNS servers to our TUN interface via `SetInterfaceDnsSettings`, and
/// disable dynamic DNS registration for it. Targets the adapter by the fixed
/// GUID we registered it with.
#[cfg(windows)]
fn set_interface_dns(servers: &[String]) -> Result<(), String> {
    use std::net::IpAddr;
    use std::str::FromStr;

    // Same GUID we registered the wintun adapter with (base + current address prefix).
    // tun-rs converts the u128 via GUID::from_u128, so this matches the interface GUID exactly.
    let guid = windows::core::GUID::from_u128(
        TUN_DEVICE_GUID_BASE.wrapping_add(crate::address::address_prefix() as u128),
    );

    // SetInterfaceDnsSettings configures one address family per call, and IPv6
    // nameservers require the DNS_SETTING_IPV6 flag — without it the addresses are
    // parsed as IPv4 and the call fails with ERROR_INVALID_PARAMETER. Split by family.
    let mut v4: Vec<&str> = Vec::new();
    let mut v6: Vec<&str> = Vec::new();
    for s in servers {
        match IpAddr::from_str(s) {
            Ok(IpAddr::V4(_)) => v4.push(s),
            Ok(IpAddr::V6(_)) => v6.push(s),
            Err(_) => tracing::warn!("Ignoring invalid DNS server address: {}", s),
        }
    }

    apply_interface_dns(guid, &v4, false)?;
    apply_interface_dns(guid, &v6, true)?;

    // Disable dynamic DNS registration for the mesh interface: registering this
    // interface's address with the mesh DNS servers is pointless and only produces
    // repeated failing DDNS attempts.
    set_interface_registration(guid, false)?;
    Ok(())
}

/// Enable or disable dynamic DNS (DDNS) registration of the interface's addresses.
#[cfg(windows)]
fn set_interface_registration(guid: windows::core::GUID, enabled: bool) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
        DNS_SETTING_REGISTRATION_ENABLED,
    };

    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_REGISTRATION_ENABLED as u64,
        RegistrationEnabled: if enabled { 1 } else { 0 },
        ..Default::default()
    };

    call_set_interface_dns_settings(guid, &settings as *const _)
        .map_err(|e| format!("SetInterfaceDnsSettings (registration): {}", e))
}

/// Set the nameserver list for a single address family on the interface.
/// `ipv6` selects the DNS_SETTING_IPV6 flag. No-op for an empty list.
#[cfg(windows)]
fn apply_interface_dns(guid: windows::core::GUID, addrs: &[&str], ipv6: bool) -> Result<(), String> {
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::IpHelper::{
        DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
        DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    };

    if addrs.is_empty() {
        return Ok(());
    }

    // Comma-separated, null-terminated UTF-16 nameserver list.
    // Must stay alive for the duration of the call below.
    let mut ns: Vec<u16> = addrs
        .join(",")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut flags = DNS_SETTING_NAMESERVER as u64;
    if ipv6 {
        flags |= DNS_SETTING_IPV6 as u64;
    }

    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: flags,
        NameServer: PWSTR(ns.as_mut_ptr()),
        ..Default::default()
    };

    call_set_interface_dns_settings(guid, &settings as *const _)
        .map_err(|e| format!("SetInterfaceDnsSettings (ipv6={}): {}", ipv6, e))
}

#[cfg(test)]
mod auto_name_tests {
    use super::auto_requested_name;

    #[test]
    fn auto_requested_name_windows() {
        if cfg!(windows) {
            assert_eq!(auto_requested_name(), "Yggdrasil");
        }
    }

    #[test]
    fn auto_requested_name_macos_or_bsd_is_empty() {
        if cfg!(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
        )) {
            assert!(
                auto_requested_name().is_empty(),
                "auto must not pass an explicit name on macOS/BSD"
            );
        }
    }

    #[test]
    fn auto_requested_name_linux_keeps_ygg0() {
        if cfg!(all(
            unix,
            not(target_os = "macos"),
            not(target_os = "freebsd"),
            not(target_os = "netbsd"),
            not(target_os = "openbsd"),
        )) {
            assert_eq!(auto_requested_name(), "ygg0");
        }
    }
}

#[cfg(test)]
mod tun_mtu_probe_tests {
    use super::probe_highest_mtu;

    #[test]
    fn keeps_floor_when_requested_is_not_higher() {
        let mut calls = Vec::new();
        let got = probe_highest_mtu(1500, 1500, |v| {
            calls.push(v);
            true
        });
        assert_eq!(got, 1500);
        assert!(calls.is_empty());
    }

    #[test]
    fn accepts_requested_when_kernel_allows_it() {
        let got = probe_highest_mtu(1500, 65535, |_| true);
        assert_eq!(got, 65535);
    }

    #[test]
    fn finds_stock_netbsd_tunmtu() {
        let got = probe_highest_mtu(1500, 65535, |v| v <= 1500);
        assert_eq!(got, 1500);
    }

    #[test]
    fn finds_stock_openbsd_tunmru() {
        let got = probe_highest_mtu(16384, 65535, |v| v <= 16384);
        assert_eq!(got, 16384);
    }

    #[test]
    fn finds_custom_kernel_cap_between_floor_and_requested() {
        // Custom NetBSD with TUNMTU raised to 9000, or OpenBSD with
        // TUNMRU raised to 32767 / 65535.
        assert_eq!(probe_highest_mtu(1500, 65535, |v| v <= 9000), 9000);
        assert_eq!(probe_highest_mtu(16384, 65535, |v| v <= 32767), 32767);
        assert_eq!(probe_highest_mtu(16384, 40000, |_| true), 40000);
    }

    #[test]
    fn never_asks_below_floor_or_above_requested() {
        let mut seen = Vec::new();
        let cap = 9000u16;
        let floor = 1500u16;
        let requested = 65535u16;
        let got = probe_highest_mtu(floor, requested, |v| {
            seen.push(v);
            v <= cap
        });
        assert_eq!(got, cap);
        assert!(seen.iter().all(|&v| v >= floor && v <= requested));
        assert_eq!(seen.first().copied(), Some(requested));
    }

    #[cfg(target_os = "netbsd")]
    #[test]
    fn netbsd_create_mtu_is_stock_1500() {
        assert_eq!(super::tun_create_mtu(65535), 1500);
        assert_eq!(super::tun_create_mtu(1280), 1280);
        assert_eq!(super::tun_create_mtu(1500), 1500);
    }

    #[cfg(target_os = "openbsd")]
    #[test]
    fn openbsd_create_mtu_is_stock_16384() {
        assert_eq!(super::tun_create_mtu(65535), 16384);
        assert_eq!(super::tun_create_mtu(1280), 1280);
        assert_eq!(super::tun_create_mtu(16384), 16384);
    }

    #[cfg(not(any(target_os = "netbsd", target_os = "openbsd")))]
    #[test]
    fn other_os_create_mtu_is_unchanged() {
        assert_eq!(super::tun_create_mtu(65535), 65535);
        assert_eq!(super::tun_create_mtu(1280), 1280);
    }
}

#[cfg(all(
    test,
    any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
    )
))]
mod bsd_destroy_tests {
    use super::{fill_ifr_name, siocifdestroy_request};

    #[test]
    fn fill_ifr_name_copies_ascii_and_keeps_nul() {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        assert!(fill_ifr_name(&mut ifr, "tun0"));
        assert_eq!(ifr.ifr_name[0] as u8, b't');
        assert_eq!(ifr.ifr_name[1] as u8, b'u');
        assert_eq!(ifr.ifr_name[2] as u8, b'n');
        assert_eq!(ifr.ifr_name[3] as u8, b'0');
        assert_eq!(ifr.ifr_name[4], 0);
    }

    #[test]
    fn fill_ifr_name_rejects_empty() {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        assert!(!fill_ifr_name(&mut ifr, ""));
    }

    #[test]
    fn fill_ifr_name_rejects_too_long() {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let too_long = "x".repeat(libc::IFNAMSIZ as usize);
        assert!(!fill_ifr_name(&mut ifr, &too_long));
    }

    #[test]
    fn siocifdestroy_request_is_iow_i_121() {
        const IOC_IN: libc::c_ulong = 0x8000_0000;
        const IOCPARM_MASK: libc::c_ulong = 0x1fff;
        let len = std::mem::size_of::<libc::ifreq>() as libc::c_ulong;
        let expected =
            IOC_IN | ((len & IOCPARM_MASK) << 16) | ((b'i' as libc::c_ulong) << 8) | 121;
        assert_eq!(siocifdestroy_request(), expected);
    }
}

#[cfg(all(test, any(target_os = "freebsd")))]
mod freebsd_alias_tests {
    use super::{
        linux_like_auto_tun_name_from, siocsifname_request,
    };

    #[test]
    fn default_alias_is_ygg0_without_prefix_port() {
        assert_eq!(linux_like_auto_tun_name_from(None), "ygg0");
    }

    #[test]
    fn alias_follows_linux_suffix_rule() {
        // Binary/symlink `ygg_0615001` → prefix 0x06, port 15001.
        assert_eq!(
            linux_like_auto_tun_name_from(Some((0x06, 15001))),
            "ygg0615001"
        );
        assert_eq!(
            linux_like_auto_tun_name_from(Some((0x02, 9001))),
            "ygg029001"
        );
    }

    #[test]
    fn alias_fits_ifnamsiz() {
        let name = linux_like_auto_tun_name_from(Some((0xfc, 65535)));
        assert_eq!(name, "yggfc65535");
        assert!(name.len() < libc::IFNAMSIZ as usize);
    }

    #[test]
    fn siocsifname_request_is_iow_i_40() {
        const IOC_IN: libc::c_ulong = 0x8000_0000;
        const IOCPARM_MASK: libc::c_ulong = 0x1fff;
        let len = std::mem::size_of::<libc::ifreq>() as libc::c_ulong;
        let expected =
            IOC_IN | ((len & IOCPARM_MASK) << 16) | ((b'i' as libc::c_ulong) << 8) | 40;
        assert_eq!(siocsifname_request(), expected);
    }

    #[test]
    fn explicit_if_name_is_used_as_alias_as_is() {
        // Non-"auto" if_name is the alias verbatim; it is not forced
        // through the ygg{prefix}{port} rule and need not start with "tun".
        assert_ne!(linux_like_auto_tun_name_from(None), "vpn0");
        assert_ne!(linux_like_auto_tun_name_from(Some((0x06, 15001))), "mesh");
        assert!(libc::IFNAMSIZ as usize > "vpn0".len());
        assert!(libc::IFNAMSIZ as usize > "ygg-mesh".len());
    }
}