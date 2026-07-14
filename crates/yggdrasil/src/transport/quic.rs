//! QUIC transport primitives (quic://), matching yggdrasil-go's link_quic.go.
//!
//! Each connection carries a single bidirectional stream, exposed as a plain
//! `AsyncRead + AsyncWrite` byte stream for the Yggdrasil handshake.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Match yggdrasil-go: MaxIdleTimeout = 1 minute, KeepAlivePeriod = 20 seconds.
fn quic_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(60).try_into().expect("valid idle timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    transport
}

fn is_unreachable_error(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("host unreachable")
        || lower.contains("no route to host")
        || lower.contains("network is unreachable")
}

/// Strip IPv6 brackets from a URL host for use as a QUIC/TLS server name.
fn bare_host(url: &Url) -> Result<String, String> {
    let host = url.host_str().ok_or("missing host")?;
    Ok(host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string())
}

/// First certificate the peer presented during the QUIC TLS handshake,
/// for cert/identity binding in `handle_connection`.
fn peer_cert_of(connection: &quinn::Connection) -> Option<CertificateDer<'static>> {
    connection
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?
        .first()
        .cloned()
}

/// Dial a QUIC peer, opening a single bidirectional stream.
pub(crate) async fn quic_connect(
    url: &Url,
    client_config: Arc<rustls::ClientConfig>,
) -> Result<QuicStream, String> {
    let host = bare_host(url)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "missing port".to_string())?;

    // Resolve all addresses, keeping both AAAA/A records.
    let target = format!("{}:{}", host, port);
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host(&target)
        .await
        .map_err(|e| format!("address resolution failed for {}: {}", target, e))?
        .collect();
    if addrs.is_empty() {
        return Err("no address resolved".to_string());
    }
    addrs.sort_unstable();
    addrs.dedup();

    let (v6_addrs, v4_addrs): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv6());
    let mut attempt_addrs = v6_addrs.clone();
    attempt_addrs.extend(v4_addrs.clone());

    let quic_client_config = Arc::new(
        QuicClientConfig::try_from(client_config)
            .map_err(|e| format!("QUIC client config: {}", e))?,
    );
    let transport_config = Arc::new(quic_transport_config());

    // Try IPv6 first, then IPv4. On explicit v6 unreachable errors, ensure we
    // still attempt IPv4 before failing.
    let mut last_err = String::from("no address resolved");
    let mut forced_v4_fallback = false;
    let mut tried = Vec::new();
    let mut idx = 0usize;
    while idx < attempt_addrs.len() {
        let remote_addr = attempt_addrs[idx];
        idx += 1;
        tried.push(remote_addr);

        let mut client_config = quinn::ClientConfig::new(quic_client_config.clone());
        client_config.transport_config(transport_config.clone());

        let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let mut endpoint = match quinn::Endpoint::client(bind_addr) {
            Ok(e) => e,
            Err(e) => {
                last_err = format!("QUIC endpoint: {}", e);
                continue;
            }
        };
        endpoint.set_default_client_config(client_config);

        let connecting = match endpoint.connect(remote_addr, &host) {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("QUIC connect: {}", e);
                if remote_addr.is_ipv6()
                    && !v4_addrs.is_empty()
                    && is_unreachable_error(&last_err)
                    && !forced_v4_fallback
                {
                    forced_v4_fallback = true;
                    attempt_addrs = v4_addrs.clone();
                    idx = 0;
                }
                continue;
            }
        };

        // Per-address timeout so we quickly fall through to the next address.
        let connection = match tokio::time::timeout(Duration::from_secs(5), connecting).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                last_err = format!("QUIC connection to {} failed: {}", remote_addr, e);
                if remote_addr.is_ipv6()
                    && !v4_addrs.is_empty()
                    && is_unreachable_error(&last_err)
                    && !forced_v4_fallback
                {
                    forced_v4_fallback = true;
                    attempt_addrs = v4_addrs.clone();
                    idx = 0;
                }
                continue;
            }
            Err(_) => {
                last_err = format!("QUIC connection to {} timed out", remote_addr);
                continue;
            }
        };

        // Open a single bidirectional stream (matching yggdrasil-go: OpenStreamSync).
        let (send, recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                last_err = format!("QUIC open stream to {}: {}", remote_addr, e);
                continue;
            }
        };

        let peer_cert = peer_cert_of(&connection);
        return Ok(QuicStream {
            send,
            recv,
            remote_addr,
            peer_cert,
            _connection: connection,
            _endpoint: Some(endpoint),
            _permit: None,
        });
    }

    Err(format!(
        "{} (tried: {})",
        last_err,
        tried
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Start a QUIC listener, spawning an accept loop that feeds a channel.
///
/// `limiter` is the global incoming-connection semaphore shared with the TCP
/// listeners. A permit is claimed *before* the TLS handshake runs (matching
/// the TCP path) and rides inside the resulting `QuicStream`, so it is held
/// for the lifetime of the connection and released on drop.
pub(crate) async fn quic_listen(
    bind_addr: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    limiter: Arc<Semaphore>,
) -> Result<QuicListener, String> {
    let quic_server_config = QuicServerConfig::try_from(server_config)
        .map_err(|e| format!("QUIC server config: {}", e))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(quic_transport_config()));

    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .map_err(|e| format!("QUIC server bind: {}", e))?;

    let local_addr = endpoint
        .local_addr()
        .map_err(|e| format!("local_addr: {}", e))?;

    let (tx, rx) = mpsc::channel::<QuicStream>(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let endpoint_clone = endpoint.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => {
                    endpoint_clone.close(0u32.into(), b"shutdown");
                    break;
                }
                incoming = endpoint_clone.accept() => {
                    let Some(incoming) = incoming else { break };

                    // Claim a connection permit before doing any handshake work,
                    // so unauthenticated endpoints can't pin unbounded resources.
                    let permit = match limiter.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::warn!(
                                "Rejected QUIC connection from {} (too many concurrent connections)",
                                incoming.remote_address()
                            );
                            incoming.refuse();
                            continue;
                        }
                    };

                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let connection = match incoming.await {
                            Ok(conn) => conn,
                            Err(e) => {
                                tracing::debug!("QUIC accept failed: {}", e);
                                return;
                            }
                        };
                        let remote_addr = connection.remote_address();

                        // Accept a single bidirectional stream (matching yggdrasil-go: AcceptStream).
                        let (send, recv) = match connection.accept_bi().await {
                            Ok(streams) => streams,
                            Err(e) => {
                                tracing::debug!("QUIC accept stream failed: {}", e);
                                connection.close(1u32.into(), format!("stream error: {}", e).as_bytes());
                                return;
                            }
                        };

                        let peer_cert = peer_cert_of(&connection);
                        // Server side: the endpoint is owned by the QuicListener,
                        // so the per-connection stream doesn't carry one.
                        let _ = tx
                            .send(QuicStream {
                                send,
                                recv,
                                remote_addr,
                                peer_cert,
                                _connection: connection,
                                _endpoint: None,
                                _permit: Some(permit),
                            })
                            .await;
                    });
                }
            }
        }
    });

    Ok(QuicListener {
        local_addr,
        rx: Mutex::new(rx),
        cancel,
        _endpoint: endpoint,
    })
}

/// A QUIC listener. Dropping it (or calling `close`) shuts down the endpoint
/// and all of its connections.
pub(crate) struct QuicListener {
    local_addr: SocketAddr,
    rx: Mutex<mpsc::Receiver<QuicStream>>,
    cancel: CancellationToken,
    _endpoint: quinn::Endpoint,
}

impl QuicListener {
    pub(crate) async fn accept(&self) -> Result<QuicStream, String> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| "QUIC listener closed".to_string())
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn close(&self) {
        self.cancel.cancel();
    }
}

/// Wraps a QUIC bidirectional stream as AsyncRead + AsyncWrite, keeping the
/// connection (and, on the client side, the endpoint) alive. Incoming streams
/// also hold their connection-limiter permit for the connection's lifetime.
pub(crate) struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    remote_addr: SocketAddr,
    peer_cert: Option<CertificateDer<'static>>,
    _connection: quinn::Connection,
    _endpoint: Option<quinn::Endpoint>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl QuicStream {
    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub(crate) fn peer_cert(&self) -> Option<&CertificateDer<'static>> {
        self.peer_cert.as_ref()
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tls;
    use ed25519_dalek::SigningKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let material = tls::generate_self_signed_cert(&signing_key).unwrap();
        let server = tls::create_server_config(
            material.cert_chain(),
            material.private_key().unwrap(),
        )
        .unwrap();
        let client = tls::create_client_config(
            material.cert_chain(),
            material.private_key().unwrap(),
        )
        .unwrap();
        (server, client)
    }

    /// Loopback connect + byte round-trip, including peer cert extraction.
    #[tokio::test]
    async fn test_quic_roundtrip() {
        let (server_config, client_config) = test_configs();
        let limiter = Arc::new(Semaphore::new(4));
        let listener = quic_listen("127.0.0.1:0".parse().unwrap(), server_config, limiter)
            .await
            .expect("listen");

        let url = Url::parse(&format!("quic://{}", listener.local_addr())).unwrap();
        // The QUIC stream only materializes on the wire once the initiator
        // sends data (quinn's open_bi is local, like Go's OpenStreamSync), so
        // the server's accept_bi — and therefore listener.accept() — cannot
        // complete until the client writes. Connect AND write in one arm.
        let (client_stream, server_stream) = tokio::join!(
            async {
                let mut c = quic_connect(&url, client_config).await?;
                c.write_all(b"hello quic")
                    .await
                    .map_err(|e| e.to_string())?;
                c.flush().await.map_err(|e| e.to_string())?;
                Ok::<_, String>(c)
            },
            listener.accept(),
        );
        let mut client_stream = client_stream.expect("connect");
        let mut server_stream = server_stream.expect("accept");

        // Both sides should see the other's certificate (mutual TLS).
        assert!(client_stream.peer_cert().is_some(), "client sees server cert");
        assert!(server_stream.peer_cert().is_some(), "server sees client cert");

        let mut buf = [0u8; 10];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello quic");

        server_stream.write_all(b"pong").await.unwrap();
        server_stream.flush().await.unwrap();
        let mut back = [0u8; 4];
        client_stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");

        listener.close();
    }

    /// With no permits available the listener must refuse before handshaking.
    #[tokio::test]
    async fn test_quic_connection_limit() {
        let (server_config, client_config) = test_configs();
        let limiter = Arc::new(Semaphore::new(0));
        let listener = quic_listen("127.0.0.1:0".parse().unwrap(), server_config, limiter)
            .await
            .expect("listen");

        let url = Url::parse(&format!("quic://{}", listener.local_addr())).unwrap();
        let result = quic_connect(&url, client_config).await;
        assert!(result.is_err(), "connection must be refused when limiter is exhausted");

        listener.close();
    }
}
