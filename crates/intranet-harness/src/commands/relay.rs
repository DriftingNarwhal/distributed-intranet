//! Relay node subcommand — Core Protocol Spec §5.2–5.5.

use super::{CliResult, parse_network, resolve_identity};
use clap::Args;
use intranet_transport::{NodeEvent, RelayNode};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Args)]
pub struct RelayArgs {
    /// BIP-39 backup phrase for the relay's master seed.
    #[arg(long, conflicts_with = "seed")]
    phrase: Option<String>,
    /// Deterministic seed byte, for reproducible scenarios.
    #[arg(long)]
    seed: Option<u8>,
    /// Network identifier, as hex or a small integer.
    #[arg(long)]
    network: String,
    /// Addresses to listen on. Repeatable; defaults to dual-stack TCP and QUIC.
    #[arg(long = "listen")]
    listen: Vec<String>,
    /// Port for the health and peer-id endpoint.
    #[arg(long, default_value_t = 8080)]
    health_port: u16,
}

/// What the health endpoint currently reports.
#[derive(Clone)]
struct Health {
    ready: bool,
    peer_id: Option<String>,
}

impl RelayArgs {
    pub async fn run(self) -> CliResult {
        // §5.4: serve health checks *before* the node is fully initialized,
        // returning a placeholder until setup completes. Otherwise a slow boot
        // is indistinguishable from a failed deployment to a hosting platform's
        // health check, which is a cheap mistake to avoid and an annoying one to
        // debug.
        let health = Arc::new(Mutex::new(Health {
            ready: false,
            peer_id: None,
        }));
        spawn_health_endpoint(self.health_port, Arc::clone(&health));

        let network = parse_network(&self.network)?;
        let identity = resolve_identity(self.phrase.as_deref(), self.seed, &network)?;
        let mut relay = RelayNode::new(&identity).map_err(|e| e.to_string())?;
        let peer_id = relay.peer_id().to_string();

        if self.listen.is_empty() {
            relay.listen_default().map_err(|e| e.to_string())?;
        } else {
            for address in &self.listen {
                let address = address
                    .parse()
                    .map_err(|e| format!("bad listen address '{address}': {e}"))?;
                relay.listen_on(address).map_err(|e| e.to_string())?;
            }
        }

        {
            let mut guard = health.lock().expect("health lock");
            guard.ready = true;
            guard.peer_id = Some(peer_id.clone());
        }

        // §5.4: expose the peer id over an out-of-band verifiable channel, so a
        // client adding this relay as a bootstrap candidate can confirm it is
        // reaching the relay it intends to rather than an impersonator.
        println!("peer-id: {peer_id}");
        println!("health-port: {}", self.health_port);

        loop {
            tokio::select! {
                event = relay.next_event() => match event {
                    NodeEvent::Listening(address) => {
                        println!("listening: {address}/p2p/{peer_id}");
                    }
                    NodeEvent::Connected { peer, tier, .. } => {
                        println!("connected: peer={peer} tier={}", tier.label());
                    }
                    NodeEvent::Disconnected { peer } => {
                        println!("disconnected: peer={peer}");
                    }
                    _ => {}
                },
                _ = tokio::signal::ctrl_c() => {
                    println!("shutting down");
                    // §5.4: a relay persists no state across restarts by
                    // design, so there is deliberately nothing to flush here.
                    return Ok(());
                }
            }
        }
    }
}

/// A deliberately tiny HTTP responder for health and peer-id checks.
///
/// Hand-rolled rather than pulling in a web framework: it answers two questions
/// with fixed strings, and a relay is meant to be cheap and disposable.
fn spawn_health_endpoint(port: u16, health: Arc<Mutex<Health>>) {
    tokio::spawn(async move {
        let Ok(listener) = tokio::net::TcpListener::bind(("0.0.0.0", port)).await else {
            eprintln!("warning: could not bind health port {port}");
            return;
        };
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            let snapshot = health.lock().expect("health lock").clone();

            let mut buffer = [0u8; 1024];
            let read = socket.read(&mut buffer).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]);
            let wants_peer_id = request.contains("/peer-id");

            let body = if wants_peer_id {
                match &snapshot.peer_id {
                    Some(peer_id) => format!("{{\"peer_id\":\"{peer_id}\"}}"),
                    None => "{\"peer_id\":null}".to_string(),
                }
            } else if snapshot.ready {
                "{\"status\":\"ready\"}".to_string()
            } else {
                "{\"status\":\"starting\"}".to_string()
            };

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
}
