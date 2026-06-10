//! HTTP server for Prometheus metrics endpoint
//!
//! Exposes metrics on http://0.0.0.0:9090/metrics for Prometheus scraping

use crate::metrics::METRICS;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// Start the metrics HTTP server
pub async fn start_metrics_server(port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(&addr).await?;

    info!("Prometheus metrics server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((mut stream, peer_addr)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&mut stream, peer_addr).await {
                        error!("Failed to handle metrics request from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = [0u8; 4096];
    let n = stream.read(&mut buffer).await?;

    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..n]);

    // Parse HTTP request
    if !request.starts_with("GET") {
        let response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // Check if requesting /metrics
    if request.contains("GET /metrics") {
        // Gather metrics
        let metrics = METRICS.read().await.gather()?;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
            metrics.len(),
            metrics
        );

        stream.write_all(response.as_bytes()).await?;
        info!("Served metrics to {}", peer_addr);
    } else if request.contains("GET /health") {
        // Health check endpoint
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK\n";
        stream.write_all(response.as_bytes()).await?;
    } else {
        let response = "HTTP/1.1 404 Not Found\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_endpoint() {
        // Spawn server in background
        tokio::spawn(async {
            let _ = start_metrics_server(19090).await;
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Make HTTP request
        let client = reqwest::Client::new();
        let response = client
            .get("http://127.0.0.1:19090/metrics")
            .send()
            .await;

        if let Ok(resp) = response {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.unwrap();
            assert!(body.contains("tamandua_agent_info"));
        }
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        tokio::spawn(async {
            let _ = start_metrics_server(19091).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = reqwest::Client::new();
        let response = client.get("http://127.0.0.1:19091/health").send().await;

        if let Ok(resp) = response {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.unwrap();
            assert_eq!(body, "OK\n");
        }
    }
}
