//! Proxy support for WebSocket connections.
//!
//! Supports HTTP CONNECT and SOCKS5 proxies for enterprise environments
//! where direct connections to the EDR server are not possible.
//!
//! # Usage
//!
//! Configure a proxy via the `proxy_url` field in agent config:
//!
//! ```toml
//! [transport]
//! proxy_url = "http://proxy.corp.example.com:8080"
//! # or with authentication:
//! proxy_url = "http://user:password@proxy.corp.example.com:8080"
//! # or SOCKS5:
//! proxy_url = "socks5://proxy.corp.example.com:1080"
//! ```

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

/// Percent-decode a userinfo component (e.g. `p%40ss` -> `p@ss`).
///
/// Falls back to lossy UTF-8 for non-UTF-8 byte sequences. Invalid or
/// truncated `%` escapes are preserved verbatim.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Proxy configuration parsed from a URL string.
///
/// Supports HTTP CONNECT and SOCKS5 proxy protocols with optional
/// username/password authentication.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Parsed proxy URL (scheme determines protocol)
    pub url: Url,
    /// Optional username for proxy authentication
    pub username: Option<String>,
    /// Optional password for proxy authentication
    pub password: Option<String>,
}

impl ProxyConfig {
    /// Parse a proxy configuration from a URL string.
    ///
    /// Supported schemes: `http`, `https` (both use HTTP CONNECT), `socks5`.
    /// Credentials can be embedded in the URL: `http://user:pass@host:port`
    pub fn from_url(url_str: &str) -> Result<Self> {
        let url = Url::parse(url_str).context("Invalid proxy URL")?;
        // url::Url returns userinfo as percent-encoded ASCII; decode it so the
        // real credentials are used for Proxy-Authorization / SOCKS5 auth.
        let username = if url.username().is_empty() {
            None
        } else {
            Some(percent_decode(url.username()))
        };
        let password = url.password().map(percent_decode);
        Ok(Self {
            url,
            username,
            password,
        })
    }

    /// Connect through the proxy to the target host:port.
    ///
    /// Establishes a TCP connection to the proxy server, then negotiates
    /// a tunnel to the target using either HTTP CONNECT or SOCKS5 protocol
    /// depending on the proxy URL scheme.
    ///
    /// Returns a `TcpStream` that is tunneled through the proxy and ready
    /// for TLS upgrade and WebSocket handshake.
    pub async fn connect(&self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        let proxy_host = self.url.host_str().unwrap_or("127.0.0.1");
        let proxy_port = self.url.port().unwrap_or(8080);

        tracing::info!(
            proxy_host = proxy_host,
            proxy_port = proxy_port,
            target_host = target_host,
            target_port = target_port,
            scheme = self.url.scheme(),
            "Connecting through proxy"
        );

        let stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port))
            .await
            .context("Failed to connect to proxy server")?;

        match self.url.scheme() {
            "http" | "https" => self.http_connect(stream, target_host, target_port).await,
            "socks5" => self.socks5_connect(stream, target_host, target_port).await,
            scheme => bail!("Unsupported proxy scheme: {}", scheme),
        }
    }

    /// Perform HTTP CONNECT tunnel negotiation.
    ///
    /// Sends an HTTP CONNECT request to the proxy and waits for a 200 response,
    /// indicating the tunnel is established. Supports Basic proxy authentication
    /// if credentials are configured.
    async fn http_connect(
        &self,
        mut stream: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<TcpStream> {
        let mut request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            host, port, host, port
        );

        // Add proxy authentication if configured
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let credentials = STANDARD.encode(format!("{}:{}", user, pass));
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", credentials));
        }

        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .await
            .context("Failed to send HTTP CONNECT request to proxy")?;

        // Read response -- we need at least the status line
        let mut buf = [0u8; 1024];
        let n = stream
            .read(&mut buf)
            .await
            .context("Failed to read HTTP CONNECT response from proxy")?;

        if n == 0 {
            bail!("Proxy closed connection during HTTP CONNECT handshake");
        }

        let response = String::from_utf8_lossy(&buf[..n]);

        // Check for 200 status code
        if !response.contains("200") {
            let status_line = response.lines().next().unwrap_or("(empty response)");
            tracing::warn!(
                status = status_line,
                "HTTP CONNECT proxy rejected tunnel request"
            );
            bail!("HTTP CONNECT proxy rejected connection: {}", status_line);
        }

        tracing::debug!("HTTP CONNECT tunnel established through proxy");
        Ok(stream)
    }

    /// Perform SOCKS5 tunnel negotiation.
    ///
    /// Implements the SOCKS5 protocol (RFC 1928) with support for:
    /// - No authentication (method 0x00)
    /// - Username/password authentication (method 0x02, RFC 1929)
    /// - Domain name address type (0x03)
    async fn socks5_connect(
        &self,
        mut stream: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<TcpStream> {
        // --- Phase 1: Method negotiation ---
        let has_auth = self.username.is_some() && self.password.is_some();
        if has_auth {
            // Offer both NoAuth (0x00) and UserPass (0x02)
            stream
                .write_all(&[0x05, 0x02, 0x00, 0x02])
                .await
                .context("Failed to send SOCKS5 greeting")?;
        } else {
            // Offer only NoAuth (0x00)
            stream
                .write_all(&[0x05, 0x01, 0x00])
                .await
                .context("Failed to send SOCKS5 greeting")?;
        }

        let mut method_response = [0u8; 2];
        stream
            .read_exact(&mut method_response)
            .await
            .context("Failed to read SOCKS5 method response")?;

        if method_response[0] != 0x05 {
            bail!(
                "SOCKS5 proxy returned invalid version: {} (expected 5)",
                method_response[0]
            );
        }

        // --- Phase 2: Authentication (if requested by proxy) ---
        match method_response[1] {
            0x00 => {
                // No authentication required
                tracing::debug!("SOCKS5 proxy requires no authentication");
            }
            0x02 => {
                // Username/password authentication (RFC 1929)
                let user = self.username.as_deref().unwrap_or("");
                let pass = self.password.as_deref().unwrap_or("");

                if user.len() > 255 || pass.len() > 255 {
                    bail!("SOCKS5 username or password exceeds 255 bytes");
                }

                let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
                auth.push(0x01); // Auth sub-negotiation version
                auth.push(user.len() as u8);
                auth.extend_from_slice(user.as_bytes());
                auth.push(pass.len() as u8);
                auth.extend_from_slice(pass.as_bytes());

                stream
                    .write_all(&auth)
                    .await
                    .context("Failed to send SOCKS5 authentication")?;

                let mut auth_resp = [0u8; 2];
                stream
                    .read_exact(&mut auth_resp)
                    .await
                    .context("Failed to read SOCKS5 authentication response")?;

                if auth_resp[1] != 0x00 {
                    bail!(
                        "SOCKS5 proxy authentication failed (status: {})",
                        auth_resp[1]
                    );
                }

                tracing::debug!("SOCKS5 proxy authentication successful");
            }
            0xFF => {
                bail!("SOCKS5 proxy rejected all offered authentication methods");
            }
            method => {
                bail!(
                    "SOCKS5 proxy requires unsupported authentication method: 0x{:02X}",
                    method
                );
            }
        }

        // --- Phase 3: Connection request ---
        if host.len() > 255 {
            bail!("Target hostname exceeds 255 bytes for SOCKS5 domain address");
        }

        let mut connect_req = Vec::with_capacity(7 + host.len());
        connect_req.push(0x05); // SOCKS version
        connect_req.push(0x01); // CMD: CONNECT
        connect_req.push(0x00); // Reserved
        connect_req.push(0x03); // ATYP: DOMAINNAME
        connect_req.push(host.len() as u8);
        connect_req.extend_from_slice(host.as_bytes());
        connect_req.push((port >> 8) as u8); // Port high byte
        connect_req.push((port & 0xFF) as u8); // Port low byte

        stream
            .write_all(&connect_req)
            .await
            .context("Failed to send SOCKS5 connect request")?;

        // --- Phase 4: Read connect response ---
        let mut resp_header = [0u8; 4];
        stream
            .read_exact(&mut resp_header)
            .await
            .context("Failed to read SOCKS5 connect response")?;

        if resp_header[0] != 0x05 {
            bail!(
                "SOCKS5 connect response has invalid version: {}",
                resp_header[0]
            );
        }

        if resp_header[1] != 0x00 {
            let reason = match resp_header[1] {
                0x01 => "general SOCKS server failure",
                0x02 => "connection not allowed by ruleset",
                0x03 => "network unreachable",
                0x04 => "host unreachable",
                0x05 => "connection refused",
                0x06 => "TTL expired",
                0x07 => "command not supported",
                0x08 => "address type not supported",
                _ => "unknown error",
            };
            bail!(
                "SOCKS5 connect failed: {} (code: 0x{:02X})",
                reason,
                resp_header[1]
            );
        }

        // Skip the bound address in the response (BND.ADDR + BND.PORT)
        match resp_header[3] {
            0x01 => {
                // IPv4: 4 bytes address + 2 bytes port
                let mut skip = [0u8; 6];
                stream
                    .read_exact(&mut skip)
                    .await
                    .context("Failed to read SOCKS5 bound IPv4 address")?;
            }
            0x03 => {
                // Domain: 1 byte length + N bytes domain + 2 bytes port
                let mut len_buf = [0u8; 1];
                stream
                    .read_exact(&mut len_buf)
                    .await
                    .context("Failed to read SOCKS5 bound domain length")?;
                let mut skip = vec![0u8; len_buf[0] as usize + 2];
                stream
                    .read_exact(&mut skip)
                    .await
                    .context("Failed to read SOCKS5 bound domain address")?;
            }
            0x04 => {
                // IPv6: 16 bytes address + 2 bytes port
                let mut skip = [0u8; 18];
                stream
                    .read_exact(&mut skip)
                    .await
                    .context("Failed to read SOCKS5 bound IPv6 address")?;
            }
            atyp => {
                bail!("SOCKS5 unsupported bound address type: 0x{:02X}", atyp);
            }
        }

        tracing::debug!("SOCKS5 tunnel established through proxy");
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_proxy() {
        let proxy = ProxyConfig::from_url("http://proxy.example.com:8080").unwrap();
        assert_eq!(proxy.url.scheme(), "http");
        assert_eq!(proxy.url.host_str(), Some("proxy.example.com"));
        assert_eq!(proxy.url.port(), Some(8080));
        assert!(proxy.username.is_none());
        assert!(proxy.password.is_none());
    }

    #[test]
    fn test_parse_socks5_proxy() {
        let proxy = ProxyConfig::from_url("socks5://localhost:1080").unwrap();
        assert_eq!(proxy.url.scheme(), "socks5");
        assert_eq!(proxy.url.host_str(), Some("localhost"));
        assert_eq!(proxy.url.port(), Some(1080));
    }

    #[test]
    fn test_parse_proxy_with_auth() {
        let proxy = ProxyConfig::from_url("http://user:p%40ss@proxy.example.com:3128").unwrap();
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("p@ss"));
    }

    #[test]
    fn test_invalid_proxy_url() {
        let result = ProxyConfig::from_url("not a url");
        assert!(result.is_err());
    }
}
