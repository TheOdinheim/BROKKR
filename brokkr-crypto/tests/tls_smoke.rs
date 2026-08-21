//! Live mTLS smoke test for the wolfSSL TLS client (Phase 12).
//!
//! `#[ignore]` — requires the nginx mTLS gateway on `localhost:8443` and the dev certs under
//! `~/BROKKR/certs/`. Run explicitly:
//!
//! ```text
//! cargo test -p brokkr-crypto --test tls_smoke -- --ignored --nocapture
//! ```

use brokkr_crypto::{TlsClient, TlsConfig};

fn certs_dir() -> String {
    // ~/BROKKR/certs — resolved from HOME so the path is not machine-specific in the source.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/jerem".to_string());
    format!("{home}/BROKKR/certs")
}

fn dev_config() -> TlsConfig {
    let c = certs_dir();
    TlsConfig {
        host: "127.0.0.1".to_string(),
        port: 8443,
        ca_file: format!("{c}/ca.crt"),
        client_cert_file: format!("{c}/client.crt"),
        client_key_file: format!("{c}/client.key"),
    }
}

#[test]
#[ignore = "requires the live nginx mTLS gateway on localhost:8443"]
fn mtls_handshake_reads_negotiated_group() {
    let mut client = TlsClient::connect(&dev_config()).expect("mTLS handshake to the gateway");

    // The negotiated group is a real fact read from the live session.
    let group = client.negotiated_group();
    println!("negotiated group: {group:?}");
    assert!(group.is_some(), "wolfSSL reported a negotiated group name");

    // A minimal real request through the gateway to ollama, proving read/write over the channel.
    let req = concat!(
        "GET /api/tags HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Connection: close\r\n",
        "\r\n"
    );
    client.write_all(req.as_bytes()).expect("write request");
    let resp = client.read_until_close().expect("read response");
    let text = String::from_utf8_lossy(&resp);
    println!("response bytes: {}", resp.len());
    assert!(text.starts_with("HTTP/1.1"), "got an HTTP response");
    assert!(text.contains("llama3.2"), "ollama tags mention the model");
}
