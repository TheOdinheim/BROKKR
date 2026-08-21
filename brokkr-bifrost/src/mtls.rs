//! The real mTLS transport to a model endpoint (Phase 12) — **the wire**.
//!
//! Phase 8.5 built BIFRÖST as pure clearance logic and treated the negotiated group as an *input*.
//! This module supplies that input for real, and carries the model call itself: it opens a
//! wolfSSL TLS 1.3 mutual-auth connection to the gateway (via [`brokkr_crypto::TlsClient`], the
//! sole crate permitted `unsafe`), reads the **actually negotiated** key-exchange group, and — for
//! the model call — writes an HTTP request and reads the response.
//!
//! **Why the transport lives here (I-6).** *"There is no path from `brokkr-reasoner` to a network
//! socket that does not pass through BIFRÖST."* So the socket to the model belongs to BIFRÖST;
//! MÍMIR's backend (Phase 10) reaches the model **through** [`MtlsTransport::round_trip`], never a
//! socket of its own. BIFRÖST is the guarded crossing; this is the crossing.
//!
//! **No `unsafe` here.** All FFI is inside `brokkr-crypto`; this module calls its safe wrapper.

use brokkr_core::classification::{ChannelStrength, NamedGroup};
use brokkr_crypto::{TlsClient, TlsConfig, TlsError};

/// Gateway connection parameters (address + mTLS material, all PEM files). Mirrors
/// [`brokkr_crypto::TlsConfig`]; kept as a distinct BIFRÖST type so callers depend on BIFRÖST, not
/// on the crypto backend's shape.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub host: String,
    pub port: u16,
    pub ca_file: String,
    pub client_cert_file: String,
    pub client_key_file: String,
}

impl GatewayConfig {
    fn to_tls(&self) -> TlsConfig {
        TlsConfig {
            host: self.host.clone(),
            port: self.port,
            ca_file: self.ca_file.clone(),
            client_cert_file: self.client_cert_file.clone(),
            client_key_file: self.client_key_file.clone(),
        }
    }
}

/// The result of a real handshake: the raw negotiated group name (the truth) and the
/// [`NamedGroup`] it projects to (what the clearance decision consumes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The exact string `wolfSSL_get_curve_name` reported (e.g. `"SECP256R1"`,
    /// `"SECP384R1_MLKEM1024"`). The source of truth.
    pub raw_name: String,
    /// The projection onto core's closed [`NamedGroup`] vocabulary, chosen so that
    /// [`ChannelStrength::from_group`] yields the correct strength. **Lossy for classical curves
    /// outside the vocabulary** (see [`map_group`]).
    pub group: NamedGroup,
}

impl Negotiated {
    /// The channel strength implied by the projected group.
    pub fn strength(&self) -> ChannelStrength {
        ChannelStrength::from_group(self.group)
    }
}

/// Why a transport operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The TLS handshake or I/O failed. Carries the underlying [`TlsError`].
    Tls(TlsError),
    /// The handshake succeeded but wolfSSL reported no negotiated group name.
    NoGroup,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bifrost transport error: {self:?}")
    }
}
impl std::error::Error for TransportError {}

/// Project a raw wolfSSL group name onto core's closed [`NamedGroup`] vocabulary.
///
/// The match is on the **uppercased** name. PQC-hybrid groups map exactly; every classical curve
/// (X25519, secp256r1, secp384r1, …) maps to a **classical** `NamedGroup` so that
/// [`ChannelStrength::from_group`] returns [`ChannelStrength::Classical`]. The channel-strength
/// decision is therefore always correct; the *label* is lossy where the raw curve has no exact
/// `NamedGroup` variant (e.g. `SECP256R1` projects to `Secp384r1`). The exact name is preserved in
/// [`Negotiated::raw_name`]; closing the label gap would need a core `NamedGroup` addition
/// (out of scope for Phase 12).
pub fn map_group(raw_name: &str) -> NamedGroup {
    let u = raw_name.to_ascii_uppercase();
    if u.contains("MLKEM1024") || u.contains("ML_KEM_1024") {
        NamedGroup::Secp384r1MlKem1024
    } else if u.contains("MLKEM768") || u.contains("ML_KEM_768") {
        NamedGroup::X25519MlKem768
    } else if u.contains("25519") {
        NamedGroup::X25519
    } else {
        // Any other classical curve (SECP256R1, SECP384R1, …): classical by strength; labeled with
        // the classical EC variant. `raw_name` holds the truth.
        NamedGroup::Secp384r1
    }
}

/// The mTLS transport BIFRÖST owns. Holds only configuration; each operation opens its own
/// connection (no pooling in Phase 12, §4).
pub struct MtlsTransport {
    cfg: GatewayConfig,
}

impl MtlsTransport {
    pub fn new(cfg: GatewayConfig) -> Self {
        Self { cfg }
    }

    /// Handshake, read the negotiated group, and drop the connection. Used to learn the channel
    /// fact **before** the clearance decision (the orchestrator bakes [`Negotiated::group`] into
    /// the crossing's `Destination::Reasoner`, and HÚÐ's condition 8 collapses the effective
    /// authorization accordingly).
    pub fn negotiate(&self) -> Result<Negotiated, TransportError> {
        let client = TlsClient::connect(&self.cfg.to_tls()).map_err(TransportError::Tls)?;
        let raw_name = client.negotiated_group().ok_or(TransportError::NoGroup)?;
        let group = map_group(&raw_name);
        Ok(Negotiated { raw_name, group })
    }

    /// The model crossing (I-6): open a connection, write `request`, read the full response until
    /// the peer closes. `request` is the caller's already-formatted HTTP request (MÍMIR formats
    /// the ollama POST); BIFRÖST carries the bytes and returns the raw response.
    pub fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut client = TlsClient::connect(&self.cfg.to_tls()).map_err(TransportError::Tls)?;
        client.write_all(request).map_err(TransportError::Tls)?;
        client.read_until_close().map_err(TransportError::Tls)
    }
}
