//! Data classification, TLS named groups, channel strength, and the effective-
//! authorization calculation that BIFRÖST (Phase 8.5) will drive (BROKKR-ARCH 6.10).
//!
//! No crypto is performed here; these are the *facts* the barrier reasons over.

/// Data sensitivity tier. Ordered ascending: `Public < Internal < Cui < Secret`,
/// so [`core::cmp::min`] yields the lesser (more restrictive-to-exceed) tier used
/// by [`effective_authorization`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Classification {
    Public,
    Internal,
    Cui,
    Secret,
}

/// A TLS key-exchange named group. The codepoint is the IANA/wolfSSL group number
/// — a typed value, never a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamedGroup {
    /// Classical X25519.
    X25519,
    /// Classical secp384r1.
    Secp384r1,
    /// PQC-hybrid, 768-class. wolfSSL group 4588. Enhanced target.
    X25519MlKem768,
    /// PQC-hybrid, 1024-class. wolfSSL group 4589. High-Assurance target.
    Secp384r1MlKem1024,
}

impl NamedGroup {
    /// The IANA/wolfSSL codepoint for this group.
    pub fn code_point(&self) -> u16 {
        match self {
            NamedGroup::X25519 => 0x001d,
            NamedGroup::Secp384r1 => 0x0018,
            NamedGroup::X25519MlKem768 => 0x11ec,     // 4588
            NamedGroup::Secp384r1MlKem1024 => 0x11ed, // 4589
        }
    }

    /// True iff this group carries a PQC key-encapsulation (ML-KEM hybrid).
    pub fn is_pqc_hybrid(&self) -> bool {
        matches!(
            self,
            NamedGroup::X25519MlKem768 | NamedGroup::Secp384r1MlKem1024
        )
    }
}

/// Channel strength, derived from the *actually negotiated* group — never from an
/// offered list (BROKKR-ARCH 6.10: only facts reach the gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelStrength {
    /// Classical only (no ML-KEM). HNDL-exposed above Public (OQGF-I-2).
    Classical,
    /// PQC-hybrid, 768-class (X25519MLKEM768). Enhanced.
    PqcHybrid768,
    /// PQC-hybrid, 1024-class (SECP384R1MLKEM1024). High-Assurance.
    PqcHybrid1024,
}

impl ChannelStrength {
    /// Derive channel strength from the negotiated named group.
    pub fn from_group(group: NamedGroup) -> Self {
        match group {
            NamedGroup::X25519 | NamedGroup::Secp384r1 => ChannelStrength::Classical,
            NamedGroup::X25519MlKem768 => ChannelStrength::PqcHybrid768,
            NamedGroup::Secp384r1MlKem1024 => ChannelStrength::PqcHybrid1024,
        }
    }

    /// The highest classification this channel may carry. A classical channel is
    /// HNDL-exposed, so it caps at Public; a PQC-hybrid channel is quantum-safe and
    /// may carry up to Secret (OQGF-I-1/I-2, BROKKR-ARCH 6.10).
    pub fn permits(&self) -> Classification {
        match self {
            ChannelStrength::Classical => Classification::Public,
            ChannelStrength::PqcHybrid768 => Classification::Secret,
            ChannelStrength::PqcHybrid1024 => Classification::Secret,
        }
    }
}

/// An endpoint's **effective authorization**: the lesser of its registry ceiling
/// and what its actually-negotiated channel can carry (BROKKR-ARCH 6.10). A
/// registry ceiling of `Internal` reached over a `Classical` channel collapses to
/// `Public`.
pub fn effective_authorization(
    endpoint_max: Classification,
    channel: ChannelStrength,
) -> Classification {
    core::cmp::min(endpoint_max, channel.permits())
}
