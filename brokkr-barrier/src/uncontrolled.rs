//! The Uncontrolled-Channel register (OQGF-I-14).
//!
//! **This type enforces nothing.** It is the record of what the architecture *cannot
//! reach*: channels through which governed data could leave outside HÚÐ's enforcement — a
//! developer's own terminal in another window, a personal device, an editor's telemetry.
//! OQGF-I-14 requires that such channels be **enumerated** and their reliance **reduced**;
//! the framework "names what it cannot reach" rather than claiming to enforce it. The
//! register has no `brokkr-core` consumer, so it is a `brokkr-barrier` type (§6.5).

/// The declared posture toward reducing reliance on an uncontrolled channel. Reducing
/// reliance — making the governed path the path of least resistance — is a standing
/// obligation (OQGF-I-14); this records where each channel stands, not an enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReductionPosture {
    /// Reliance is being actively reduced (e.g. the governed path is being made easier).
    Reducing,
    /// Reliance is acknowledged and monitored, with no active reduction underway.
    Monitored,
    /// Newly identified; no posture decided yet.
    Unassessed,
}

/// One enumerated uncontrolled channel: a human description and the reduction posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncontrolledChannel {
    /// What the channel is (e.g. "developer terminal in another window").
    pub description: String,
    pub posture: ReductionPosture,
}

/// The enumeration of uncontrolled channels (OQGF-I-14). **Enforces nothing** — it is the
/// standing record of what HÚÐ cannot reach, so reliance on those channels can be tracked
/// and reduced. It does not gate, deny, or quarantine anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UncontrolledChannelRegister {
    channels: Vec<UncontrolledChannel>,
}

impl UncontrolledChannelRegister {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
        }
    }

    /// Enumerate a channel (OQGF-I-14: "enumerate the Uncontrolled Channels … record that
    /// enumeration").
    pub fn enumerate(&mut self, description: impl Into<String>, posture: ReductionPosture) {
        self.channels.push(UncontrolledChannel {
            description: description.into(),
            posture,
        });
    }

    /// The recorded channels. Read-only; the register enforces nothing.
    pub fn channels(&self) -> &[UncontrolledChannel] {
        &self.channels
    }
}
