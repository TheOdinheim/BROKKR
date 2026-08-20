//! `brokkr` — the binary entry point.
//!
//! Phase 11 wires the governed action cycle in [`brokkr_cli::Orchestrator`] (in the library, so
//! integration tests can compose it from test doubles). Production wiring — constructing the real
//! subsystems and their adapters, obtaining a Root Intent, and driving the loop — is a follow-on;
//! the executor is deliberately the last thing built, and it is not yet connected to real backends.

fn main() {
    println!(
        "brokkr: the orchestrator library is wired; production backends are not yet connected."
    );
}
