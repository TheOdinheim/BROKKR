//! brokkr-tools tests. A tool executes an already-authorized action; it never authorizes. To hand
//! a tool a genuine `AuthorizedAction`, these tests mint one the ONLY sanctioned way — through a
//! `CostimulationGate` (the sole minter, I-1) — using core types only. brokkr-tools itself does
//! not do this; the executor (Phase 11) does.

use brokkr_core::crypto::{Attestation, Digest, DualSignature, HashAlg, Signature, SignatureAlg};
use brokkr_core::gate::{
    Action, AnergyReason, AuthorizationDecision, AuthorizedAction, CostimulationGate,
};
use brokkr_core::ids::{Dap, Nonce, SubjectId, Timestamp, ToolId};
use brokkr_core::intent::{
    Capability, IntentProvenanceChain, IntentScope, InvariantSet, RootIntent,
};

use brokkr_tools::{FixedResultTool, NoOpTool, ToolExecutor};

// ---- minting an AuthorizedAction the sanctioned way (core only) ----------------------

fn dual_sig() -> DualSignature {
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: Vec::new(),
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: Vec::new(),
        },
    }
}

fn attestation() -> Attestation {
    Attestation {
        subject: SubjectId::new("hop-1"),
        measurements: Digest {
            alg: HashAlg::Sha384,
            bytes: Vec::new(),
        },
        freshness: Nonce(1),
        signatures: dual_sig(),
    }
}

fn root_intent() -> RootIntent {
    RootIntent {
        principal: SubjectId::new("principal"),
        dap: Dap::new("Jeremy Rose", "dap-1"),
        scope: IntentScope::new([Capability::new("write")]),
        invariants: InvariantSet::new([]),
        nonce: Nonce(1),
        expiry: Timestamp(1_000_000),
        signature: dual_sig(),
    }
}

/// A gate that grants — used only to MINT an `AuthorizedAction` for these tests. In the real
/// system this is SINDRI, which actually verifies both signals; here the point is not the verdict
/// logic but that the *only* way to obtain an `AuthorizedAction` is through the gate's provided
/// `authorize` (the tool cannot make one).
struct MintingGate;
impl CostimulationGate for MintingGate {
    fn evaluate(
        &self,
        _identity: &Attestation,
        _chain: &IntentProvenanceChain,
        _action: &Action,
        _now: Timestamp,
    ) -> Result<(), AnergyReason> {
        Ok(())
    }
}

fn authorized(tool: &str) -> AuthorizedAction {
    let chain = IntentProvenanceChain::new(root_intent());
    let action = Action {
        tool: ToolId::new(tool),
        detail: "do the thing".to_string(),
    };
    match MintingGate.authorize(&attestation(), &chain, action, Timestamp(1)) {
        AuthorizationDecision::Granted(a) => a,
        AuthorizationDecision::Anergy { .. } => panic!("MintingGate always grants"),
    }
}

// ---- tests --------------------------------------------------------------------------

#[test]
fn test_authorized_action_executes() {
    let tool = FixedResultTool::new(ToolId::new("write"), "wrote 3 bytes");
    let action = authorized("write");

    let outcome = tool.execute(&action).expect("the stub tool succeeds");
    assert_eq!(outcome.output, "wrote 3 bytes");
    assert_eq!(tool.tool_id(), &ToolId::new("write"));
}

#[test]
fn test_tool_does_not_reauthorize() {
    // Structural: a tool RECEIVES an `AuthorizedAction`; it never makes one. The action below was
    // minted by the gate (above), not by the tool — and the tool CANNOT mint one (the constructor
    // is sealed in `brokkr-core::gate`; the `compile_fail` doctest in `lib.rs` proves it, and
    // nothing in `brokkr-tools` calls `authorize`). The tool executes directly, with no re-check.
    let tool = NoOpTool::new(ToolId::new("noop"));
    let action = authorized("noop");
    assert!(tool.execute(&action).is_ok());
}
