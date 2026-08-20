//! The tool-execution surface (Task 2).
//!
//! A tool **executes an already-authorized action**. By the time a tool runs, SINDRI has minted an
//! [`AuthorizedAction`] (the structural proof of costimulation, I-1) — the tool does **not**
//! re-check authorization, and it *cannot*: [`AuthorizedAction`]'s constructor is sealed in
//! `brokkr-core::gate` (a tool that tried to forge one does not compile). A tool receives one and
//! reads its [`Action`](brokkr_core::gate::Action) to know what to do.
//!
//! `ToolSchema` is opaque prose (`brokkr-core::genome`), so there is no structured schema-to-impl
//! dispatch here. Tools are identified by [`ToolId`]; the executor (Phase 11) maps a `ToolId` to
//! the implementation to run. Phase 10 builds this trait and stub implementations; real file or
//! shell execution is a deployment concern (out of scope).

use brokkr_core::gate::AuthorizedAction;
use brokkr_core::ids::ToolId;

/// What a tool produces on success. Opaque to the governance spine — a tool's output is data, not
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutcome {
    pub output: String,
}

/// Why a tool execution failed. A tool that fails does so as a *value*; it never panics (§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    pub detail: String,
}

impl core::fmt::Display for ToolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "tool execution failed: {}", self.detail)
    }
}

impl std::error::Error for ToolError {}

/// A tool the executor may run. **It receives an [`AuthorizedAction`]; it does not make one.**
///
/// `execute` takes `&AuthorizedAction` — proof SINDRI already authorized this action. The tool
/// reads `action.action()` and does the work. There is no `authorize` here, no gate, no re-check:
/// the authorization decision is upstream and final. Nothing in this crate constructs an
/// `AuthorizedAction` (the mint is private to `brokkr-core::gate`).
pub trait ToolExecutor: Send + Sync {
    /// The tool this executor implements. The Phase-11 executor dispatches on this.
    fn tool_id(&self) -> &ToolId;

    /// Execute the already-authorized action. The tool does **not** re-authorize.
    fn execute(&self, action: &AuthorizedAction) -> Result<ToolOutcome, ToolError>;
}

/// A tool that does nothing and reports success — the stub used to prove the execution path
/// without side effects.
pub struct NoOpTool {
    id: ToolId,
}

impl NoOpTool {
    pub fn new(id: ToolId) -> Self {
        Self { id }
    }
}

impl ToolExecutor for NoOpTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, _action: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        Ok(ToolOutcome {
            output: String::new(),
        })
    }
}

/// A tool that returns a fixed result — the stub used to prove a tool can read the authorized
/// action and produce output.
pub struct FixedResultTool {
    id: ToolId,
    result: String,
}

impl FixedResultTool {
    pub fn new(id: ToolId, result: impl Into<String>) -> Self {
        Self {
            id,
            result: result.into(),
        }
    }
}

impl ToolExecutor for FixedResultTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, action: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        // A tool MAY read the authorized action's detail; it does not re-check authorization.
        let _ = action.action();
        Ok(ToolOutcome {
            output: self.result.clone(),
        })
    }
}
