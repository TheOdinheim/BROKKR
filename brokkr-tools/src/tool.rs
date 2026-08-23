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

/// A filesystem write tool that **validates its own input** (13-FIX F-2).
///
/// The spine gates *declared authority*, never the content of `Action.detail` (the §13 residual).
/// Path safety is therefore the **tool's** responsibility, and this is where it lives: the tool
/// canonicalizes the requested path against a fixed `root` and **rejects any path that escapes it**
/// — `..`, absolute escapes, and root-relative traversal — returning a [`ToolError`] (never a
/// panic). It writes a fixed marker only when the target is inside the sandbox.
pub struct SandboxedTool {
    id: ToolId,
    /// The canonical sandbox root. Every write must resolve to a path under this.
    root: std::path::PathBuf,
}

impl SandboxedTool {
    /// Construct over a sandbox root. The root must already exist (it is canonicalized here, which
    /// resolves symlinks in the root itself); a missing/inaccessible root is a [`ToolError`].
    pub fn new(id: ToolId, root_dir: impl AsRef<std::path::Path>) -> Result<Self, ToolError> {
        let root = std::fs::canonicalize(root_dir).map_err(|e| ToolError {
            detail: format!("sandbox root is not accessible: {e}"),
        })?;
        Ok(Self { id, root })
    }

    /// Resolve `detail` to an absolute path and confirm it stays within the sandbox root. Returns a
    /// [`ToolError`] if it escapes. The requested path is joined onto the root (an absolute request
    /// replaces the root, then must still be under it), then **lexically** normalized (`.`/`..`
    /// resolved without touching the filesystem, so a not-yet-existing target can be checked).
    pub fn resolve(&self, detail: &str) -> Result<std::path::PathBuf, ToolError> {
        let joined = self.root.join(detail);
        let normalized = normalize_lexical(&joined);
        if normalized.starts_with(&self.root) {
            Ok(normalized)
        } else {
            Err(ToolError {
                detail: format!(
                    "path escapes the sandbox root {}: {}",
                    self.root.display(),
                    normalized.display()
                ),
            })
        }
    }
}

impl ToolExecutor for SandboxedTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, action: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        let path = self.resolve(&action.action().detail)?;
        std::fs::write(&path, b"written by SandboxedTool").map_err(|e| ToolError {
            detail: format!("write failed: {e}"),
        })?;
        Ok(ToolOutcome {
            output: format!("wrote within sandbox: {}", path.display()),
        })
    }
}

/// Lexically normalize a path — resolve `.` and `..` components **without touching the filesystem**
/// (so a target that does not yet exist can still be checked). Symlink resolution within an
/// existing tree is not performed here; the sandbox root is canonicalized (symlink-resolved) at
/// construction, which covers the common escape (`..`).
fn normalize_lexical(p: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}
