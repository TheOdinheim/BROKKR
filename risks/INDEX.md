# Risk Register Index

Standing inventory of identified risks (OQGF-P-10.6). Interim markdown register; migrates
into the persisted `brokkr-audit` Risk Register at Phase 7. Never deleted — closed and
superseded entries are annotated and retained.

| ID | Description | Source | Likelihood | Impact | Disposition | Status | Target |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RISK-2026-0001 | Single-source entropy for key generation (OQGF-R-4) | ThreatModel (P2 conformance) | Unlikely | Major | Reduce | Open | Pre-production |
| RISK-2026-0002 | Crypto-shred durability not guaranteed at FFI layer (OQGF-P-11 / G-7) | ThreatModel (P2 conformance) | Unlikely | Major | Reduce | Open — **tombstone half delivered P7 (6 Aug)**; durable-destruction substrate NOT built and re-assigned off `brokkr-audit` (SAGA holds no subject key, §6.9/P-11.7) → target set by DAP 6 Aug (see REGISTER) | ~~Phase 7~~ → **Pre-production** (`brokkr-crypto` memory-locking rev before Phase 11 + deployment HSM/swap) |
| RISK-2026-0003 | brokkr-crypto has no public-key-only verifier (DualPublicKey) (OQGF-M-8) | ThreatModel (P3 conformance) | AlmostCertain | Major | Reduce | ~~Open~~ → type 17 Jul → SKULD verify 20 Jul → **SINDRI wiring landed 24 Jul (P4); wiring residual CLOSED** (pre-shared-roots residual → RISK-2026-0005) | Executed (Phase 4) |
| RISK-2026-0004 | Two of OQGF-M-11's four conjuncts not enforced at Phase 4 (M-11 / M-10) | ThreatModel (P4 conformance; disposed ARCH Rev 1.3) | Possible | Major | Reduce | Closed — **types placed 27 Jul (Rev 1.4 core rev)**; enforcement pending Phase 5; detail-level invariants stay open | Phase 5 (REGIN) — hard gate before Phase 11 |
| RISK-2026-0005 | Attestation is not verified as attestation (OQGF-M-1 PARTIAL) | ThreatModel (P4 conformance; disposed ARCH Rev 1.3) | Unlikely | Major | Reduce | Open | Deferred (issuer + committed signed-content + measurement source) |
| RISK-2026-0006 | A defeated freshness check survived four phases of review (OQGF-M-14 / I-13) — held-clock class across **three crates** (gate, bifrost, sentinel); grep matched shape not property | ThreatModel (P8.5 buildability check; ARCH Rev 1.15 / CLAUDE.md v1.7 I-13) | Possible | Major | Reduce | **held-clock removal EXECUTED 18 Aug — SINDRI  BIFRÖST  sentinel  (loop+inherent EIR, ARCH Rev 1.16); exhaustive comparison table CLEAN (13/13 per-call), workspace GREEN 159**. Two residuals NOT closed: table-check discipline every pass; and the "component/test that could not have failed" class → **recommend RISK-2026-0007** | ~~held clocks~~ Executed; residuals ongoing (table each pass) |
| RISK-2026-0007 (recommended, DAP decision) | A component may be correct, documented, and never called; a conformance verdict may be recorded on a test that could not have failed | ThreatModel (Rev 1.16 §13; loop gap + three freshness verdicts) | Likely | Major | Reduce | Recommended for DAP placement (PHASE-8-REV-2026-08-18-R2 Task 8) — mitigation is discipline (enumerate the end-to-end path; every test has a way to fail), not a structural check | (DAP to open) |

**Full entries:** `risks/REGISTER.md`
