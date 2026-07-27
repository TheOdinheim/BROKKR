# Risk Register Index

Standing inventory of identified risks (OQGF-P-10.6). Interim markdown register; migrates
into the persisted `brokkr-audit` Risk Register at Phase 7. Never deleted — closed and
superseded entries are annotated and retained.

| ID | Description | Source | Likelihood | Impact | Disposition | Status | Target |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RISK-2026-0001 | Single-source entropy for key generation (OQGF-R-4) | ThreatModel (P2 conformance) | Unlikely | Major | Reduce | Open | Pre-production |
| RISK-2026-0002 | Crypto-shred durability not guaranteed at FFI layer (OQGF-P-11 / G-7) | ThreatModel (P2 conformance) | Unlikely | Major | Reduce | Open | Phase 7 |
| RISK-2026-0003 | brokkr-crypto has no public-key-only verifier (DualPublicKey) (OQGF-M-8) | ThreatModel (P3 conformance) | AlmostCertain | Major | Reduce | ~~Open~~ → type 17 Jul → SKULD verify 20 Jul → **SINDRI wiring landed 24 Jul (P4); wiring residual CLOSED** (pre-shared-roots residual → RISK-2026-0005) | Executed (Phase 4) |
| RISK-2026-0004 | Two of OQGF-M-11's four conjuncts not enforced at Phase 4 (M-11 / M-10) | ThreatModel (P4 conformance; disposed ARCH Rev 1.3) | Possible | Major | Reduce | Open — **types placed 27 Jul (Rev 1.4 core rev)**; enforcement pending Phase 5; detail-level invariants stay open | Phase 5 (REGIN) — hard gate before Phase 11 |
| RISK-2026-0005 | Attestation is not verified as attestation (OQGF-M-1 PARTIAL) | ThreatModel (P4 conformance; disposed ARCH Rev 1.3) | Unlikely | Major | Reduce | Open | Deferred (issuer + committed signed-content + measurement source) |

**Full entries:** `risks/REGISTER.md`
