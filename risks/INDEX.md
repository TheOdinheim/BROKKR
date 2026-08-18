# Risk Register Index

Standing inventory of identified risks (OQGF-P-10.6). Interim markdown register; migrates
into the persisted `brokkr-audit` Risk Register at Phase 7. Never deleted — closed and
superseded entries are annotated and retained.

| ID | Description | Source | Likelihood | Impact | Disposition | Status | Target |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RISK-2026-0001 | Single-source entropy for key generation (OQGF-R-4) | ThreatModel (P2 conformance) | Unlikely | Major | Reduce | Open | Pre-production |
| RISK-2026-0002 | Crypto-shred durability not guaranteed at FFI layer (OQGF-P-11 / G-7) | ThreatModel (P2 conformance) | Unlikely | Major | Reduce | Open — **tombstone half delivered P7 (6 Aug)**; durable-destruction substrate NOT built and re-assigned off `brokkr-audit` (SAGA holds no subject key, §6.9/P-11.7) → target set by DAP 6 Aug (see REGISTER) | ~~Phase 7~~ → **Pre-production** (`brokkr-crypto` memory-locking rev before Phase 11 + deployment HSM/swap) |
| RISK-2026-0003 | brokkr-crypto has no public-key-only verifier (DualPublicKey) (OQGF-M-8) | ThreatModel (P3 conformance) | AlmostCertain | Major | Reduce | ~~Open~~ → type 17 Jul → SKULD verify 20 Jul → **SINDRI wiring landed 24 Jul (P4); wiring residual CLOSED** (pre-shared-roots residual → RISK-2026-0005) | Executed (Phase 4) |
| RISK-2026-0004 | Two of OQGF-M-11's four conjuncts not enforced at Phase 4 (M-11 / M-10) | ThreatModel (P4 conformance; disposed ARCH Rev 1.3) | Possible | Major | Reduce | Open — **types placed 27 Jul (Rev 1.4 core rev)**; enforcement pending Phase 5; detail-level invariants stay open | Phase 5 (REGIN) — hard gate before Phase 11 |
| RISK-2026-0005 | Attestation is not verified as attestation (OQGF-M-1 PARTIAL) | ThreatModel (P4 conformance; disposed ARCH Rev 1.3) | Unlikely | Major | Reduce | Open | Deferred (issuer + committed signed-content + measurement source) |
| RISK-2026-0006 | A defeated freshness check survived four phases of review (OQGF-M-14 / I-13) — SINDRI held `now` at construction; freshness passed while enforcing nothing; class recurred in BIFRÖST **and in brokkr-sentinel** | ThreatModel (P8.5 buildability check; ARCH Rev 1.15 / CLAUDE.md v1.7 I-13) | Possible | Major | Reduce | Open — SINDRI half CLOSED 18 Aug + **BIFRÖST half CLOSED 18 Aug (workspace GREEN, 153 tests)**; but the closure grep found a **THIRD held clock in brokkr-sentinel (EIR+HEIMDALL)** → **GAP-2026-08-18-001**; NOT closed until sentinel corrected AND workspace grep empty | ~~SINDRI rev~~ + ~~Phase 8.5 rebuild~~ done → **brokkr-sentinel I-13 revision (DAP) remains** |

**Full entries:** `risks/REGISTER.md`
