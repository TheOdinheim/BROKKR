# Risk Register Index

Standing inventory of identified risks (OQGF-P-10.6). Interim markdown register; migrates
into the persisted `brokkr-audit` Risk Register at Phase 7. Never deleted — closed and
superseded entries are annotated and retained.

| ID | Description | Source | Likelihood | Impact | Disposition | Status | Target |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RISK-2026-0001 | Single-source entropy for key generation (OQGF-R-4) | ThreatModel (P2 conformance) | Unlikely | Major | Reduce | Open | Pre-production |
| RISK-2026-0002 | Crypto-shred durability not guaranteed at FFI layer (OQGF-P-11 / G-7) | ThreatModel (P2 conformance) | Unlikely | Major | Reduce | Open | Phase 7 |
| RISK-2026-0003 | brokkr-crypto has no public-key-only verifier (DualPublicKey) (OQGF-M-8) | ThreatModel (P3 conformance) | AlmostCertain | Major | Reduce | ~~Open~~ → Reduced 17 Jul 2026 (DualPublicKey added); residual OPEN | Phase 4 (verify_chain/SINDRI wiring) |

**Full entries:** `risks/REGISTER.md`
