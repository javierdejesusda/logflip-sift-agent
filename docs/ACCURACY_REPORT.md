# Accuracy Report

A self-assessment of findings accuracy, the known misses, the hallucination
posture, and the evidence-integrity approach. Failure modes are documented as
signal, not hidden.

## Method

Accuracy is assessed at two layers:

- **Engine layer** (`logflip`, reused unmodified): 809 passing tests and a
  documented measured false-positive rate of 0.000 on its real corpora
  (`logflip-closed/docs/false_positive_rates.md`).
- **Agent layer** (this repo): 42 tests covering the read-only surface, the
  verdict guard, the loop control, the self-correction path, log traceability,
  the LLM drivers, and the CLI. Behavioral validation uses the deterministic demo case in
  `cases/demo_stomp/` (see [DATASET.md](DATASET.md)).

## Findings accuracy on the demo case

| Record | Ground truth | Agent verdict | Correct? |
|-------:|--------------|---------------|----------|
| 5 | journaled stomp | `provisional` (signed leaf) | Yes |
| 7 | journaled stomp | `provisional` (signed leaf) | Yes |
| 9 | benign | `clean` (not reported) | Yes (true negative) |
| 12 | journal-less raw-disk delta | `anomaly` (corroborated, not escalated) | Yes |

- **False positives: 0.** No benign record was reported.
- **False confirmations: 0.** No record was marked `confirmed` (the demo key
  cannot produce one; see below).
- **Missed artifacts on this case: 0.** All planted conditions were surfaced at
  the correct confidence tier.

## False positives

The agent introduces no new false-positive source: it reports only the engine's
verdicts, and the engine's measured rate on its corpora is 0.000. A `provisional`
verdict is a routed byte disagreement, not a confirmed accusation, and is labeled
as such with the engine's scope-bounded disclaimer.

## Known misses and limitations (documented, not hidden)

- **`confirmed` is unreachable in the default demo.** A confirmed verdict requires
  all four engine gates *and* a real engagement key *and* a signed fingerprint DB
  whose family carries a non-empty byte pattern. The shipped stub signatures have
  empty patterns, so the honest ceiling with the demo key is `provisional`. This
  is a deliberate never-false-confirm property, not a bug.
- **Raw-disk edits with no journal trace are anomalies, never confirmations.** A
  SetMACE-style edit that leaves no `$LogFile` record cannot be cryptographically
  inverted. The agent detects the `$SI`-vs-`$FN` delta, corroborates via the
  `$UsnJrnl`, and reports an `anomaly` requiring manual review. It will not claim
  more than the evidence supports.
- **`$LogFile` rollover window.** Tampering older than the live journal cannot be
  reconstructed; the engine returns an incomplete inversion and the record is not
  confirmed.
- **Scope: NTFS filesystem-journal artifacts only.** No memory, no network, no
  non-NTFS logs. The agent does not consume memory captures.
- **`$UsnJrnl` corroboration uses the engine's exact file-reference match.** The
  agent corroborates an anomaly by querying the journal for a file reference, and
  the engine compares it for exact equality with no sequence-number masking (the
  same convention logflip's own pipeline uses). On the synthetic case the reference
  equals the bare MFT record number (sequence zero), so corroboration matches; on a
  real acquired image the full 64-bit reference (entry plus sequence) is required,
  and this corroboration path is not yet validated against real acquisitions.
- **Scan-time journal read.** `scan_image` relies on the engine's `$Extend`
  auto-discovery and has no journal-record override, so on the synthetic image
  (minimal `$Extend`) the scan summary does not consume the journal. The journal is
  read by `detect_record` and `inspect_usnjrnl` with an explicit record number.
  This does not affect anomaly detection, which is `$SI`-vs-`$FN` based.

## Hallucination posture

- **The model cannot inflate a verdict.** Reported findings are assembled from
  engine tool outputs, and the verdict guard (`sift_agent/guard.py`) re-derives the
  structured claim from the signed leaf. A model that narrates "CONFIRMED EVIL on
  every record" still yields `provisional` structured findings. This is enforced
  by a test: `test_agent_loop.py::test_model_prose_cannot_forge_a_confirmed_verdict`.
- **The engine refuses unsafe confirms.** The four-gate invariant plus a demo-key
  block raise rather than emit a false confirm.

### What happens if the model ignores the rules?

Tested directly. The prompt asks the model to sequence tools and stay honest, but
that is a prompt-layer request. If the model ignores it:

- It still cannot run a destructive tool (none is registered) - architectural.
- It still cannot produce a `confirmed` finding the leaf does not support - the
  verdict guard and the engine gates reject it - architectural.
- It cannot loop forever - the max-iterations cap halts it - architectural.

So a misbehaving model degrades the *narrative quality*, never the *evidence
integrity* or the *finding accuracy*.

## Evidence-integrity approach

- **Original data is never modified.** The MCP server exposes only read-only
  forensic functions; there is no write, delete, or shell tool in the surface, and
  `logflip` sources open the image read-only. The capability to spoliate does not
  exist in the agent's reach.
- **Did we test for spoliation?** Yes. `test_mcp_server.py` asserts that the
  registered tool surface is exactly the six read-only tools and contains no tool
  whose name implies writing, deleting, executing, or shelling. This is the
  spoliation guard, verified against the actually-registered tools.
- **Tamper-evidence.** Every journaled finding is an HMAC-signed leaf over the
  RFC 8785 canonical JSON of its fields; `verify_leaf` re-checks it offline with a
  constant-time comparison, and the demo key is refused for verification. Each
  session-log tool line also records a digest of the raw tool output.

## Summary

On the reproducible demo case the agent is correct at every record with zero false
positives and zero false confirmations. Its accuracy ceiling, its anomaly
non-escalation, and its NTFS-only scope are intrinsic, documented properties. The
guarantees that matter for a forensic result - read-only evidence handling,
tamper-evident signing, and no hallucinated confirmation - are architectural and
hold even if the language model misbehaves.
