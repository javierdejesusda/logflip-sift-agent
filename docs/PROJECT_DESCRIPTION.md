# Project Description

## What it does

`logflip-sift-agent` is an autonomous incident-response agent that finds NTFS
timestamp tampering on a disk image and reasons about it the way a senior analyst
would. It scans the `$LogFile` for records whose in-image timestamps disagree with
the journal, investigates each one by reverse-replaying the journal, and - when a
record looks tampered but has no journal coverage - self-corrects by corroborating
across an independent channel before drawing a conclusion. Every finding is bound
to an HMAC-signed evidence leaf and a timestamped execution log, so a reviewer can
trace any claim back to the exact tool call and re-verify it offline.

Crucially, the agent cannot fabricate a finding or damage the evidence. It drives
a read-only MCP tool surface over a deterministic engine whose "never-false-confirm"
invariant is enforced in code, and a verdict guard re-derives every reported claim
from the signed leaf rather than from the model's prose.

## How I built it

The system is three thin layers over the existing, MIT-licensed `logflip` engine
(NTFS `$LogFile` reverse-replay timestomp detection):

- **`sift-mcp`** - a FastMCP server that exposes the engine as six typed,
  read-only functions (`scan_image`, `detect_record`, `inspect_mft`,
  `inspect_usnjrnl`, `verify_leaf`, `verify_db`). No write, delete, or shell tool
  exists in the surface.
- **`sift-agent`** - a tool-calling loop with interchangeable drivers: two LLM
  drivers (Claude via the Anthropic tool-use API, and OpenAI via chat-completions
  tool calling) and a deterministic analyst policy (no API key, fully
  reproducible). All are bounded by the same guards: a max-iterations cap, the
  verdict guard, and a structured session log.
- **Audit layer** - a JSONL session log where every finding's verdict links to the
  tool execution that derived it (`produced_by_seq`), a corroborated anomaly links
  its corroboration tools (`corroborated_by_seq`), and journaled findings link to a
  signed leaf.

Everything was built test-first (42 tests: read-only surface, verdict guard, loop
control, self-correction, log traceability, LLM drivers, CLI). The engine is reused
unmodified and depended on as a pre-existing component.

## Challenges

- **Making self-correction honest.** A single-source anomaly (an `$SI`-vs-`$FN`
  delta with no `$LogFile` coverage) is the shape of a raw-disk edit that bypassed
  the journal. The tempting bug is to "confirm" it. The correct behavior is to
  corroborate and then *refuse to escalate*, because the engine has no journal to
  invert. The self-correction is toward honesty, not toward a louder verdict.
- **Testing an autonomous loop deterministically.** LLM behavior is not
  reproducible, so the orchestrator was designed to be client-agnostic. The
  deterministic policy and an injected fake Anthropic client let the loop's
  control logic, guards, and self-correction be unit-tested without a key.
- **Resisting the urge to over-claim breadth.** The engine is deep on NTFS and
  silent on memory and network. Rather than fake coverage, the scope is stated
  plainly.

## What I learned

- **Architectural guardrails beat prompt guardrails.** The most defensible parts
  of this submission are the ones a misbehaving model cannot break: a tool surface
  with no destructive capability, a closed result schema, and a verdict guard that
  reads the signed leaf. The prompt only decides ordering.
- **The hardest forensic value was already deterministic.** Wrapping a tested,
  signed engine and adding autonomy on top produced a stronger result than trying
  to make an LLM do the forensics directly.

## What's next

- Validate against real acquired NTFS images and the SANS starter case data.
- Ship a populated, signed fingerprint DB so the `confirmed` tier is reachable in
  a demo (today the demo's honest ceiling is `provisional`).
- Add more read-only MCP tools (prefetch, registry LastWrite, event-log gaps) as
  independent corroboration channels, each typed and non-destructive.
- A cross-source correlation mode that pairs the disk timeline with a memory
  capture.

## Which qualities of autonomous execution this addresses

- **Reasons about next steps**: scan, then investigate only what disagrees, then
  corroborate only what is single-source.
- **Handles failures**: tools return structured errors (never tracebacks); the
  loop has a hard iteration cap.
- **Self-corrects in real time**: the anomaly pivot to an independent channel,
  with an honest non-escalation, is visible in the session log.
- **Accuracy and traceability**: findings come from signed engine verdicts and
  trace to specific tool executions; hallucinated escalation is structurally
  impossible.
