# Dataset Documentation

## What the agent was tested against

The committed demo runs against a **synthetic NTFS volume image**, generated
deterministically by `cases/demo_stomp/generate.py` from the `logflip.lab`
fixture builders. No real disk, no personal data, fully reproducible.

The image (`cases/demo_stomp/case.img`, ~132 KiB) contains a minimal but valid
NTFS layout (boot sector, self-mapping `$MFT`, `$LogFile`, and a `$UsnJrnl` `$J`
stream at MFT record 42) with these planted records:

| MFT record | Planted condition | Expected verdict |
|-----------:|-------------------|------------------|
| 5 | Timestamp stomp recorded in the `$LogFile` (undo != redo); `$SI` != `$FN` | `provisional` |
| 7 | Timestamp stomp recorded in the `$LogFile`; `$SI` != `$FN` | `provisional` |
| 9 | Benign log record (undo == redo); `$SI` == `$FN` | `clean` |
| 12 | `$SI`-vs-`$FN` delta with **no** `$LogFile` coverage (raw-disk / SetMACE-bypass shape) | `anomaly` |
| 15 | No delta, absent from the `$LogFile` | not surfaced |

This single case exercises all three behaviors that matter for judging: a clean
detection path (records 5, 7), a true-negative (record 9), and a single-source
anomaly that drives the agent's self-correction (record 12).

## Source and provenance

- **Builder**: `logflip.lab.synthetic.build_image_with_journal_less_delta_record`,
  a deterministic in-memory NTFS constructor used by the engine's own test suite.
  It is lab/test tooling and never participates in the detection gates.
- **Determinism**: the image is byte-stable across runs, so results reproduce
  exactly. Regenerate with `python cases/demo_stomp/generate.py`.

## What the agent found (committed sample run)

From `logs/sample_session.jsonl` (deterministic policy driver, 5 iterations):

- Records 5 and 7: `provisional` timestomp findings, each bound to an HMAC-signed
  leaf (`cases/demo_stomp/leaves/leaf_5.json`, `leaf_7.json`).
- Record 12: `anomaly`. The agent recognized a single-source signal, corroborated
  via `$UsnJrnl` and the MFT delta, and reported it as requiring manual review
  rather than confirming it. No leaf is produced for an anomaly.
- Record 9: `clean`, correctly not reported.

## Reproducibility

```bash
python cases/demo_stomp/generate.py
python -m sift_agent --image cases/demo_stomp/case.img --usnjrnl-record 42 \
    --log logs/session.jsonl --leaf-dir cases/demo_stomp/leaves
```

`--usnjrnl-record 42` is supplied because the synthetic image carries only a
minimal `$Extend` index. A real acquired image auto-discovers the `$UsnJrnl`, so
the flag is omitted there. Note: the scan step itself does not consume the journal
on this synthetic image (the engine's scan has no journal-record override);
`detect_record` and `inspect_usnjrnl` read it with the explicit record number. See
the limitations in [ACCURACY_REPORT.md](ACCURACY_REPORT.md).

## Using real data (SIFT Workstation)

The same commands work against a real raw NTFS image or a live volume:

```bash
python -m sift_agent --image /evidence/disk.raw --driver claude --log logs/session.jsonl
```

The SANS *FIND EVIL!* starter case data (disk and memory captures) can be used as
input for the NTFS-disk portion; this agent analyzes the NTFS filesystem-journal
artifacts and does not consume memory captures (see the scope note in the
[accuracy report](ACCURACY_REPORT.md)).

## Honesty note

This dataset is synthetic and intentionally small so judges can reproduce it in
seconds without acquiring evidence. It demonstrates correctness and the
self-correction behavior; it is not a breadth benchmark. Larger real-image
validation is listed under "what's next" in the project description.
