# Demo case: demo_stomp

A deterministic synthetic NTFS image used to demonstrate and test the agent.

- `generate.py` - writes `case.img` from the `logflip.lab` fixture builders.
- `case.img` - the generated image (regenerate any time; it is byte-stable).
- `leaves/` - signed evidence leaves written by a demo run.

Contents: journaled timestamp stomps at MFT records 5 and 7 (`provisional`), a
benign record at 9 (`clean`), and a journal-less `$SI`-vs-`$FN` anomaly at record
12 (`anomaly`, the agent's self-correction trigger). The `$UsnJrnl` `$J` stream is
at MFT record 42.

Regenerate and run:

```bash
python cases/demo_stomp/generate.py
python -m sift_agent --image cases/demo_stomp/case.img --usnjrnl-record 42 \
    --log logs/session.jsonl --leaf-dir cases/demo_stomp/leaves
```

Full provenance and expected results: [../../docs/DATASET.md](../../docs/DATASET.md).
