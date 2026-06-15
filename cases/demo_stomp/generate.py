"""Generate the synthetic demo NTFS case for logflip-sift-agent.

Builds an in-memory NTFS volume with two journaled timestamp stomps (MFT records
5 and 7) and one journal-less SI-vs-FN anomaly (MFT record 12, the SetMACE-bypass
shape), then writes it to case.img. The journaled stomps drive the detection
path; the anomaly drives the agent's self-correction path.

The $UsnJrnl $J stream lives at MFT record 42. Pass that to the agent via
--usnjrnl-record because this synthetic image carries only a minimal $Extend
index; a real acquired image auto-discovers the journal.
"""

from __future__ import annotations

from pathlib import Path

from logflip.lab.synthetic import (
    USNJRNL_RECORD_NUM,
    build_image_with_journal_less_delta_record,
)

CASE_PATH = Path(__file__).parent / "case.img"
USNJRNL_RECORD = USNJRNL_RECORD_NUM


def main() -> None:
    """Write the synthetic case image next to this script."""
    image, _ = build_image_with_journal_less_delta_record()
    CASE_PATH.write_bytes(image)
    print(
        f"wrote {CASE_PATH} ({len(image)} bytes); "
        f"$UsnJrnl $J at MFT record {USNJRNL_RECORD}"
    )


if __name__ == "__main__":
    main()
