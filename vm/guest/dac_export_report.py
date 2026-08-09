#!/usr/bin/python3 -I
"""Stream one allowlisted report through an already authenticated SSH session."""

from __future__ import annotations

import os
import re
import stat
import sys

REPORT_ROOT = "/var/lib/detection-goggles/reports"
REPORT_NAMES = frozenset({"report.json", "report.md"})
RUN_ID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
MAX_REPORT_SIZE = 10 * 1024 * 1024
READ_SIZE = 64 * 1024


def _fail(message: str) -> None:
    raise RuntimeError(message)


def _open_report(run_id: str, report_name: str) -> tuple[int, int, os.stat_result]:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    root_descriptor = os.open(REPORT_ROOT, directory_flags)
    try:
        run_descriptor = os.open(run_id, directory_flags, dir_fd=root_descriptor)
    finally:
        os.close(root_descriptor)

    try:
        report_descriptor = os.open(report_name, file_flags, dir_fd=run_descriptor)
    except BaseException:
        os.close(run_descriptor)
        raise

    metadata = os.fstat(report_descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(report_descriptor)
        os.close(run_descriptor)
        _fail("report is not a regular file")
    if metadata.st_nlink != 1:
        os.close(report_descriptor)
        os.close(run_descriptor)
        _fail("report must have exactly one hard link")
    if metadata.st_size > MAX_REPORT_SIZE:
        os.close(report_descriptor)
        os.close(run_descriptor)
        _fail("report exceeds the export size limit")
    return run_descriptor, report_descriptor, metadata


def _stream_report(run_id: str, report_name: str) -> None:
    run_descriptor, report_descriptor, initial = _open_report(run_id, report_name)
    try:
        emitted = 0
        while chunk := os.read(report_descriptor, READ_SIZE):
            emitted += len(chunk)
            if emitted > MAX_REPORT_SIZE:
                _fail("report grew beyond the export size limit")
            sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        final = os.fstat(report_descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        if any(getattr(initial, field) != getattr(final, field) for field in stable_fields):
            _fail("report changed while it was exported")
        if emitted != initial.st_size:
            _fail("exported byte count does not match report metadata")
    finally:
        os.close(report_descriptor)
        os.close(run_descriptor)


def main(arguments: list[str] | None = None) -> int:
    selected = sys.argv[1:] if arguments is None else arguments
    if len(selected) != 2:
        print("usage: dac-export-report RUN_ID REPORT_NAME", file=sys.stderr)
        return 2
    run_id, report_name = selected
    if RUN_ID.fullmatch(run_id) is None:
        print("invalid run ID", file=sys.stderr)
        return 2
    if report_name not in REPORT_NAMES:
        print("report format is not exportable", file=sys.stderr)
        return 2
    try:
        _stream_report(run_id, report_name)
    except (OSError, RuntimeError) as exc:
        print(f"report export failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
