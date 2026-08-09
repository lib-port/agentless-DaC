"""Shared, deterministic static profiles used by the Malevolent ModMaker rules."""

from __future__ import annotations

import struct

GO_MARKERS = (
    b"Go build ID:",
    b"go.buildid",
    b"runtime.goexit",
    b"runtime.main",
    b"gopclntab",
)
AES_MARKERS = (b"crypto/aes", b"aes.NewCipher", b"NewCipher")
GCM_MARKERS = (b"cipher.NewGCM", b"crypto/cipher.newGCM", b"gcm.Seal", b"NewGCM")
FILE_MARKERS = (
    b"os.Remove",
    b"os.RemoveAll",
    b"os.ReadFile",
    b"os.WriteFile",
    b"filepath.Walk",
    b"filepath.WalkDir",
)
NETWORK_MARKERS = (b"net/http", b"http.NewRequest", b"http.Get", b"https://", b"http://")
EXECUTION_MARKERS = (
    b"os/exec",
    b"exec.Command",
    b"cmd.exe",
    b"powershell.exe",
    b"ShellExecute",
    b"CreateProcess",
)
ELEVATION_OR_EVASION_MARKERS = (
    b"runas",
    b"IsUserAnAdmin",
    b"CheckTokenMembership",
    b"VirtualProtect",
    b"AmsiScanBuffer",
    b"EtwEventWrite",
)


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    return offset + 4 <= len(data) and data[offset : offset + 4] == b"PE\0\0"


def marker_labels(lowered: bytes, markers: tuple[bytes, ...]) -> list[str]:
    """Return semantic marker hits without double-counting contained marker names."""

    accepted_spans: list[tuple[int, int]] = []
    matched_indexes: set[int] = set()
    for index, marker in sorted(enumerate(markers), key=lambda item: len(item[1]), reverse=True):
        needle = marker.lower()
        start = 0
        while (position := lowered.find(needle, start)) >= 0:
            span = (position, position + len(needle))
            if not any(
                span[0] >= accepted_start and span[1] <= accepted_end
                for accepted_start, accepted_end in accepted_spans
            ):
                accepted_spans.append(span)
                matched_indexes.add(index)
            start = position + 1
    return [
        marker.decode("ascii", errors="replace")
        for index, marker in enumerate(markers)
        if index in matched_indexes
    ]


def ransomware_profile(data: bytes) -> dict[str, object]:
    lowered = data.lower()
    go_hits = marker_labels(lowered, GO_MARKERS)
    aes_hits = marker_labels(lowered, AES_MARKERS)
    gcm_hits = marker_labels(lowered, GCM_MARKERS)
    file_hits = marker_labels(lowered, FILE_MARKERS)
    return {
        "matched": bool(is_pe(data) and go_hits and aes_hits and gcm_hits and len(file_hits) >= 2),
        "go_hits": go_hits,
        "aes_hits": aes_hits,
        "gcm_hits": gcm_hits,
        "file_hits": file_hits,
    }


def loader_profile(data: bytes) -> dict[str, object]:
    lowered = data.lower()
    network_hits = marker_labels(lowered, NETWORK_MARKERS)
    execution_hits = marker_labels(lowered, EXECUTION_MARKERS)
    support_hits = marker_labels(lowered, ELEVATION_OR_EVASION_MARKERS) + marker_labels(
        lowered, GO_MARKERS
    )
    return {
        "matched": bool(is_pe(data) and network_hits and execution_hits and support_hits),
        "network_hits": network_hits,
        "execution_hits": execution_hits,
        "support_hits": support_hits,
    }
