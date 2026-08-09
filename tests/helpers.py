from __future__ import annotations

import struct
from pathlib import Path


def synthetic_pe(path: Path, *markers: bytes) -> Path:
    """Create a harmless PE-shaped static-analysis fixture; it is not executable."""
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    data.extend(b"\0".join(markers))
    path.write_bytes(data)
    return path


def malevolent_profile_files(directory: Path) -> tuple[Path, Path]:
    ransomware = synthetic_pe(
        directory / "ransomware-fixture.bin",
        b"Go build ID: synthetic-safe-fixture",
        b"runtime.goexit",
        b"crypto/aes",
        b"aes.NewCipher",
        b"cipher.NewGCM",
        b"os.ReadFile",
        b"os.WriteFile",
        b"os.Remove",
        b"filepath.Walk",
    )
    loader = synthetic_pe(
        directory / "loader-fixture.bin",
        b"Go build ID: synthetic-safe-fixture",
        b"runtime.goexit",
        b"net/http",
        b"http.NewRequest",
        b"https://example.invalid/synthetic-payload",
        b"os/exec",
        b"exec.Command",
    )
    return ransomware, loader
