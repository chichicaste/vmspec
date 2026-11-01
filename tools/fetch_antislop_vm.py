#!/usr/bin/env python3
"""Fetch the Parallax Cartridge VM fixture and verify upstream hashes."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
from urllib.request import urlopen


BASE_URL = (
    "https://raw.githubusercontent.com/Abdelkad3r/Anti-SlopCTF-2026/"
    "main/reverse/parallax-cartridge/"
)
FILES = {
    "parallax-cartridge": "4cbddae4588ad2673d5475ff7d01cd4d0276b225eeacadc14f1f3b0f49292eef",
    "starter.qar": "745eaaf2e5ae12ddc4bfd14bd6ad041572a38ff9915d4c178142d288b12222bc",
}
OUTPUT = Path("data/external/antislopctf-2026/parallax-cartridge")


def fetch(name: str, expected: str) -> Path:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    target = OUTPUT / name
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
        print(f"verified {target}")
        return target

    digest = hashlib.sha256()
    fd, temporary = tempfile.mkstemp(dir=OUTPUT, prefix=f".{name}.")
    try:
        with os.fdopen(fd, "wb") as destination, urlopen(BASE_URL + name, timeout=30) as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                destination.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError(f"SHA-256 mismatch for {name}: {digest.hexdigest()}")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"downloaded and verified {target}")
    return target


if __name__ == "__main__":
    for filename, sha256 in FILES.items():
        fetch(filename, sha256)
