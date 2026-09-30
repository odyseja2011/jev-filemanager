from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

TARGET_DESCRIPTIONS = {
    "MOVIES": "Movies and feature-length live-action film content.",
    "SERIES": "Episodic live-action television series and shows.",
    "MUSIC": "Music recordings, albums, discographies and songs.",
    "BOOKS": "Ebooks, books, comics, manga and manuals.",
}


def base_config(tmp: Path, **overrides: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "version": 1,
        "migration": {"name": "test-migration"},
        "workspace": {"path": str(tmp / "workspace")},
        "scope": {
            "sources": [{"id": "media", "path": str(tmp / "MEDIA"), "include": ["**/*"], "exclude": []}],
            "targets": [{"id": tid, "path": str(tmp / "LIBRARY" / tid), "description": d}
                        for tid, d in TARGET_DESCRIPTIONS.items()],
        },
        "inventory": {"checksum": {"workers": 2, "read_block_mib": 1}},
    }
    for k, v in overrides.items():
        _merge(cfg, {k: v})
    return cfg


def _merge(dst: dict, src: dict) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


def write_config(tmp: Path, name: str = "migration.yaml", **overrides: Any) -> Path:
    p = tmp / name
    p.write_text(yaml.safe_dump(base_config(tmp, **overrides), sort_keys=False))
    return p


def write_files(root: Path, files: dict[str, bytes | str]) -> None:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())


def snapshot_tree(*roots: Path) -> dict[str, tuple]:
    """Byte-for-byte fingerprint of directory trees (content, type, mode, mtime, inode)."""
    import hashlib
    out: dict[str, tuple] = {}
    for root in roots:
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for n in sorted(dirnames + filenames):
                p = Path(dirpath) / n
                st = p.lstat()
                if p.is_symlink():
                    out[str(p)] = ("link", os.readlink(p))
                elif p.is_dir():
                    out[str(p)] = ("dir", st.st_mode, st.st_mtime_ns)
                else:
                    out[str(p)] = ("file", hashlib.sha256(p.read_bytes()).hexdigest(),
                                   st.st_mode, st.st_mtime_ns, st.st_ino, st.st_size)
    return out
