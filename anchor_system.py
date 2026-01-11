#!/usr/bin/env python3
from __future__ import annotations

import os
import json
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# --- Defaults: qué escanear/excluir para Linux ---
DEFAULT_EXCLUDES_PREFIX = (
    "/proc", "/sys", "/dev", "/run", "/tmp",
    "/var/tmp", "/var/cache", "/var/log",
    "/swapfile", "/lost+found",
)

DEFAULT_EXCLUDES_GLOB = (
    "**/.cache/**",
    "**/__pycache__/**",
)

@dataclass(frozen=True)
class FileEntry:
    path: str
    sha256: str
    size: int
    mtime_ns: int
    mode: int
    uid: int
    gid: int

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _is_excluded(path: str, excludes_prefix=DEFAULT_EXCLUDES_PREFIX) -> bool:
    # Excluye por prefijo absoluto
    for pref in excludes_prefix:
        if path == pref or path.startswith(pref + "/"):
            return True
    return False

def iter_files(root: Path, follow_symlinks: bool = False) -> Iterable[Path]:
    # Recorrido eficiente
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # poda rápida de directorios excluidos
        dp = dirpath.replace("\\", "/")
        if _is_excluded(dp):
            dirnames[:] = []
            continue

        # también podar subdirectorios excluidos
        pruned = []
        for d in dirnames:
            full = (Path(dirpath) / d).as_posix()
            if not _is_excluded(full):
                pruned.append(d)
        dirnames[:] = pruned

        for fn in filenames:
            p = Path(dirpath) / fn
            yield p

def build_manifest(
    root: str = "/",
    follow_symlinks: bool = False,
    max_file_size_mb: int = 512,
) -> Dict[str, FileEntry]:
    """
    Genera manifest (path->FileEntry) para un root dado.
    - max_file_size_mb evita colgarte con ISOs gigantes (puedes ajustar)
    """
    rootp = Path(root)
    manifest: Dict[str, FileEntry] = {}

    max_bytes = max_file_size_mb * 1024 * 1024

    for p in iter_files(rootp, follow_symlinks=follow_symlinks):
        try:
            st = p.lstat()  # no sigue symlink
            # saltar symlinks (puedes decidir incluirlos como metadata)
            if p.is_symlink():
                continue
            if not p.is_file():
                continue
            if st.st_size > max_bytes:
                continue

            sha = _sha256_file(p)
            rel = p.as_posix()  # guardamos rutas absolutas (más simple para system baseline)
            manifest[rel] = FileEntry(
                path=rel,
                sha256=sha,
                size=int(st.st_size),
                mtime_ns=int(st.st_mtime_ns),
                mode=int(st.st_mode),
                uid=int(st.st_uid),
                gid=int(st.st_gid),
            )
        except (PermissionError, FileNotFoundError):
            # Cambios mientras escanea / permisos: simplemente ignora
            continue
        except OSError:
            continue

    return manifest

def manifest_to_jsonl(manifest: Dict[str, FileEntry]) -> str:
    """
    Serializa determinísticamente a JSONL ordenado por path.
    """
    lines: List[str] = []
    for k in sorted(manifest.keys()):
        e = manifest[k]
        obj = {
            "path": e.path,
            "sha256": e.sha256,
            "size": e.size,
            "mtime_ns": e.mtime_ns,
            "mode": e.mode,
            "uid": e.uid,
            "gid": e.gid,
        }
        lines.append(json.dumps(obj, sort_keys=True, separators=(",", ":")))
    return "\n".join(lines) + "\n"

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def diff_manifests(
    old: Dict[str, FileEntry],
    new: Dict[str, FileEntry],
) -> Dict[str, List[str]]:
    old_keys = set(old.keys())
    new_keys = set(new.keys())

    added = sorted(list(new_keys - old_keys))
    removed = sorted(list(old_keys - new_keys))

    modified: List[str] = []
    for k in sorted(list(old_keys & new_keys)):
        if old[k].sha256 != new[k].sha256:
            modified.append(k)

    return {"added": added, "removed": removed, "modified": modified}

# --- Arch/pacman helpers (opcional) ---

def _run(cmd: List[str]) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out.strip()
    except Exception as e:
        return 127, str(e)

def pacman_owner(path: str) -> Optional[str]:
    """
    Devuelve el paquete dueño del archivo o None si no pertenece a ningún paquete.
    """
    code, out = _run(["pacman", "-Qo", path])
    if code != 0:
        return None
    # formato típico: "/usr/bin/ls is owned by coreutils 9.6-1"
    parts = out.split(" is owned by ")
    if len(parts) != 2:
        return None
    pkg = parts[1].split()[0].strip()
    return pkg or None

def classify_changes_pacman(paths: List[str]) -> Dict[str, List[str]]:
    owned: List[str] = []
    unowned: List[str] = []
    for p in paths:
        pkg = pacman_owner(p)
        (owned if pkg else unowned).append(p)
    return {"owned_by_pkg": owned, "not_owned": unowned}
