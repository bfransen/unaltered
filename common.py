"""
Shared code for unaltered index and verify: constants, types, DB, hashing, reporting.
"""

import hashlib
import json
import logging
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set


DEFAULT_DB_NAME = "integrity.db"
DEFAULT_HASH_ALGO = "sha256"
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
COMMIT_EVERY = 250
DEFAULT_WORKERS = 1
PROGRESS_EVERY = 1000
HASH_BATCH_SIZE = 100


@dataclass
class FileInfo:
    """Information about a file to be hashed."""
    path: Path
    path_str: str
    filename: str
    size: int
    mtime_ns: int
    existing_hash: Optional[str] = None


@dataclass
class HashResult:
    """Result of a hash computation."""
    file_info: FileInfo
    digest: Optional[str] = None
    error: Optional[str] = None


def setup_logging(log_file: Optional[Path] = None, verbose: bool = False) -> None:
    """Configure logging to file and console."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        handlers.append(logging.FileHandler(log_file, mode='w', encoding='utf-8'))

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


def parse_exclude_extensions(exclude_args: List[str]) -> Set[str]:
    """Normalize exclude extensions into a set of lowercase suffixes."""
    extensions: Set[str] = set()
    for item in exclude_args:
        for part in item.split(','):
            ext = part.strip().lower()
            if not ext:
                continue
            if not ext.startswith('.'):
                ext = f".{ext}"
            extensions.add(ext)
    return extensions


def should_ignore_file(file_path: Path, size: Optional[int] = None) -> bool:
    """Ignore files matching delete_by_filename criteria (prefix + size)."""
    try:
        if not file_path.name.startswith("._"):
            return False
        s = size if size is not None else file_path.stat().st_size
        return s < 4500
    except (OSError, AttributeError):
        return False


def iter_files(root: Path) -> Iterable[Path]:
    """Iterate through files under root without following symlinks."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                    except OSError as exc:
                        logging.warning(f"Skipping entry {entry.path}: {exc}")
        except OSError as exc:
            logging.warning(f"Skipping directory {current}: {exc}")


def compute_hash(file_path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Compute SHA-256 hash for a file."""
    hasher = hashlib.sha256()
    with file_path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_hash_task(file_info: FileInfo) -> HashResult:
    """Compute hash for a file, returning a HashResult (for use in thread pool)."""
    try:
        digest = compute_hash(file_info.path)
        return HashResult(file_info=file_info, digest=digest)
    except OSError as exc:
        return HashResult(file_info=file_info, error=str(exc))


def connect_database(db_path: Path) -> sqlite3.Connection:
    """Open database connection and initialize schema."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            hash TEXT NOT NULL,
            hash_algo TEXT NOT NULL,
            last_seen INTEGER NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_last_seen ON files(last_seen)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_filename ON files(filename)")
    return conn


def open_database_readonly(db_path: Path) -> sqlite3.Connection:
    """Open the database in read-only mode."""
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def is_under_root(file_path: Path, root: Path) -> bool:
    """Return True if file_path is under root."""
    try:
        file_path.relative_to(root)
    except ValueError:
        return False
    return True


def build_report(
    root: Path,
    db_path: Path,
    hash_algo: str,
    exclude_exts: Set[str],
    stats: Dict[str, int],
    run_started: int,
    run_finished: int,
    mode: str,
    details: Optional[Dict[str, object]],
) -> Dict[str, object]:
    """Build JSON-compatible report."""
    report: Dict[str, object] = {
        "run_started": datetime.fromtimestamp(run_started).isoformat(),
        "run_finished": datetime.fromtimestamp(run_finished).isoformat(),
        "duration_seconds": run_finished - run_started,
        "root": str(root),
        "db": str(db_path),
        "hash_algo": hash_algo,
        "mode": mode,
        "exclude_exts": sorted(exclude_exts),
        "stats": stats,
    }
    if details:
        report.update(details)
    return report


def write_report(report: Dict[str, object], report_path: Path) -> None:
    """Write report to file."""
    report_json = json.dumps(report, indent=2, sort_keys=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_json, encoding='utf-8')
    logging.info(f"Report written to {report_path}")
