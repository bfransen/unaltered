#!/usr/bin/env python3
"""
Unaltered – bit-rot detection.

Scans a directory tree, computes SHA-256 hashes for new or changed files,
and stores results in a local SQLite database.

Commands:
  index   Build or update the hash DB; only new/changed files are hashed.
  verify  Re-hash files under --root and compare to stored hashes.

A JSON report is always written (default: report.json for index, verify.json for verify).
Use --help for full options and examples.
"""

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set


DEFAULT_DB_NAME = "integrity.db"
DEFAULT_HASH_ALGO = "sha256"
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
COMMIT_EVERY = 250
DEFAULT_WORKERS = 1
PROGRESS_EVERY = 1000  # Log progress every N files
HASH_BATCH_SIZE = 100  # Number of files to batch for parallel hashing


@dataclass
class FileInfo:
    """Information about a file to be hashed."""
    path: Path
    path_str: str
    filename: str
    size: int
    mtime_ns: int
    existing_hash: Optional[str] = None  # For index: previous hash if updating


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
    """Ignore files matching delete_by_filename criteria (prefix + size).

    Files are ignored if they start with '._' and are 4KB or smaller (< 4500 bytes).
    """
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


def _upsert_file_record(
    conn: sqlite3.Connection,
    path_str: str,
    filename: str,
    size: int,
    mtime_ns: int,
    digest: str,
    run_started: int,
) -> None:
    """Insert or update a file record in the files table."""
    conn.execute(
        """
        INSERT INTO files (path, filename, size, mtime_ns, hash, hash_algo, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            filename = excluded.filename,
            size = excluded.size,
            mtime_ns = excluded.mtime_ns,
            hash = excluded.hash,
            hash_algo = excluded.hash_algo,
            last_seen = excluded.last_seen
        """,
        (path_str, filename, size, mtime_ns, digest, DEFAULT_HASH_ALGO, run_started),
    )


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


def _process_hash_results_index(
    results: Iterable[HashResult],
    conn: sqlite3.Connection,
    run_started: int,
    stats: Dict[str, int],
    added: List[Dict[str, object]],
    updated: List[Dict[str, object]],
    errors: List[Dict[str, object]],
) -> int:
    """Process hash results and write to database. Returns count of successes."""
    processed = 0
    for result in results:
        fi = result.file_info
        if result.error:
            stats["errors"] += 1
            logging.warning(f"Failed to hash {fi.path}: {result.error}")
            errors.append({"path": fi.path_str, "error": result.error})
            continue

        digest = result.digest
        if fi.existing_hash is not None:
            stats["hashed_updated"] += 1
            updated.append(
                {
                    "path": fi.path_str,
                    "size": fi.size,
                    "mtime_ns": fi.mtime_ns,
                    "hash": digest,
                    "previous_hash": fi.existing_hash,
                }
            )
        else:
            stats["hashed_new"] += 1
            added.append(
                {
                    "path": fi.path_str,
                    "size": fi.size,
                    "mtime_ns": fi.mtime_ns,
                    "hash": digest,
                }
            )

        _upsert_file_record(conn, fi.path_str, fi.filename, fi.size, fi.mtime_ns, digest, run_started)
        processed += 1
    return processed


def index_files(
    root: Path,
    db_path: Path,
    exclude_exts: Set[str],
    report_path: Path,
    ignore_deleted: bool = False,
    workers: int = DEFAULT_WORKERS,
) -> Dict[str, object]:
    """Scan files, hash new or changed entries, and update the database."""
    stats = {
        "scanned": 0,
        "excluded": 0,
        "excluded_by_path": 0,
        "excluded_by_extension": 0,
        "excluded_ignore_deleted": 0,
        "hashed_new": 0,
        "hashed_updated": 0,
        "unchanged": 0,
        "errors": 0,
    }
    added: List[Dict[str, object]] = []
    updated: List[Dict[str, object]] = []
    errors: List[Dict[str, object]] = []

    run_started = int(time.time())
    excluded_paths = {
        str(db_path.resolve()),
        str(report_path.resolve()),
    }

    conn = connect_database(db_path)
    processed_since_commit = 0
    total_processed = 0
    last_progress_log = 0
    db_entries_after = 0

    def log_progress() -> None:
        nonlocal last_progress_log
        if total_processed - last_progress_log >= PROGRESS_EVERY:
            logging.info(
                f"Progress: scanned={stats['scanned']}, "
                f"hashed={stats['hashed_new'] + stats['hashed_updated']}, "
                f"unchanged={stats['unchanged']}, errors={stats['errors']}"
            )
            last_progress_log = total_processed

    try:
        if workers <= 1:
            # Single-threaded path (original behavior)
            for file_path in iter_files(root):
                path_str = str(file_path)
                if path_str in excluded_paths:
                    stats["excluded_by_path"] += 1
                    stats["excluded"] += 1
                    continue
                if file_path.suffix.lower() in exclude_exts:
                    stats["excluded_by_extension"] += 1
                    stats["excluded"] += 1
                    continue

                stats["scanned"] += 1
                try:
                    file_stat = file_path.stat()
                except OSError as exc:
                    stats["errors"] += 1
                    logging.warning(f"Failed to stat {file_path}: {exc}")
                    errors.append({"path": path_str, "error": str(exc)})
                    total_processed += 1
                    log_progress()
                    continue

                size = file_stat.st_size
                mtime_ns = file_stat.st_mtime_ns
                if ignore_deleted and should_ignore_file(file_path, size):
                    stats["excluded_ignore_deleted"] += 1
                    stats["excluded"] += 1
                    continue

                filename = file_path.name
                existing = conn.execute(
                    "SELECT size, mtime_ns, hash FROM files WHERE path = ?",
                    (path_str,),
                ).fetchone()

                if existing and existing["size"] == size and existing["mtime_ns"] == mtime_ns:
                    conn.execute(
                        "UPDATE files SET last_seen = ? WHERE path = ?",
                        (run_started, path_str),
                    )
                    stats["unchanged"] += 1
                else:
                    try:
                        digest = compute_hash(file_path)
                    except OSError as exc:
                        stats["errors"] += 1
                        logging.warning(f"Failed to hash {file_path}: {exc}")
                        errors.append({"path": path_str, "error": str(exc)})
                        total_processed += 1
                        log_progress()
                        continue

                    if existing:
                        stats["hashed_updated"] += 1
                        updated.append(
                            {
                                "path": path_str,
                                "size": size,
                                "mtime_ns": mtime_ns,
                                "hash": digest,
                                "previous_hash": existing["hash"],
                            }
                        )
                    else:
                        stats["hashed_new"] += 1
                        added.append(
                            {
                                "path": path_str,
                                "size": size,
                                "mtime_ns": mtime_ns,
                                "hash": digest,
                            }
                        )

                    _upsert_file_record(
                        conn, path_str, filename, size, mtime_ns, digest, run_started
                    )

                processed_since_commit += 1
                total_processed += 1
                log_progress()
                if processed_since_commit >= COMMIT_EVERY:
                    conn.commit()
                    processed_since_commit = 0

            if processed_since_commit:
                conn.commit()
        else:
            # Multi-threaded path
            logging.info(f"Using {workers} worker threads for hashing")
            hash_batch: List[FileInfo] = []

            def flush_batch() -> None:
                nonlocal processed_since_commit, total_processed
                if not hash_batch:
                    return
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(compute_hash_task, fi) for fi in hash_batch]
                    results = [f.result() for f in as_completed(futures)]
                processed = _process_hash_results_index(
                    results, conn, run_started, stats, added, updated, errors
                )
                processed_since_commit += processed
                total_processed += len(results)
                log_progress()
                if processed_since_commit >= COMMIT_EVERY:
                    conn.commit()
                    processed_since_commit = 0
                hash_batch.clear()

            for file_path in iter_files(root):
                path_str = str(file_path)
                if path_str in excluded_paths:
                    stats["excluded_by_path"] += 1
                    stats["excluded"] += 1
                    continue
                if file_path.suffix.lower() in exclude_exts:
                    stats["excluded_by_extension"] += 1
                    stats["excluded"] += 1
                    continue

                stats["scanned"] += 1
                try:
                    file_stat = file_path.stat()
                except OSError as exc:
                    stats["errors"] += 1
                    logging.warning(f"Failed to stat {file_path}: {exc}")
                    errors.append({"path": path_str, "error": str(exc)})
                    total_processed += 1
                    log_progress()
                    continue

                size = file_stat.st_size
                mtime_ns = file_stat.st_mtime_ns
                if ignore_deleted and should_ignore_file(file_path, size):
                    stats["excluded_ignore_deleted"] += 1
                    stats["excluded"] += 1
                    continue

                filename = file_path.name
                existing = conn.execute(
                    "SELECT size, mtime_ns, hash FROM files WHERE path = ?",
                    (path_str,),
                ).fetchone()

                if existing and existing["size"] == size and existing["mtime_ns"] == mtime_ns:
                    conn.execute(
                        "UPDATE files SET last_seen = ? WHERE path = ?",
                        (run_started, path_str),
                    )
                    stats["unchanged"] += 1
                    processed_since_commit += 1
                    total_processed += 1
                    log_progress()
                    if processed_since_commit >= COMMIT_EVERY:
                        conn.commit()
                        processed_since_commit = 0
                else:
                    # Queue for hashing
                    existing_hash = existing["hash"] if existing else None
                    hash_batch.append(FileInfo(
                        path=file_path,
                        path_str=path_str,
                        filename=filename,
                        size=size,
                        mtime_ns=mtime_ns,
                        existing_hash=existing_hash,
                    ))
                    if len(hash_batch) >= HASH_BATCH_SIZE:
                        flush_batch()

            # Flush remaining batch
            flush_batch()
            if processed_since_commit:
                conn.commit()
        db_entries_after = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    finally:
        conn.close()

    run_finished = int(time.time())

    summary: Dict[str, object] = {
        "total_files_walked": stats["scanned"] + stats["excluded"],
        "already_indexed_unchanged": stats["unchanged"],
        "hashed_this_run": stats["hashed_new"] + stats["hashed_updated"],
        "excluded_breakdown": {
            "by_extension": stats["excluded_by_extension"],
            "ignore_deleted": stats["excluded_ignore_deleted"],
            "by_path": stats["excluded_by_path"],
        },
        "db_entries_after": db_entries_after,
        "errors": stats["errors"],
    }

    logging.info(
        "Index summary: %d files walked | "
        "already indexed (unchanged): %d | hashed this run: %d | "
        "excluded (by ext: %d, ._* <4KB: %d, path: %d) | errors: %d | DB total: %d"
        % (
            summary["total_files_walked"],
            summary["already_indexed_unchanged"],
            summary["hashed_this_run"],
            stats["excluded_by_extension"],
            stats["excluded_ignore_deleted"],
            stats["excluded_by_path"],
            stats["errors"],
            db_entries_after,
        )
    )

    details: Dict[str, object] = {
        "added": added,
        "updated": updated,
        "errors": errors,
        "summary": summary,
    }
    if ignore_deleted:
        details["ignore_deleted"] = True
    if workers > 1:
        details["workers"] = workers
    report = build_report(
        root=root,
        db_path=db_path,
        hash_algo=DEFAULT_HASH_ALGO,
        exclude_exts=exclude_exts,
        stats=stats,
        run_started=run_started,
        run_finished=run_finished,
        mode="index",
        details=details,
    )
    return report


def _process_hash_result_verify(
    result: HashResult,
    conn: sqlite3.Connection,
    stats: Dict[str, int],
    mismatched: List[Dict[str, object]],
    untracked: List[Dict[str, object]],
    errors: List[Dict[str, object]],
    verified_hashes: Set[str],
    verified_paths: Set[str],
) -> None:
    """Process a single hash result for verification."""
    fi = result.file_info
    if result.error:
        stats["errors"] += 1
        logging.warning(f"Failed to hash {fi.path}: {result.error}")
        errors.append({"path": fi.path_str, "error": result.error})
        return

    digest = result.digest
    filename = fi.filename

    # Try hash-based lookup first (handles moved/renamed files)
    rows_by_hash = conn.execute(
        "SELECT path, filename, hash_algo FROM files WHERE hash = ?",
        (digest,),
    ).fetchall()

    # Try path-based lookup for backwards compatibility
    row_by_path = conn.execute(
        "SELECT path, filename, hash, hash_algo FROM files WHERE path = ?",
        (fi.path_str,),
    ).fetchone()

    # Determine which row to use
    row = None
    matched_by_hash = False
    if rows_by_hash:
        # Found by hash - check if filename matches (prefer exact match)
        for candidate in rows_by_hash:
            if candidate["filename"] == filename:
                row = candidate
                matched_by_hash = True
                verified_hashes.add(digest)
                verified_paths.add(candidate["path"])
                break
        # If no filename match, use first hash match (file may have been renamed)
        if not row:
            row = rows_by_hash[0]
            matched_by_hash = True
            verified_hashes.add(digest)
            verified_paths.add(row["path"])
    elif row_by_path:
        # Found by path (backwards compatibility)
        row = row_by_path
        verified_paths.add(fi.path_str)
        # Check if hash matches
        if row_by_path["hash"] != digest:
            # Path matches but hash doesn't - file was modified
            stats["mismatched"] += 1
            mismatched.append(
                {
                    "path": fi.path_str,
                    "size": fi.size,
                    "mtime_ns": fi.mtime_ns,
                    "expected_hash": row_by_path["hash"],
                    "actual_hash": digest,
                }
            )
            return

    if not row:
        stats["untracked"] += 1
        untracked.append(
            {
                "path": fi.path_str,
                "size": fi.size,
                "mtime_ns": fi.mtime_ns,
            }
        )
        return

    if row["hash_algo"] != DEFAULT_HASH_ALGO:
        stats["errors"] += 1
        logging.warning(
            f"Unsupported hash algorithm for {fi.path}: {row['hash_algo']}"
        )
        errors.append(
            {
                "path": fi.path_str,
                "error": f"Unsupported hash algorithm: {row['hash_algo']}",
            }
        )
        return

    # Hash matches
    stats["verified"] += 1
    if matched_by_hash and row["path"] != fi.path_str:
        logging.debug(f"File moved: {row['path']} -> {fi.path_str}")


def verify_files(
    root: Path,
    db_path: Path,
    exclude_exts: Set[str],
    report_path: Path,
    cross_root: bool = False,
    ignore_deleted: bool = False,
    workers: int = DEFAULT_WORKERS,
) -> Dict[str, object]:
    """Verify files by comparing stored hashes against current hashes.

    When cross_root is True, root is a different tree than the indexed one (e.g. backup).
    Verification is hash-only; "missing" = hashes in DB not seen under root.
    """
    stats = {
        "scanned": 0,
        "excluded": 0,
        "verified": 0,
        "mismatched": 0,
        "missing": 0,
        "untracked": 0,
        "errors": 0,
        "db_entries": 0,
    }
    mismatched: List[Dict[str, object]] = []
    missing: List[Dict[str, object]] = []
    untracked: List[Dict[str, object]] = []
    errors: List[Dict[str, object]] = []

    run_started = int(time.time())
    excluded_paths = {
        str(db_path.resolve()),
        str(report_path.resolve()),
    }

    conn = open_database_readonly(db_path)
    total_processed = 0
    last_progress_log = 0

    def log_progress() -> None:
        nonlocal last_progress_log
        if total_processed - last_progress_log >= PROGRESS_EVERY:
            logging.info(
                f"Progress: scanned={stats['scanned']}, "
                f"verified={stats['verified']}, mismatched={stats['mismatched']}, "
                f"errors={stats['errors']}"
            )
            last_progress_log = total_processed

    try:
        stats["db_entries"] = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        
        # Track which hashes have been verified (to avoid marking moved files as missing)
        verified_hashes: Set[str] = set()
        # Track which paths have been verified (for backwards compatibility)
        verified_paths: Set[str] = set()

        if workers <= 1:
            # Single-threaded path (original behavior)
            for file_path in iter_files(root):
                path_str = str(file_path)
                if path_str in excluded_paths:
                    stats["excluded"] += 1
                    continue
                if file_path.suffix.lower() in exclude_exts:
                    stats["excluded"] += 1
                    continue

                stats["scanned"] += 1
                try:
                    file_stat = file_path.stat()
                except OSError as exc:
                    stats["errors"] += 1
                    logging.warning(f"Failed to stat {file_path}: {exc}")
                    errors.append({"path": path_str, "error": str(exc)})
                    total_processed += 1
                    log_progress()
                    continue

                if ignore_deleted and should_ignore_file(file_path, file_stat.st_size):
                    stats["excluded"] += 1
                    continue

                file_info = FileInfo(
                    path=file_path,
                    path_str=path_str,
                    filename=file_path.name,
                    size=file_stat.st_size,
                    mtime_ns=file_stat.st_mtime_ns,
                )
                result = compute_hash_task(file_info)
                _process_hash_result_verify(
                    result,
                    conn,
                    stats,
                    mismatched,
                    untracked,
                    errors,
                    verified_hashes,
                    verified_paths,
                )

                total_processed += 1
                log_progress()
        else:
            # Multi-threaded path
            logging.info(f"Using {workers} worker threads for hashing")
            hash_batch: List[FileInfo] = []

            def flush_batch() -> None:
                nonlocal total_processed
                if not hash_batch:
                    return
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(compute_hash_task, fi) for fi in hash_batch]
                    for future in as_completed(futures):
                        result = future.result()
                        _process_hash_result_verify(
                            result, conn, stats, mismatched, untracked, errors,
                            verified_hashes, verified_paths
                        )
                        total_processed += 1
                        log_progress()
                hash_batch.clear()

            for file_path in iter_files(root):
                path_str = str(file_path)
                if path_str in excluded_paths:
                    stats["excluded"] += 1
                    continue
                if file_path.suffix.lower() in exclude_exts:
                    stats["excluded"] += 1
                    continue

                stats["scanned"] += 1
                try:
                    file_stat = file_path.stat()
                except OSError as exc:
                    stats["errors"] += 1
                    logging.warning(f"Failed to stat {file_path}: {exc}")
                    errors.append({"path": path_str, "error": str(exc)})
                    total_processed += 1
                    log_progress()
                    continue

                if ignore_deleted and should_ignore_file(file_path, file_stat.st_size):
                    stats["excluded"] += 1
                    continue

                # Queue for hashing
                hash_batch.append(FileInfo(
                    path=file_path,
                    path_str=path_str,
                    filename=file_path.name,
                    size=file_stat.st_size,
                    mtime_ns=file_stat.st_mtime_ns,
                ))
                if len(hash_batch) >= HASH_BATCH_SIZE:
                    flush_batch()

            # Flush remaining batch
            flush_batch()

        # Check for missing files: entries in DB that weren't found
        def _db_row_ignored(row: object) -> bool:
            if not ignore_deleted:
                return False
            r = row
            return (
                Path(r["path"]).name.startswith("._")
                and r["size"] < 4500
            )

        if cross_root:
            # Hash-based missing: DB was built from different root (e.g. source).
            # Missing = hashes in DB not seen when scanning root (e.g. backup).
            reported_missing_hashes: Set[str] = set()
            for row in conn.execute("SELECT path, hash, size FROM files"):
                if _db_row_ignored(row):
                    continue
                record_path = Path(row["path"])
                if record_path.suffix.lower() in exclude_exts:
                    continue
                record_str = str(record_path)
                if record_str in excluded_paths:
                    continue
                if row["hash"] in verified_hashes or record_str in verified_paths:
                    continue
                if row["hash"] in reported_missing_hashes:
                    continue
                reported_missing_hashes.add(row["hash"])
                stats["missing"] += 1
                missing.append({"path": record_str, "hash": row["hash"]})
        else:
            # Path-based missing: same root as index. Missing = in DB, under root, not on disk.
            for row in conn.execute("SELECT path, hash, size FROM files"):
                if _db_row_ignored(row):
                    continue
                record_path = Path(row["path"])
                if not is_under_root(record_path, root):
                    continue
                if record_path.suffix.lower() in exclude_exts:
                    continue
                record_str = str(record_path)
                if record_str in excluded_paths:
                    continue
                if row["hash"] in verified_hashes or record_str in verified_paths:
                    continue
                if not record_path.exists():
                    stats["missing"] += 1
                    missing.append({"path": record_str})
    finally:
        conn.close()

    run_finished = int(time.time())
    logging.info(
        f"Completed: scanned={stats['scanned']}, verified={stats['verified']}, "
        f"mismatched={stats['mismatched']}, missing={stats['missing']}, "
        f"untracked={stats['untracked']}, errors={stats['errors']}"
    )
    details: Dict[str, object] = {
        "mismatched": mismatched,
        "missing": missing,
        "untracked": untracked,
        "errors": errors,
    }
    if cross_root:
        details["cross_root"] = True
    if ignore_deleted:
        details["ignore_deleted"] = True
    if workers > 1:
        details["workers"] = workers

    report = build_report(
        root=root,
        db_path=db_path,
        hash_algo=DEFAULT_HASH_ALGO,
        exclude_exts=exclude_exts,
        stats=stats,
        run_started=run_started,
        run_finished=run_finished,
        mode="verify",
        details=details,
    )
    return report


def write_report(report: Dict[str, object], report_path: Path) -> None:
    """Write report to file."""
    report_json = json.dumps(report, indent=2, sort_keys=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_json, encoding='utf-8')
    logging.info(f"Report written to {report_path}")


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Index file hashes (index) or verify integrity (verify). '
                    'Scan with --root; store/compare via SQLite.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  index:
    python unaltered.py index --root /path/to/photos --db integrity.db
    python unaltered.py index --root /path/to/photos --exclude-ext .tmp,.db
    python unaltered.py index --root /path/to/photos --ignore-deleted
    python unaltered.py index --root /path/to/photos --report my_report.json
    python unaltered.py index --root /path/to/photos --workers 4

  verify:
    python unaltered.py verify --root /path/to/photos --db integrity.db
    python unaltered.py verify --root /path/to/backup --db integrity.db --cross-root
    python unaltered.py verify --root /path/to/photos --workers 4
        """,
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    index_parser = subparsers.add_parser(
        'index',
        help='Scan files and store hashes for new or changed entries',
    )
    index_parser.add_argument(
        '--root',
        type=Path,
        required=True,
        help='Root directory to scan recursively',
    )
    index_parser.add_argument(
        '--db',
        type=Path,
        default=Path(DEFAULT_DB_NAME),
        help=f'Path to SQLite database (default: {DEFAULT_DB_NAME})',
    )
    index_parser.add_argument(
        '--exclude-ext',
        action='append',
        default=[],
        help='Extensions to exclude (e.g. .tmp,.db). Comma-separated or repeatable.',
    )
    index_parser.add_argument(
        '--report',
        type=Path,
        default=Path('report.json'),
        help='JSON report path (default: report.json)',
    )
    index_parser.add_argument(
        '--ignore-deleted',
        action='store_true',
        help='Ignore ._* files < 4KB (matches delete_by_filename criteria)',
    )
    index_parser.add_argument(
        '--log',
        type=Path,
        help='Write log output to this file',
    )
    index_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose (debug) logging',
    )
    index_parser.add_argument(
        '--workers',
        type=int,
        default=DEFAULT_WORKERS,
        help=f'Number of parallel hashing threads (default: {DEFAULT_WORKERS})',
    )

    verify_parser = subparsers.add_parser(
        'verify',
        help='Verify files by comparing stored hashes to current hashes',
    )
    verify_parser.add_argument(
        '--root',
        type=Path,
        required=True,
        help='Root directory to scan recursively',
    )
    verify_parser.add_argument(
        '--db',
        type=Path,
        default=Path(DEFAULT_DB_NAME),
        help=f'Path to SQLite database (default: {DEFAULT_DB_NAME})',
    )
    verify_parser.add_argument(
        '--exclude-ext',
        action='append',
        default=[],
        help='Extensions to exclude (e.g. .tmp,.db). Comma-separated or repeatable.',
    )
    verify_parser.add_argument(
        '--report',
        type=Path,
        default=Path('verify.json'),
        help='JSON report path (default: verify.json)',
    )
    verify_parser.add_argument(
        '--cross-root',
        action='store_true',
        help='Verify a different tree (e.g. backup): index was built from source, '
             'root is backup. Missing = hashes in DB not found under root.',
    )
    verify_parser.add_argument(
        '--ignore-deleted',
        action='store_true',
        help='Ignore ._* files < 4KB (matches delete_by_filename criteria)',
    )
    verify_parser.add_argument(
        '--log',
        type=Path,
        help='Write log output to this file',
    )
    verify_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose (debug) logging',
    )
    verify_parser.add_argument(
        '--workers',
        type=int,
        default=DEFAULT_WORKERS,
        help=f'Number of parallel hashing threads (default: {DEFAULT_WORKERS})',
    )

    args = parser.parse_args()

    setup_logging(getattr(args, 'log', None), getattr(args, 'verbose', False))

    if args.command == 'index':
        root = args.root.resolve()
        if not root.exists():
            logging.error(f"Root directory does not exist: {root}")
            sys.exit(1)
        if not root.is_dir():
            logging.error(f"Root path is not a directory: {root}")
            sys.exit(1)

        exclude_exts = parse_exclude_extensions(args.exclude_ext)
        report = index_files(
            root=root,
            db_path=args.db,
            exclude_exts=exclude_exts,
            report_path=args.report,
            ignore_deleted=args.ignore_deleted,
            workers=args.workers,
        )
        write_report(report, args.report)
        sys.exit(0)

    if args.command == 'verify':
        root = args.root.resolve()
        if not root.exists():
            logging.error(f"Root directory does not exist: {root}")
            sys.exit(1)
        if not root.is_dir():
            logging.error(f"Root path is not a directory: {root}")
            sys.exit(1)

        exclude_exts = parse_exclude_extensions(args.exclude_ext)
        try:
            report = verify_files(
                root=root,
                db_path=args.db,
                exclude_exts=exclude_exts,
                report_path=args.report,
                cross_root=args.cross_root,
                ignore_deleted=args.ignore_deleted,
                workers=args.workers,
            )
        except FileNotFoundError as exc:
            logging.error(str(exc))
            sys.exit(1)

        write_report(report, args.report)

        stats = report.get("stats", {})
        if stats.get("mismatched", 0) or stats.get("missing", 0) or stats.get("errors", 0):
            sys.exit(1)
        sys.exit(0)


if __name__ == "__main__":
    main()
