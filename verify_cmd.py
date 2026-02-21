"""
Verify command: re-hash files and compare to stored hashes.
"""

import logging
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, DefaultDict
from collections import defaultdict

from common import (
    DEFAULT_HASH_ALGO,
    DEFAULT_WORKERS,
    FileInfo,
    HashResult,
    HASH_BATCH_SIZE,
    PROGRESS_EVERY,
    build_report,
    is_under_root,
    open_database_readonly,
    compute_hash_task,
    iter_files,
    should_ignore_file,
)


def _process_hash_result_verify(
    result: HashResult,
    conn: sqlite3.Connection,
    stats: Dict[str, int],
    mismatched: List[Dict[str, object]],
    moved: List[Dict[str, object]],
    untracked: List[Dict[str, object]],
    errors: List[Dict[str, object]],
    verified_hashes: Set[str],
    verified_paths: Set[str],
    hash_to_paths: DefaultDict[str, Set[str]],
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

    rows_by_hash = conn.execute(
        "SELECT path, filename, hash_algo FROM files WHERE hash = ?",
        (digest,),
    ).fetchall()

    row_by_path = conn.execute(
        "SELECT path, filename, hash, hash_algo FROM files WHERE path = ?",
        (fi.path_str,),
    ).fetchone()

    row = None
    matched_by_hash = False
    if rows_by_hash:
        for candidate in rows_by_hash:
            if candidate["filename"] == filename:
                row = candidate
                matched_by_hash = True
                verified_hashes.add(digest)
                verified_paths.add(fi.path_str)
                hash_to_paths[digest].add(fi.path_str)
                break
        if not row:
            row = rows_by_hash[0]
            matched_by_hash = True
            verified_hashes.add(digest)
            verified_paths.add(fi.path_str)
            hash_to_paths[digest].add(fi.path_str)
    elif row_by_path:
        row = row_by_path
        verified_paths.add(fi.path_str)
        hash_to_paths[digest].add(fi.path_str)
        if row_by_path["hash"] != digest:
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

    stats["verified"] += 1
    # Move vs duplicate is decided in a post-scan pass using hash_to_paths


def _verify_single_threaded(
    root: Path,
    exclude_exts: Set[str],
    excluded_paths: Set[str],
    ignore_deleted: bool,
    conn: sqlite3.Connection,
    stats: Dict[str, int],
    mismatched: List[Dict[str, object]],
    moved: List[Dict[str, object]],
    untracked: List[Dict[str, object]],
    errors: List[Dict[str, object]],
    verified_hashes: Set[str],
    verified_paths: Set[str],
    hash_to_paths: DefaultDict[str, Set[str]],
    total_processed_ref: List[int],
    tick_progress: Callable[[], None],
) -> None:
    """Scan files under root and verify each one by hashing in the current thread."""
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
            total_processed_ref[0] += 1
            tick_progress()
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
            moved,
            untracked,
            errors,
            verified_hashes,
            verified_paths,
            hash_to_paths,
        )
        total_processed_ref[0] += 1
        tick_progress()


def _verify_multi_threaded(
    root: Path,
    exclude_exts: Set[str],
    excluded_paths: Set[str],
    ignore_deleted: bool,
    workers: int,
    conn: sqlite3.Connection,
    stats: Dict[str, int],
    mismatched: List[Dict[str, object]],
    moved: List[Dict[str, object]],
    untracked: List[Dict[str, object]],
    errors: List[Dict[str, object]],
    verified_hashes: Set[str],
    verified_paths: Set[str],
    hash_to_paths: DefaultDict[str, Set[str]],
    total_processed_ref: List[int],
    tick_progress: Callable[[], None],
) -> None:
    """Scan files under root and verify in batches using a thread pool."""
    logging.info(f"Using {workers} worker threads for hashing")
    hash_batch: List[FileInfo] = []

    def flush_batch() -> None:
        if not hash_batch:
            return
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(compute_hash_task, fi) for fi in hash_batch]
            for future in as_completed(futures):
                result = future.result()
                _process_hash_result_verify(
                    result, conn, stats, mismatched, moved, untracked, errors,
                    verified_hashes, verified_paths, hash_to_paths,
                )
                total_processed_ref[0] += 1
                tick_progress()
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
            total_processed_ref[0] += 1
            tick_progress()
            continue

        if ignore_deleted and should_ignore_file(file_path, file_stat.st_size):
            stats["excluded"] += 1
            continue

        hash_batch.append(FileInfo(
            path=file_path,
            path_str=path_str,
            filename=file_path.name,
            size=file_stat.st_size,
            mtime_ns=file_stat.st_mtime_ns,
        ))
        if len(hash_batch) >= HASH_BATCH_SIZE:
            flush_batch()

    flush_batch()


def verify_files(
    root: Path,
    db_path: Path,
    exclude_exts: Set[str],
    report_path: Path,
    cross_root: bool = False,
    ignore_deleted: bool = False,
    workers: int = DEFAULT_WORKERS,
    progress_callback: Optional[Callable[[int, Dict[str, int]], None]] = None,
) -> Dict[str, object]:
    """Verify files by comparing stored hashes against current hashes.

    When cross_root is True, root is a different tree than the indexed one (e.g. backup).
    Verification is hash-only; "missing" = hashes in DB not seen under root.
    """
    stats = {
        "scanned": 0,
        "excluded": 0,
        "verified": 0,
        "moved": 0,
        "mismatched": 0,
        "missing": 0,
        "untracked": 0,
        "duplicates": 0,
        "errors": 0,
        "db_entries": 0,
    }
    mismatched: List[Dict[str, object]] = []
    moved: List[Dict[str, object]] = []
    missing: List[Dict[str, object]] = []
    untracked: List[Dict[str, object]] = []
    duplicates: List[Dict[str, object]] = []
    errors: List[Dict[str, object]] = []

    run_started = int(time.time())
    excluded_paths = {
        str(db_path.resolve()),
        str(report_path.resolve()),
    }

    conn = open_database_readonly(db_path)
    total_processed_ref: List[int] = [0]
    last_progress_log = [0]

    def log_progress() -> None:
        n = total_processed_ref[0]
        if n - last_progress_log[0] >= PROGRESS_EVERY:
            logging.info(
                f"Progress: scanned={stats['scanned']}, "
                f"verified={stats['verified']}, mismatched={stats['mismatched']}, "
                f"errors={stats['errors']}"
            )
            last_progress_log[0] = n

    def tick_progress() -> None:
        log_progress()
        if progress_callback:
            progress_callback(total_processed_ref[0], dict(stats))

    try:
        stats["db_entries"] = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        verified_hashes: Set[str] = set()
        verified_paths: Set[str] = set()
        hash_to_paths: DefaultDict[str, Set[str]] = defaultdict(set)

        if workers <= 1:
            _verify_single_threaded(
                root=root,
                exclude_exts=exclude_exts,
                excluded_paths=excluded_paths,
                ignore_deleted=ignore_deleted,
                conn=conn,
                stats=stats,
                mismatched=mismatched,
                moved=moved,
                untracked=untracked,
                errors=errors,
                verified_hashes=verified_hashes,
                verified_paths=verified_paths,
                hash_to_paths=hash_to_paths,
                total_processed_ref=total_processed_ref,
                tick_progress=tick_progress,
            )
        else:
            _verify_multi_threaded(
                root=root,
                exclude_exts=exclude_exts,
                excluded_paths=excluded_paths,
                ignore_deleted=ignore_deleted,
                workers=workers,
                conn=conn,
                stats=stats,
                mismatched=mismatched,
                moved=moved,
                untracked=untracked,
                errors=errors,
                verified_hashes=verified_hashes,
                verified_paths=verified_paths,
                hash_to_paths=hash_to_paths,
                total_processed_ref=total_processed_ref,
                tick_progress=tick_progress,
            )

        def _db_row_ignored(row: object) -> bool:
            if not ignore_deleted:
                return False
            r = row
            return (
                Path(r["path"]).name.startswith("._")
                and r["size"] < 4500
            )

        # Post-scan: distinguish moves (hash at exactly one path, different from DB) from duplicates (hash at multiple paths)
        if not cross_root:
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
                if record_str in verified_paths:
                    continue
                if row["hash"] not in verified_hashes:
                    continue
                current_paths = hash_to_paths.get(row["hash"], set())
                if len(current_paths) == 1:
                    (current_path,) = current_paths
                    if current_path != record_str:
                        stats["moved"] += 1
                        moved.append(
                            {
                                "stored_path": record_str,
                                "current_path": current_path,
                                "size": row["size"],
                                "hash": row["hash"],
                            }
                        )
                        logging.debug(f"File moved: {record_str} -> {current_path}")

            for digest, paths in hash_to_paths.items():
                if len(paths) <= 1:
                    continue
                size_row = conn.execute(
                    "SELECT size FROM files WHERE hash = ? LIMIT 1", (digest,)
                ).fetchone()
                size = size_row["size"] if size_row else None
                stats["duplicates"] += 1
                duplicates.append(
                    {"hash": digest, "paths": sorted(paths), "size": size}
                )

        if cross_root:
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
        f"moved={stats['moved']}, mismatched={stats['mismatched']}, missing={stats['missing']}, "
        f"untracked={stats['untracked']}, duplicates={stats['duplicates']}, errors={stats['errors']}"
    )
    details: Dict[str, object] = {
        "mismatched": mismatched,
        "moved": moved,
        "missing": missing,
        "untracked": untracked,
        "duplicates": duplicates,
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
    if progress_callback:
        progress_callback(total_processed_ref[0], dict(stats))
    return report
