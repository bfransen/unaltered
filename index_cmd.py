"""
Index command: scan files, hash new or changed entries, update the database.
"""

import logging
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set

from common import (
    COMMIT_EVERY,
    DEFAULT_HASH_ALGO,
    DEFAULT_WORKERS,
    FileInfo,
    HashResult,
    HASH_BATCH_SIZE,
    PROGRESS_EVERY,
    build_report,
    connect_database,
    compute_hash,
    compute_hash_task,
    iter_files,
    should_ignore_file,
)


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
    progress_callback: Optional[Callable[[int, Dict[str, int]], None]] = None,
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

    def emit_progress() -> None:
        if progress_callback:
            progress_callback(total_processed, dict(stats))

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
                    emit_progress()
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
                        emit_progress()
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
                emit_progress()
                if processed_since_commit >= COMMIT_EVERY:
                    conn.commit()
                    processed_since_commit = 0

            if processed_since_commit:
                conn.commit()
        else:
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
                emit_progress()
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
                    emit_progress()
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
                    emit_progress()
                    if processed_since_commit >= COMMIT_EVERY:
                        conn.commit()
                        processed_since_commit = 0
                else:
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
    emit_progress()
    return report
