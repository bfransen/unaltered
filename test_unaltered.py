#!/usr/bin/env python3
"""
Unit tests for unaltered.py hashing and indexing logic.
"""

import hashlib
import logging
import os
import sqlite3
import time
from pathlib import Path

import pytest

from unaltered import (
    compute_hash,
    index_files,
    parse_exclude_extensions,
    verify_files,
)


logging.basicConfig(level=logging.WARNING)


def _write_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _fetch_db_rows(db_path: Path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT path, size, mtime_ns, hash, hash_algo FROM files ORDER BY path"
        ).fetchall()
    finally:
        conn.close()


def test_parse_exclude_extensions_normalizes():
    exclude = parse_exclude_extensions(["tmp,.db", ".log", "  .MOV , mp4  "])
    assert exclude == {".tmp", ".db", ".log", ".mov", ".mp4"}


def test_index_files_records_new_and_excludes(tmp_path: Path):
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"

    _write_file(root / "a.txt", b"alpha")
    _write_file(root / "b.tmp", b"temp")
    _write_file(root / "nested" / "c.bin", b"binary")

    report = index_files(
        root=root,
        db_path=db_path,
        exclude_exts={".tmp"},
        report_path=report_path,
    )

    assert report["stats"]["scanned"] == 2
    assert report["stats"]["excluded"] == 1
    assert report["stats"]["hashed_new"] == 2
    assert report["stats"]["hashed_updated"] == 0
    assert report["stats"]["unchanged"] == 0
    assert len(report["added"]) == 2

    added_paths = {item["path"] for item in report["added"]}
    assert added_paths == {
        str(root / "a.txt"),
        str(root / "nested" / "c.bin"),
    }

    rows = _fetch_db_rows(db_path)
    assert len(rows) == 2
    row_map = {row["path"]: row for row in rows}
    assert row_map[str(root / "a.txt")]["hash"] == hashlib.sha256(b"alpha").hexdigest()
    assert row_map[str(root / "nested" / "c.bin")]["hash_algo"] == "sha256"


def test_index_files_updates_on_change_and_tracks_unchanged(tmp_path: Path):
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"
    file_path = root / "photo.jpg"

    initial_content = b"version-one"
    _write_file(file_path, initial_content)
    first = index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )
    assert first["stats"]["hashed_new"] == 1

    previous_hash = hashlib.sha256(initial_content).hexdigest()
    new_content = b"version-two"
    _write_file(file_path, new_content)
    mtime = file_path.stat().st_mtime + 10
    time.sleep(0.01)
    os.utime(file_path, (mtime, mtime))

    second = index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    assert second["stats"]["hashed_updated"] == 1
    assert second["stats"]["hashed_new"] == 0
    assert len(second["updated"]) == 1
    assert second["updated"][0]["previous_hash"] == previous_hash

    rows = _fetch_db_rows(db_path)
    assert len(rows) == 1
    assert rows[0]["hash"] == compute_hash(file_path)

    third = index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )
    assert third["stats"]["unchanged"] == 1


def test_verify_files_reports_mismatch_and_untracked(tmp_path: Path):
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"

    tracked_path = root / "tracked.txt"
    _write_file(tracked_path, b"original")
    _write_file(root / "stable.txt", b"stable")

    index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    _write_file(tracked_path, b"changed")
    untracked_path = root / "new.txt"
    _write_file(untracked_path, b"new")

    report = verify_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    stats = report["stats"]
    assert stats["mismatched"] == 1
    assert stats["verified"] == 1
    assert stats["untracked"] == 1
    assert stats["missing"] == 0

    mismatch_paths = {item["path"] for item in report["mismatched"]}
    assert mismatch_paths == {str(tracked_path)}
    untracked_paths = {item["path"] for item in report["untracked"]}
    assert untracked_paths == {str(untracked_path)}


def test_verify_files_reports_missing(tmp_path: Path):
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"
    missing_path = root / "gone.txt"

    _write_file(missing_path, b"data")
    index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    missing_path.unlink()

    report = verify_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    stats = report["stats"]
    assert stats["missing"] == 1
    assert report["missing"][0]["path"] == str(missing_path)


def test_verify_files_handles_moved_files_by_hash(tmp_path: Path):
    """Test that verify can find files that have been moved/renamed using hash-based matching."""
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"
    
    # Create file in original location
    original_path = root / "old_folder" / "photo.jpg"
    _write_file(original_path, b"photo content")
    
    # Index the file
    index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )
    
    # Move file to new location (simulating folder rename)
    new_path = root / "2024-01-15_January_15_2024" / "photo.jpg"
    new_path.parent.mkdir(parents=True, exist_ok=True)
    new_path.write_bytes(original_path.read_bytes())
    original_path.unlink()
    original_path.parent.rmdir()
    
    # Verify - should find file by hash even though path changed
    report = verify_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )
    
    stats = report["stats"]
    # File should be verified (found by hash)
    assert stats["verified"] == 1
    # Path changed should be reported as moved
    assert stats["moved"] == 1
    # Original path should NOT be marked as missing (because hash was verified)
    assert stats["missing"] == 0
    # New path should NOT be marked as untracked (because hash matched)
    assert stats["untracked"] == 0
    # Move details should include old and new paths
    assert len(report["moved"]) == 1
    assert report["moved"][0]["stored_path"] == str(original_path)
    assert report["moved"][0]["current_path"] == str(new_path)


def test_verify_files_reports_duplicates_not_moved_when_same_hash_at_multiple_paths(
    tmp_path: Path,
):
    """When the same file (same hash) exists at multiple paths, report duplicates, not moves."""
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"

    content = b"same content"
    path_a = root / "folder_a" / "photo.jpg"
    path_b = root / "folder_b" / "photo.jpg"
    _write_file(path_a, content)
    _write_file(path_b, content)

    index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    report = verify_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    stats = report["stats"]
    assert stats["verified"] == 2
    assert stats["duplicates"] == 1
    assert stats["moved"] == 0
    dup = report["duplicates"]
    assert len(dup) == 1
    assert dup[0]["hash"] == hashlib.sha256(content).hexdigest()
    assert set(dup[0]["paths"]) == {str(path_a), str(path_b)}


def test_verify_files_reports_all_file_operations_in_single_run(tmp_path: Path):
    """One verify run should capture move, duplicate, delete, add, and modify."""
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"

    moved_count = 2
    duplicate_count = 3
    deleted_count = 4
    modified_count = 5
    added_count = 6
    stable_count = 2

    moved_from_paths = [
        root / "tracked" / "moved" / f"move_{idx}.txt"
        for idx in range(moved_count)
    ]
    duplicate_source_paths = [
        root / "tracked" / "duplicates" / f"source_{idx}.txt"
        for idx in range(duplicate_count)
    ]
    deleted_paths = [
        root / "tracked" / "deleted" / f"delete_{idx}.txt"
        for idx in range(deleted_count)
    ]
    modified_paths = [
        root / "tracked" / "modified" / f"modify_{idx}.txt"
        for idx in range(modified_count)
    ]
    stable_paths = [
        root / "tracked" / "stable" / f"stable_{idx}.txt"
        for idx in range(stable_count)
    ]

    for idx, path in enumerate(moved_from_paths):
        _write_file(path, f"move-before-{idx}".encode("utf-8"))
    for idx, path in enumerate(duplicate_source_paths):
        _write_file(path, f"duplicate-content-{idx}".encode("utf-8"))
    for idx, path in enumerate(deleted_paths):
        _write_file(path, f"delete-content-{idx}".encode("utf-8"))
    for idx, path in enumerate(modified_paths):
        _write_file(path, f"modify-before-{idx}".encode("utf-8"))
    for idx, path in enumerate(stable_paths):
        _write_file(path, f"stable-content-{idx}".encode("utf-8"))

    index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    moved_to_paths = []
    for idx, source_path in enumerate(moved_from_paths):
        target_path = root / "current" / "moved" / f"move_{idx}.txt"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.rename(target_path)
        moved_to_paths.append(target_path)

    duplicate_copy_paths = []
    for idx, source_path in enumerate(duplicate_source_paths):
        copy_path = root / "current" / "duplicates" / f"copy_{idx}.txt"
        _write_file(copy_path, source_path.read_bytes())
        duplicate_copy_paths.append(copy_path)

    for path in deleted_paths:
        path.unlink()

    expected_mismatched_hashes = {}
    for idx, path in enumerate(modified_paths):
        before_hash = hashlib.sha256(f"modify-before-{idx}".encode("utf-8")).hexdigest()
        after_hash = hashlib.sha256(f"modify-after-{idx}".encode("utf-8")).hexdigest()
        expected_mismatched_hashes[str(path)] = (before_hash, after_hash)
        _write_file(path, f"modify-after-{idx}".encode("utf-8"))

    added_paths = []
    for idx in range(added_count):
        added_path = root / "current" / "added" / f"added_{idx}.txt"
        _write_file(added_path, f"added-content-{idx}".encode("utf-8"))
        added_paths.append(added_path)

    report = verify_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    stats = report["stats"]
    expected_verified = moved_count + (duplicate_count * 2) + stable_count
    expected_scanned = expected_verified + modified_count + added_count
    assert stats["scanned"] == expected_scanned
    assert stats["verified"] == expected_verified
    assert stats["moved"] == moved_count
    assert stats["duplicates"] == duplicate_count
    assert stats["missing"] == deleted_count
    assert stats["mismatched"] == modified_count
    assert stats["untracked"] == added_count
    assert stats["errors"] == 0

    expected_moves = {
        str(source): str(target)
        for source, target in zip(moved_from_paths, moved_to_paths)
    }
    actual_moves = {
        item["stored_path"]: item["current_path"] for item in report["moved"]
    }
    assert actual_moves == expected_moves

    expected_duplicate_hashes = {
        hashlib.sha256(f"duplicate-content-{idx}".encode("utf-8")).hexdigest()
        for idx in range(duplicate_count)
    }
    actual_duplicate_hashes = {item["hash"] for item in report["duplicates"]}
    assert actual_duplicate_hashes == expected_duplicate_hashes

    expected_duplicate_paths = {
        frozenset({str(source), str(copy_path)})
        for source, copy_path in zip(duplicate_source_paths, duplicate_copy_paths)
    }
    actual_duplicate_paths = {
        frozenset(item["paths"]) for item in report["duplicates"]
    }
    assert actual_duplicate_paths == expected_duplicate_paths

    assert {item["path"] for item in report["missing"]} == {
        str(path) for path in deleted_paths
    }

    actual_mismatched_hashes = {
        item["path"]: (item["expected_hash"], item["actual_hash"])
        for item in report["mismatched"]
    }
    assert actual_mismatched_hashes == expected_mismatched_hashes

    assert {item["path"] for item in report["untracked"]} == {
        str(path) for path in added_paths
    }


def test_verify_files_cross_root_backup(tmp_path: Path):
    """Test --cross-root: index source, verify backup (different root)."""
    source = tmp_path / "source"
    backup = tmp_path / "backup"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"

    _write_file(source / "folder_a" / "f1.txt", b"alpha")
    _write_file(source / "folder_a" / "f2.txt", b"beta")
    _write_file(source / "folder_b" / "f3.txt", b"gamma")

    index_files(
        root=source,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    # Backup has same content, different structure (e.g. date-based folders)
    _write_file(backup / "2024-01-10" / "f1.txt", b"alpha")
    _write_file(backup / "2024-01-10" / "f2.txt", b"beta")
    _write_file(backup / "2024-01-15" / "f3.txt", b"gamma")

    report = verify_files(
        root=backup,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
        cross_root=True,
    )

    stats = report["stats"]
    assert stats["verified"] == 3
    assert stats["missing"] == 0
    assert stats["untracked"] == 0
    assert report.get("cross_root") is True

    # Remove one file from backup; verify should report 1 missing
    (backup / "2024-01-10" / "f2.txt").unlink()
    report2 = verify_files(
        root=backup,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
        cross_root=True,
    )
    assert report2["stats"]["missing"] == 1
    assert "hash" in report2["missing"][0]
    assert report2["missing"][0]["hash"] == hashlib.sha256(b"beta").hexdigest()


def test_ignore_deleted_prefix_and_size(tmp_path: Path):
    """Test --ignore-deleted: ._* files < 4KB are excluded from index and verify."""
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"

    _write_file(root / "real.txt", b"content")
    _write_file(root / "._small", b"x" * 100)       # ._* and < 4500
    _write_file(root / "._big", b"x" * 5000)        # ._* but >= 4500, should be indexed
    _write_file(root / "normal_small.txt", b"y")    # not ._*, should be indexed

    report = index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
        ignore_deleted=True,
    )

    assert report["stats"]["excluded"] == 1
    assert report["stats"]["hashed_new"] == 3
    assert report.get("ignore_deleted") is True
    added_paths = {item["path"] for item in report["added"]}
    assert str(root / "._small") not in added_paths
    assert str(root / "._big") in added_paths
    assert str(root / "real.txt") in added_paths
    assert str(root / "normal_small.txt") in added_paths

    verify_report = verify_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
        ignore_deleted=True,
    )
    assert verify_report["stats"]["verified"] == 3
    assert verify_report["stats"]["excluded"] == 1
    assert verify_report["stats"]["missing"] == 0


def test_index_files_multithreaded_produces_same_results(tmp_path: Path):
    """Test that multi-threaded index produces same results as single-threaded."""
    root = tmp_path / "root"
    db_single = tmp_path / "single.db"
    db_multi = tmp_path / "multi.db"
    report_path = tmp_path / "report.json"

    # Create several files of varying sizes
    _write_file(root / "a.txt", b"alpha")
    _write_file(root / "b.txt", b"beta" * 100)
    _write_file(root / "c.txt", b"gamma" * 1000)
    _write_file(root / "nested" / "d.txt", b"delta")
    _write_file(root / "nested" / "deep" / "e.txt", b"epsilon" * 500)

    # Index with single thread
    report_single = index_files(
        root=root,
        db_path=db_single,
        exclude_exts=set(),
        report_path=report_path,
        workers=1,
    )

    # Index with multiple threads
    report_multi = index_files(
        root=root,
        db_path=db_multi,
        exclude_exts=set(),
        report_path=report_path,
        workers=4,
    )

    # Stats should match
    assert report_single["stats"]["scanned"] == report_multi["stats"]["scanned"]
    assert report_single["stats"]["hashed_new"] == report_multi["stats"]["hashed_new"]
    assert report_single["stats"]["errors"] == report_multi["stats"]["errors"]

    # Report should indicate workers used
    assert report_multi.get("workers") == 4
    assert "workers" not in report_single  # Single-threaded doesn't add this

    # Database contents should match
    rows_single = _fetch_db_rows(db_single)
    rows_multi = _fetch_db_rows(db_multi)

    assert len(rows_single) == len(rows_multi)

    # Build hash maps to compare (order may differ)
    hash_map_single = {row["path"]: row["hash"] for row in rows_single}
    hash_map_multi = {row["path"]: row["hash"] for row in rows_multi}

    assert hash_map_single == hash_map_multi


def test_verify_files_multithreaded_produces_same_results(tmp_path: Path):
    """Test that multi-threaded verify produces same results as single-threaded."""
    root = tmp_path / "root"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"

    # Create files
    _write_file(root / "a.txt", b"alpha")
    _write_file(root / "b.txt", b"beta" * 100)
    _write_file(root / "c.txt", b"gamma" * 1000)
    _write_file(root / "nested" / "d.txt", b"delta")

    # Index first
    index_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    # Modify one file and add an untracked file
    _write_file(root / "a.txt", b"modified")
    _write_file(root / "new.txt", b"untracked")

    # Verify with single thread
    report_single = verify_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
        workers=1,
    )

    # Verify with multiple threads
    report_multi = verify_files(
        root=root,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
        workers=4,
    )

    # Stats should match
    assert report_single["stats"]["scanned"] == report_multi["stats"]["scanned"]
    assert report_single["stats"]["verified"] == report_multi["stats"]["verified"]
    assert report_single["stats"]["mismatched"] == report_multi["stats"]["mismatched"]
    assert report_single["stats"]["untracked"] == report_multi["stats"]["untracked"]
    assert report_single["stats"]["errors"] == report_multi["stats"]["errors"]

    # Report should indicate workers used
    assert report_multi.get("workers") == 4

    # Mismatched files should be the same
    mismatch_single = {item["path"] for item in report_single["mismatched"]}
    mismatch_multi = {item["path"] for item in report_multi["mismatched"]}
    assert mismatch_single == mismatch_multi

    # Untracked files should be the same
    untracked_single = {item["path"] for item in report_single["untracked"]}
    untracked_multi = {item["path"] for item in report_multi["untracked"]}
    assert untracked_single == untracked_multi


def test_verify_files_multithreaded_cross_root(tmp_path: Path):
    """Test that multi-threaded verify works correctly with --cross-root."""
    source = tmp_path / "source"
    backup = tmp_path / "backup"
    db_path = tmp_path / "integrity.db"
    report_path = tmp_path / "report.json"

    # Create source files
    _write_file(source / "a.txt", b"alpha")
    _write_file(source / "b.txt", b"beta")
    _write_file(source / "c.txt", b"gamma")

    # Index source
    index_files(
        root=source,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
    )

    # Create backup with different structure but same content
    _write_file(backup / "folder1" / "a.txt", b"alpha")
    _write_file(backup / "folder2" / "b.txt", b"beta")
    # c.txt is missing from backup

    # Verify with multiple threads
    report = verify_files(
        root=backup,
        db_path=db_path,
        exclude_exts=set(),
        report_path=report_path,
        cross_root=True,
        workers=4,
    )

    assert report["stats"]["verified"] == 2
    assert report["stats"]["missing"] == 1
    assert report.get("workers") == 4
    assert report.get("cross_root") is True
