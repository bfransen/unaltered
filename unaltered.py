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
import logging
import sys
from pathlib import Path

from common import (
    DEFAULT_DB_NAME,
    DEFAULT_WORKERS,
    setup_logging,
    parse_exclude_extensions,
    write_report,
)
from index_cmd import index_files
from verify_cmd import verify_files


# Re-export for tests and external use
__all__ = [
    "compute_hash",
    "index_files",
    "parse_exclude_extensions",
    "verify_files",
]
from common import compute_hash  # noqa: E402


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
