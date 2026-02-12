# unaltered

Verifies that files have not been corrupted, changed unintentionally, or subject to bitrot. Created to warn administrators if important files get modified.

Unaltered scans a directory tree, computes SHA-256 hashes for files, and stores results in a local SQLite database. You can later re-run verification to compare current file hashes against the stored values.

## Requirements

- Python 3.x (uses only the standard library for the main script)
- For running tests: pytest

## Installation

Clone or download this repository, then optionally install the development dependencies:

```bash
pip install -r requirements.txt
```

This installs pytest for running the test suite. The main script (`unaltered.py`) has no external dependencies beyond the Python standard library.

## Usage

Unaltered has two commands: **index** (build or update the hash database) and **verify** (compare current file hashes to the stored database).

### Index

Scan a directory and store SHA-256 hashes. Only new or changed files (by size/mtime) are hashed; unchanged files are skipped for speed.

```bash
python unaltered.py index --root /path/to/directory
```

Examples:

```bash
# Basic index of a photo library (creates integrity.db and report.json)
python unaltered.py index --root /path/to/photos

# Use a custom database and report path
python unaltered.py index --root /path/to/photos --db /path/to/integrity.db --report my_report.json

# Exclude certain extensions (e.g. temp files, databases)
python unaltered.py index --root /path/to/photos --exclude-ext .tmp,.db,.log

# Ignore macOS resource forks (._* files < 4KB)
python unaltered.py index --root /path/to/photos --ignore-deleted

# Use multiple worker threads for faster hashing on large trees
python unaltered.py index --root /path/to/photos --workers 4

# Write log output to a file
python unaltered.py index --root /path/to/photos --log run.log --verbose
```

### Verify

Re-hash files under the given root and compare to the stored database. Exits with code 0 if all files match; exits 1 if there are mismatches, missing files, or errors.

```bash
python unaltered.py verify --root /path/to/directory
```

Examples:

```bash
# Basic verification (same root as index)
python unaltered.py verify --root /path/to/photos --db integrity.db

# Verify a backup tree (different root): index was built from source, root is the backup
# Uses hash-based matching so folder structure can differ
python unaltered.py verify --root /path/to/backup --db integrity.db --cross-root

# Parallel verification
python unaltered.py verify --root /path/to/photos --workers 4
```

### Options (both commands)

| Option | Description |
|--------|-------------|
| `--root` | Root directory to scan (required) |
| `--db` | Path to SQLite database (default: `integrity.db`) |
| `--exclude-ext` | Extensions to exclude, comma-separated or repeatable (e.g. `.tmp,.db`) |
| `--report` | JSON report path (default: `report.json` for index, `verify.json` for verify) |
| `--ignore-deleted` | Ignore `._*` files smaller than 4KB (macOS resource forks) |
| `--workers` | Number of parallel hashing threads (default: 1) |
| `--log` | Write log output to this file |
| `--verbose` | Enable debug logging |

### Verify-only options

| Option | Description |
|--------|-------------|
| `--cross-root` | Root is a different tree (e.g. backup). Verification is hash-only; "missing" = hashes in DB not found under root. |

## Desktop UI

If you prefer a graphical interface, run:

```bash
python unaltered_ui.py
```

The UI includes separate **Index** and **Verify** tabs with fields for:

- root directory
- database path
- report path
- exclude extensions
- worker count
- ignore-deleted flag
- optional log file
- verbose logging
- cross-root mode (verify only)

Runs execute in the background so the window stays responsive, and log output plus a summary is shown in the lower panel.

## Workflow

1. **Initial index**: Run `index` on the directory you want to protect. This creates `integrity.db` and `report.json`.
2. **Periodic verify**: Run `verify` regularly (e.g. via cron) to check for changes. If the exit code is non-zero, inspect the report for mismatched or missing files.
3. **Update index**: After legitimate changes, run `index` again to update the database.

## Running tests

```bash
pytest test_unaltered.py -v
```
