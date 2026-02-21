#!/usr/bin/env python3
"""
Desktop UI for running unaltered index and verify commands.

Features:
- Form-based index/verify controls
- Background execution with live logs
- Progress indicator with estimated remaining files
- Verify difference tree grouped by folder/subfolder
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# Optional: logo in UI (PIL/Pillow only needed for JPEG)
try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None

from common import (
    iter_files,
    parse_exclude_extensions,
    should_ignore_file,
    write_report,
)
from index_cmd import index_files
from verify_cmd import verify_files


@dataclass
class RunConfig:
    """Shared command options collected from the UI."""

    root: Path
    db_path: Path
    report_path: Path
    exclude_exts: set[str]
    ignore_deleted: bool
    workers: int
    verbose: bool
    log_path: Optional[Path]


class QueueLogHandler(logging.Handler):
    """Log handler that forwards formatted messages to the UI event queue."""

    def __init__(self, event_queue: queue.Queue[tuple[str, object]]) -> None:
        super().__init__()
        self._event_queue = event_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
        except Exception:
            message = record.getMessage()
        self._event_queue.put(("log", message))


class UnalteredUI:
    """Tkinter-based UI for indexing and verification runs."""

    STATUS_ORDER = ("changed", "deleted", "added", "moved_from", "moved_to", "duplicate")
    STATUS_LABELS = {
        "changed": "CHANGED",
        "deleted": "DELETED",
        "added": "ADDED",
        "moved_from": "MOVED_FROM",
        "moved_to": "MOVED_TO",
        "duplicate": "DUPLICATE",
    }
    STATUS_SUMMARY_LABELS = {
        "changed": "chg",
        "deleted": "del",
        "added": "add",
        "moved_from": "mv-from",
        "moved_to": "mv-to",
        "duplicate": "dup",
    }

    def __init__(self, root_window: tk.Tk) -> None:
        self.root_window = root_window
        self.root_window.title("Unaltered - Integrity UI")
        self.root_window.geometry("1100x820")

        self.event_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self.running = False
        self.run_buttons: list[ttk.Button] = []

        self.status_var = tk.StringVar(value="Ready.")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_text_var = tk.StringVar(value="Idle.")
        self.progress_total = 0
        self.progress_processed = 0

        self.common_vars: dict[str, tk.Variable]
        self.verify_vars: dict[str, tk.Variable]  # verify-only (e.g. cross_root)
        self.output: scrolledtext.ScrolledText
        self.diff_tree: ttk.Treeview
        self.progress_bar: ttk.Progressbar
        self._logo_photo = None  # keep reference so image is not garbage-collected

        self._build_ui()
        self.root_window.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root_window.after(100, self._poll_events)

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root_window, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        # Small logo at top-left (optional; requires Pillow if logo is JPEG)
        logo_path = Path(__file__).resolve().parent / "unaltered_logo.jpg"
        if Image is not None and ImageTk is not None and logo_path.is_file():
            try:
                img = Image.open(logo_path)
                h = 36
                w = max(1, int(img.width * (h / img.height)))
                img = img.resize((w, h), getattr(Image, "Resampling", Image).LANCZOS)
                self._logo_photo = ImageTk.PhotoImage(img)
                logo_label = ttk.Label(container, image=self._logo_photo)
                logo_label.pack(anchor="w", pady=(0, 8))
            except Exception:
                pass

        common_frame = ttk.LabelFrame(container, text="Common settings", padding=12)
        common_frame.pack(fill=tk.X)

        self.common_vars = self._build_common_form(common_frame)

        notebook = ttk.Notebook(container, padding=(0, 8))
        notebook.pack(fill=tk.BOTH, expand=False)

        index_tab = ttk.Frame(notebook, padding=12)
        verify_tab = ttk.Frame(notebook, padding=12)
        notebook.add(index_tab, text="Index")
        notebook.add(verify_tab, text="Verify")

        self._build_index_tab(index_tab)
        self._build_verify_tab(verify_tab)

        self._load_defaults()

        progress_frame = ttk.LabelFrame(container, text="Progress", padding=8)
        progress_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(progress_frame, textvariable=self.progress_text_var).pack(
            fill=tk.X,
            expand=True,
        )
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            orient=tk.HORIZONTAL,
            mode="determinate",
            variable=self.progress_var,
            maximum=100,
        )
        self.progress_bar.pack(fill=tk.X, expand=True, pady=(6, 0))

        results_pane = ttk.Panedwindow(container, orient=tk.VERTICAL)
        results_pane.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        output_frame = ttk.LabelFrame(results_pane, text="Run output", padding=8)
        diff_frame = ttk.LabelFrame(
            results_pane,
            text="Verify differences by folder",
            padding=8,
        )
        results_pane.add(output_frame, weight=3)
        results_pane.add(diff_frame, weight=2)

        self.output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            height=18,
            state=tk.DISABLED,
        )
        self.output.pack(fill=tk.BOTH, expand=True)

        diff_container = ttk.Frame(diff_frame)
        diff_container.pack(fill=tk.BOTH, expand=True)

        self.diff_tree = ttk.Treeview(diff_container, show="tree")
        diff_scrollbar = ttk.Scrollbar(
            diff_container,
            orient=tk.VERTICAL,
            command=self.diff_tree.yview,
        )
        self.diff_tree.configure(yscrollcommand=diff_scrollbar.set)
        self.diff_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        diff_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._set_diff_placeholder("Run verify to populate folder-level differences.")

        status_frame = ttk.Frame(container)
        status_frame.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(status_frame, textvariable=self.status_var).pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
        )
        ttk.Button(
            status_frame,
            text="Clear output",
            command=self._clear_output,
        ).pack(side=tk.RIGHT)

    def _build_common_form(self, parent: ttk.Frame) -> dict[str, tk.Variable]:
        """Build shared fields (root, db, report, etc.) used by both index and verify."""
        cwd = Path.cwd()
        vars_map: dict[str, tk.Variable] = {
            "root": tk.StringVar(value=str(cwd)),
            "db": tk.StringVar(value=str(cwd / "integrity.db")),
            "report": tk.StringVar(value=str(cwd / "report.json")),
            "exclude_ext": tk.StringVar(value=""),
            "ignore_deleted": tk.BooleanVar(value=False),
            "workers": tk.StringVar(value="1"),
            "log": tk.StringVar(value=""),
            "verbose": tk.BooleanVar(value=False),
        }

        row = 0
        self._add_labeled_entry(
            parent=parent,
            row=row,
            label_text="Root directory",
            variable=vars_map["root"],  # type: ignore[arg-type]
            browse_command=lambda: self._browse_directory(vars_map["root"]),  # type: ignore[arg-type]
            browse_label="Browse...",
        )
        row += 1

        self._add_labeled_entry(
            parent=parent,
            row=row,
            label_text="SQLite DB",
            variable=vars_map["db"],  # type: ignore[arg-type]
            browse_command=lambda: self._browse_file_save(
                vars_map["db"],  # type: ignore[arg-type]
                title="Choose database path",
                default_ext=".db",
                file_types=[("SQLite DB", "*.db"), ("All files", "*.*")],
            ),
            browse_label="Browse...",
        )
        row += 1

        self._add_labeled_entry(
            parent=parent,
            row=row,
            label_text="Report JSON",
            variable=vars_map["report"],  # type: ignore[arg-type]
            browse_command=lambda: self._browse_file_save(
                vars_map["report"],  # type: ignore[arg-type]
                title="Choose report path",
                default_ext=".json",
                file_types=[("JSON files", "*.json"), ("All files", "*.*")],
            ),
            browse_label="Browse...",
        )
        row += 1

        self._add_labeled_entry(
            parent=parent,
            row=row,
            label_text="Exclude extensions",
            variable=vars_map["exclude_ext"],  # type: ignore[arg-type]
        )
        row += 1

        self._add_labeled_entry(
            parent=parent,
            row=row,
            label_text="Workers",
            variable=vars_map["workers"],  # type: ignore[arg-type]
        )
        row += 1

        ttk.Checkbutton(
            parent,
            text="Ignore ._* files smaller than 4KB",
            variable=vars_map["ignore_deleted"],
        ).grid(row=row, column=1, sticky="w", pady=(4, 0))
        row += 1

        self._add_labeled_entry(
            parent=parent,
            row=row,
            label_text="Log file (optional)",
            variable=vars_map["log"],  # type: ignore[arg-type]
            browse_command=lambda: self._browse_file_save(
                vars_map["log"],  # type: ignore[arg-type]
                title="Choose log path",
                default_ext=".log",
                file_types=[("Log files", "*.log"), ("All files", "*.*")],
            ),
            browse_label="Browse...",
        )
        row += 1

        ttk.Checkbutton(
            parent,
            text="Verbose logging",
            variable=vars_map["verbose"],
        ).grid(row=row, column=1, sticky="w", pady=(4, 0))
        row += 1

        ttk.Button(
            parent,
            text="Save as defaults",
            command=self._save_defaults,
        ).grid(row=row, column=1, sticky="w", pady=(10, 0))

        parent.columnconfigure(1, weight=1)
        return vars_map

    @staticmethod
    def _get_defaults_path() -> Path:
        """Path to the config file where default form values are stored."""
        return Path.home() / ".config" / "unaltered" / "defaults.json"

    @staticmethod
    def _path_with_date_suffix(path: Path, timestamp: str) -> Path:
        """Insert -YYYY_MMDD_HHMM before the file extension (e.g. output.log -> output-2026_0220_1123.log)."""
        return path.parent / f"{path.stem}-{timestamp}{path.suffix}"

    def _load_defaults(self) -> None:
        """Load saved defaults from config file into the form, if it exists."""
        path = self._get_defaults_path()
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        bool_keys = {"ignore_deleted", "verbose", "cross_root"}
        for key, value in data.items():
            if key in self.common_vars:
                v = self.common_vars[key]
                if key in bool_keys:
                    if isinstance(value, bool):
                        v.set(value)
                else:
                    if isinstance(value, str):
                        v.set(value)
            elif key in self.verify_vars:
                v = self.verify_vars[key]
                if key in bool_keys and isinstance(value, bool):
                    v.set(value)

    def _save_defaults(self) -> None:
        """Save current form values to the config file as defaults."""
        data: dict[str, str | bool] = {}
        for key, v in self.common_vars.items():
            val = v.get()
            data[key] = val if isinstance(val, (str, bool)) else str(val)
        for key, v in self.verify_vars.items():
            val = v.get()
            data[key] = val if isinstance(val, (str, bool)) else str(val)
        path = self._get_defaults_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.status_var.set("Defaults saved.")
        except OSError as e:
            messagebox.showerror(
                "Save failed",
                f"Could not write defaults to {path}:\n{e}",
            )

    def _build_index_tab(self, parent: ttk.Frame) -> None:
        """Index tab: only the Run button (common settings are above)."""
        run_button = ttk.Button(
            parent,
            text="Run index",
            command=lambda: self._start_run("index"),
        )
        run_button.pack(anchor="w")
        self.run_buttons.append(run_button)

    def _build_verify_tab(self, parent: ttk.Frame) -> None:
        """Verify tab: cross-root option and Run button (common settings are above)."""
        self.verify_vars = {"cross_root": tk.BooleanVar(value=False)}
        ttk.Checkbutton(
            parent,
            text="Cross-root verify (hash-only, root can differ from index root)",
            variable=self.verify_vars["cross_root"],
        ).pack(anchor="w", pady=(0, 8))
        run_button = ttk.Button(
            parent,
            text="Run verify",
            command=lambda: self._start_run("verify"),
        )
        run_button.pack(anchor="w")
        self.run_buttons.append(run_button)

    @staticmethod
    def _add_labeled_entry(
        parent: ttk.Frame,
        row: int,
        label_text: str,
        variable: tk.StringVar,
        browse_command: Optional[object] = None,
        browse_label: str = "",
    ) -> None:
        ttk.Label(parent, text=label_text).grid(
            row=row,
            column=0,
            sticky="w",
            padx=(0, 8),
            pady=4,
        )
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky="ew", pady=4)

        if browse_command:
            ttk.Button(parent, text=browse_label, command=browse_command).grid(
                row=row,
                column=2,
                padx=(8, 0),
                pady=4,
            )

    @staticmethod
    def _browse_directory(target: tk.StringVar) -> None:
        selected = filedialog.askdirectory(title="Select root directory")
        if selected:
            target.set(selected)

    @staticmethod
    def _browse_file_save(
        target: tk.StringVar,
        title: str,
        default_ext: str,
        file_types: list[tuple[str, str]],
    ) -> None:
        selected = filedialog.asksaveasfilename(
            title=title,
            defaultextension=default_ext,
            filetypes=file_types,
            initialfile=Path(target.get()).name if target.get() else "",
        )
        if selected:
            target.set(selected)

    def _start_run(self, mode: str) -> None:
        if self.running:
            messagebox.showwarning(
                "Run in progress",
                "Please wait for the current run to finish.",
            )
            return

        run_config = self._collect_common_config(self.common_vars)
        if run_config is None:
            return

        cross_root = (
            bool(self.verify_vars["cross_root"].get()) if mode == "verify" else False
        )

        self._clear_output()
        self._append_output(f"Starting {mode} run...\n")
        self.status_var.set(f"Running {mode}...")
        self._set_progress_indeterminate("Estimating files to process...")
        if mode == "verify":
            self._set_diff_placeholder("Verify run in progress...")
        else:
            self._set_diff_placeholder("Run verify to populate folder-level differences.")

        self.running = True
        self._set_buttons_enabled(False)

        self.worker_thread = threading.Thread(
            target=self._run_worker,
            args=(mode, run_config, cross_root),
            daemon=True,
        )
        self.worker_thread.start()

    def _collect_common_config(self, values: dict[str, tk.Variable]) -> Optional[RunConfig]:
        root_value = str(values["root"].get()).strip()
        db_value = str(values["db"].get()).strip()
        report_value = str(values["report"].get()).strip()
        workers_value = str(values["workers"].get()).strip()
        log_value = str(values["log"].get()).strip()
        exclude_value = str(values["exclude_ext"].get()).strip()

        if not root_value:
            messagebox.showerror("Invalid input", "Root directory is required.")
            return None
        if not db_value:
            messagebox.showerror("Invalid input", "Database path is required.")
            return None
        if not report_value:
            messagebox.showerror("Invalid input", "Report path is required.")
            return None

        root = Path(root_value).expanduser()
        if not root.exists():
            messagebox.showerror(
                "Invalid input",
                f"Root directory does not exist:\n{root}",
            )
            return None
        if not root.is_dir():
            messagebox.showerror(
                "Invalid input",
                f"Root path is not a directory:\n{root}",
            )
            return None

        try:
            workers = int(workers_value)
            if workers < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid input", "Workers must be an integer >= 1.")
            return None

        exclude_exts = parse_exclude_extensions([exclude_value]) if exclude_value else set()
        report_path = Path(report_value).expanduser()
        log_path = Path(log_value).expanduser() if log_value else None

        timestamp = datetime.now().strftime("%Y_%m%d_%H%M")
        report_path = self._path_with_date_suffix(report_path, timestamp)
        if log_path is not None:
            log_path = self._path_with_date_suffix(log_path, timestamp)

        return RunConfig(
            root=root.resolve(),
            db_path=Path(db_value).expanduser(),
            report_path=report_path,
            exclude_exts=exclude_exts,
            ignore_deleted=bool(values["ignore_deleted"].get()),
            workers=workers,
            verbose=bool(values["verbose"].get()),
            log_path=log_path,
        )

    def _run_worker(self, mode: str, config: RunConfig, cross_root: bool) -> None:
        try:
            estimated_total = self._estimate_total_files(config)
            self.event_queue.put(("progress_init", estimated_total))

            self._configure_logging(config.verbose, config.log_path)
            last_emit = [0.0]

            def on_progress(processed: int, stats: dict[str, int]) -> None:
                now = time.monotonic()
                if now - last_emit[0] >= 0.15 or (estimated_total and processed >= estimated_total):
                    self.event_queue.put(("progress", (processed, estimated_total, stats)))
                    last_emit[0] = now

            if mode == "index":
                report = index_files(
                    root=config.root,
                    db_path=config.db_path,
                    exclude_exts=config.exclude_exts,
                    report_path=config.report_path,
                    ignore_deleted=config.ignore_deleted,
                    workers=config.workers,
                    progress_callback=on_progress,
                )
            else:
                report = verify_files(
                    root=config.root,
                    db_path=config.db_path,
                    exclude_exts=config.exclude_exts,
                    report_path=config.report_path,
                    cross_root=cross_root,
                    ignore_deleted=config.ignore_deleted,
                    workers=config.workers,
                    progress_callback=on_progress,
                )

            write_report(report, config.report_path)
            self.event_queue.put(("done", (mode, report, config.report_path)))
        except Exception:
            self.event_queue.put(("error", traceback.format_exc()))

    def _estimate_total_files(self, config: RunConfig) -> int:
        excluded_paths = {
            str(config.db_path.resolve()),
            str(config.report_path.resolve()),
        }
        total = 0
        for file_path in iter_files(config.root):
            path_str = str(file_path)
            if path_str in excluded_paths:
                continue
            if file_path.suffix.lower() in config.exclude_exts:
                continue
            try:
                file_stat = file_path.stat()
            except OSError:
                # The run will still "process" this entry and count an error.
                total += 1
                continue
            if config.ignore_deleted and should_ignore_file(file_path, file_stat.st_size):
                continue
            total += 1
        return total

    def _configure_logging(self, verbose: bool, log_path: Optional[Path]) -> None:
        root_logger = logging.getLogger()
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        queue_handler = QueueLogHandler(self.event_queue)
        queue_handler.setFormatter(formatter)
        root_logger.addHandler(queue_handler)

        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

        root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    def _poll_events(self) -> None:
        try:
            while True:
                event_type, payload = self.event_queue.get_nowait()
                if event_type == "log":
                    self._append_output(f"{payload}\n")
                elif event_type == "progress_init":
                    self._set_progress_determinate(int(payload))
                elif event_type == "progress":
                    processed, total, stats = payload  # type: ignore[misc]
                    self._update_progress(int(processed), int(total), stats)
                elif event_type == "done":
                    mode, report, report_path = payload  # type: ignore[misc]
                    self._finish_run(mode, report, report_path)
                elif event_type == "error":
                    self._finish_error(str(payload))
        except queue.Empty:
            pass
        finally:
            self.root_window.after(100, self._poll_events)

    def _set_progress_indeterminate(self, message: str) -> None:
        self.progress_total = 0
        self.progress_processed = 0
        self.progress_bar.stop()
        self.progress_bar.configure(mode="indeterminate", maximum=100)
        self.progress_var.set(0)
        self.progress_text_var.set(message)
        self.progress_bar.start(12)

    def _set_progress_determinate(self, total: int) -> None:
        self.progress_bar.stop()
        self.progress_total = max(total, 0)
        self.progress_processed = 0
        self.progress_bar.configure(mode="determinate", maximum=max(total, 1))
        self.progress_var.set(0)
        if total <= 0:
            self.progress_text_var.set("No eligible files found for this run.")
        else:
            self.progress_text_var.set(f"Processed 0/{total} files (0.0%) - about {total} left")

    def _update_progress(self, processed: int, total: int, stats: dict[str, int]) -> None:
        if str(self.progress_bar.cget("mode")) != "determinate":
            self._set_progress_determinate(total)

        self.progress_processed = max(processed, 0)
        if total > 0:
            clamped = min(self.progress_processed, total)
            self.progress_var.set(clamped)
            remaining = max(total - clamped, 0)
            percent = (clamped / total) * 100
            self.progress_text_var.set(
                f"Processed {clamped}/{total} files ({percent:.1f}%) - about {remaining} left"
            )
        else:
            scanned = int(stats.get("scanned", self.progress_processed))
            self.progress_text_var.set(f"Processed {scanned} files.")

    def _complete_progress(self) -> None:
        self.progress_bar.stop()
        if self.progress_total > 0:
            self.progress_var.set(self.progress_total)
            self.progress_text_var.set(
                f"Processed {self.progress_total}/{self.progress_total} files (100.0%)."
            )
        elif self.progress_processed > 0:
            self.progress_text_var.set(f"Processed {self.progress_processed} files.")
        else:
            self.progress_text_var.set("Run complete.")

    def _finish_run(self, mode: str, report: dict[str, object], report_path: Path) -> None:
        stats = report.get("stats", {})
        assert isinstance(stats, dict)

        self.running = False
        self._set_buttons_enabled(True)
        self._complete_progress()

        self._append_output("\nRun complete.\n")
        self._append_output(self._format_report_summary(mode, stats, report_path))

        if mode == "verify":
            has_issues = bool(
                stats.get("mismatched", 0)
                or stats.get("missing", 0)
                or stats.get("untracked", 0)
                or stats.get("moved", 0)
                or stats.get("duplicates", 0)
                or stats.get("errors", 0)
            )
            self.status_var.set(
                "Verify completed with differences." if has_issues else "Verify completed successfully."
            )
            self._render_verify_tree(report)
        else:
            self.status_var.set("Index completed successfully.")
            self._set_diff_placeholder("Run verify to populate folder-level differences.")

    def _finish_error(self, details: str) -> None:
        self.running = False
        self._set_buttons_enabled(True)
        self.progress_bar.stop()
        self.progress_text_var.set("Run failed.")
        self.status_var.set("Run failed.")
        self._append_output("\nRun failed with an exception:\n")
        self._append_output(details)
        messagebox.showerror("Run failed", "The command failed. See output for details.")

    def _render_verify_tree(self, report: dict[str, object]) -> None:
        self._clear_diff_tree()
        root_str = str(report.get("root", "")).strip()
        if not root_str:
            self._set_diff_placeholder("Verify report is missing root path.")
            return

        root_path = Path(root_str)
        issue_records = self._collect_issue_records(report)
        if not issue_records:
            self._set_diff_placeholder("No differences detected.")
            return

        def make_counts() -> dict[str, int]:
            return {status: 0 for status in self.STATUS_ORDER}

        dir_counts: dict[tuple[str, ...], dict[str, int]] = {(): make_counts()}
        files_by_dir: dict[tuple[str, ...], list[tuple[str, str, str]]] = defaultdict(list)
        outside_root: list[tuple[str, str, str]] = []

        for status, path_str, detail in issue_records:
            file_path = Path(path_str)
            if self._is_under_root(file_path, root_path):
                rel_path = file_path.relative_to(root_path)
                dir_key = rel_path.parts[:-1]
                file_name = rel_path.name if rel_path.name else str(file_path)

                for depth in range(0, len(dir_key) + 1):
                    ancestor = dir_key[:depth]
                    if ancestor not in dir_counts:
                        dir_counts[ancestor] = make_counts()
                    dir_counts[ancestor][status] += 1

                files_by_dir[dir_key].append((file_name, status, detail))
            else:
                outside_root.append((path_str, status, detail))

        children_map: dict[tuple[str, ...], list[tuple[str, ...]]] = defaultdict(list)
        for dir_key in dir_counts:
            if dir_key:
                children_map[dir_key[:-1]].append(dir_key)

        root_node_text = f"{root_path} {self._format_count_summary(dir_counts[()])}"
        root_node = self.diff_tree.insert("", tk.END, text=root_node_text, open=True)

        self._insert_tree_branch(
            parent_id=root_node,
            branch_key=(),
            children_map=children_map,
            dir_counts=dir_counts,
            files_by_dir=files_by_dir,
        )

        if outside_root:
            outside_node = self.diff_tree.insert("", tk.END, text="Outside selected root", open=False)
            for path_str, status, detail in sorted(outside_root, key=lambda row: row[0].lower()):
                label = self.STATUS_LABELS[status]
                suffix = f" {detail}" if detail else ""
                self.diff_tree.insert(
                    outside_node,
                    tk.END,
                    text=f"[{label}] {path_str}{suffix}",
                )

    def _insert_tree_branch(
        self,
        parent_id: str,
        branch_key: tuple[str, ...],
        children_map: dict[tuple[str, ...], list[tuple[str, ...]]],
        dir_counts: dict[tuple[str, ...], dict[str, int]],
        files_by_dir: dict[tuple[str, ...], list[tuple[str, str, str]]],
    ) -> None:
        for file_name, status, detail in sorted(
            files_by_dir.get(branch_key, []),
            key=lambda row: (row[0].lower(), row[1]),
        ):
            label = self.STATUS_LABELS[status]
            suffix = f" {detail}" if detail else ""
            self.diff_tree.insert(parent_id, tk.END, text=f"[{label}] {file_name}{suffix}")

        child_keys = sorted(
            children_map.get(branch_key, []),
            key=lambda parts: tuple(part.lower() for part in parts),
        )
        for child_key in child_keys:
            folder_name = child_key[-1]
            counts = dir_counts[child_key]
            node_text = f"{folder_name} {self._format_count_summary(counts)}"
            child_id = self.diff_tree.insert(parent_id, tk.END, text=node_text, open=False)
            self._insert_tree_branch(
                parent_id=child_id,
                branch_key=child_key,
                children_map=children_map,
                dir_counts=dir_counts,
                files_by_dir=files_by_dir,
            )

    def _format_count_summary(self, counts: dict[str, int]) -> str:
        parts: list[str] = []
        for status in self.STATUS_ORDER:
            count = counts.get(status, 0)
            if count:
                parts.append(f"{self.STATUS_SUMMARY_LABELS[status]}:{count}")
        if not parts:
            return "(no differences)"
        return "(" + ", ".join(parts) + ")"

    def _collect_issue_records(self, report: dict[str, object]) -> list[tuple[str, str, str]]:
        records: list[tuple[str, str, str]] = []

        def add_record(status: str, path: str, detail: str = "") -> None:
            clean_path = path.strip()
            if clean_path:
                records.append((status, clean_path, detail))

        mismatched = report.get("mismatched", [])
        if isinstance(mismatched, list):
            for item in mismatched:
                if isinstance(item, dict):
                    add_record("changed", str(item.get("path", "")), "hash mismatch")

        missing = report.get("missing", [])
        if isinstance(missing, list):
            for item in missing:
                if isinstance(item, dict):
                    add_record("deleted", str(item.get("path", "")), "")

        untracked = report.get("untracked", [])
        if isinstance(untracked, list):
            for item in untracked:
                if isinstance(item, dict):
                    add_record("added", str(item.get("path", "")), "")

        moved = report.get("moved", [])
        if isinstance(moved, list):
            for item in moved:
                if not isinstance(item, dict):
                    continue
                stored_path = str(item.get("stored_path", "")).strip()
                current_path = str(item.get("current_path", "")).strip()
                if stored_path:
                    detail = f"-> {current_path}" if current_path else ""
                    add_record("moved_from", stored_path, detail)
                if current_path:
                    detail = f"<- {stored_path}" if stored_path else ""
                    add_record("moved_to", current_path, detail)

        duplicates = report.get("duplicates", [])
        if isinstance(duplicates, list):
            for item in duplicates:
                if not isinstance(item, dict):
                    continue
                paths = item.get("paths") or []
                hash_preview = (item.get("hash") or "")[:12]
                n = len(paths)
                detail = f"hash {hash_preview}… ({n} copies)"
                for path in paths:
                    add_record("duplicate", str(path).strip(), detail)

        deduped: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for record in records:
            if record not in seen:
                deduped.append(record)
                seen.add(record)
        return deduped

    @staticmethod
    def _is_under_root(file_path: Path, root: Path) -> bool:
        try:
            file_path.relative_to(root)
        except ValueError:
            return False
        return True

    @staticmethod
    def _format_report_summary(mode: str, stats: dict[str, object], report_path: Path) -> str:
        lines = [
            f"Report written to: {report_path}",
            "",
            "Summary:",
            f"  scanned: {stats.get('scanned', 0)}",
            f"  excluded: {stats.get('excluded', 0)}",
            f"  errors: {stats.get('errors', 0)}",
        ]
        if mode == "index":
            lines.extend(
                [
                    f"  hashed_new: {stats.get('hashed_new', 0)}",
                    f"  hashed_updated: {stats.get('hashed_updated', 0)}",
                    f"  unchanged: {stats.get('unchanged', 0)}",
                ]
            )
        else:
            lines.extend(
                [
                    f"  verified: {stats.get('verified', 0)}",
                    f"  moved: {stats.get('moved', 0)}",
                    f"  mismatched: {stats.get('mismatched', 0)}",
                    f"  missing: {stats.get('missing', 0)}",
                    f"  untracked: {stats.get('untracked', 0)}",
                    f"  duplicates: {stats.get('duplicates', 0)}",
                ]
            )
        lines.append("")
        return "\n".join(lines)

    def _set_diff_placeholder(self, text: str) -> None:
        self._clear_diff_tree()
        self.diff_tree.insert("", tk.END, text=text, open=True)

    def _append_output(self, text: str) -> None:
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def _clear_output(self) -> None:
        self.output.config(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.config(state=tk.DISABLED)

    def _clear_diff_tree(self) -> None:
        for item in self.diff_tree.get_children():
            self.diff_tree.delete(item)

    def _set_buttons_enabled(self, enabled: bool) -> None:
        state = tk.NORMAL if enabled else tk.DISABLED
        for button in self.run_buttons:
            button.config(state=state)

    def _on_close(self) -> None:
        if self.running:
            should_close = messagebox.askyesno(
                "Run in progress",
                "A run is still active. Close anyway?",
            )
            if not should_close:
                return
        self.root_window.destroy()


def main() -> None:
    """Start the desktop UI."""
    try:
        root_window = tk.Tk()
    except tk.TclError as exc:
        raise SystemExit(f"Unable to start UI: {exc}")

    UnalteredUI(root_window)
    root_window.mainloop()


if __name__ == "__main__":
    main()
