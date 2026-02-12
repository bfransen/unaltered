#!/usr/bin/env python3
"""
Desktop UI for running unaltered index and verify commands.
"""

from __future__ import annotations

import logging
import queue
import threading
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from common import parse_exclude_extensions, write_report
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
    """Log handler that forwards formatted messages to a queue."""

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

    def __init__(self, root_window: tk.Tk) -> None:
        self.root_window = root_window
        self.root_window.title("Unaltered - Integrity UI")
        self.root_window.geometry("980x760")

        self.event_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self.running = False
        self.run_buttons: list[ttk.Button] = []
        self.status_var = tk.StringVar(value="Ready.")

        self.index_vars: dict[str, tk.Variable]
        self.verify_vars: dict[str, tk.Variable]
        self.output: scrolledtext.ScrolledText

        self._build_ui()
        self.root_window.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root_window.after(100, self._poll_events)

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root_window, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=False)

        index_tab = ttk.Frame(notebook, padding=12)
        verify_tab = ttk.Frame(notebook, padding=12)
        notebook.add(index_tab, text="Index")
        notebook.add(verify_tab, text="Verify")

        self.index_vars = self._build_command_form(index_tab, mode="index")
        self.verify_vars = self._build_command_form(verify_tab, mode="verify")

        output_frame = ttk.LabelFrame(container, text="Run output", padding=8)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            height=20,
            state=tk.DISABLED,
        )
        self.output.pack(fill=tk.BOTH, expand=True)

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

    def _build_command_form(self, parent: ttk.Frame, mode: str) -> dict[str, tk.Variable]:
        cwd = Path.cwd()
        vars_map: dict[str, tk.Variable] = {
            "root": tk.StringVar(value=str(cwd)),
            "db": tk.StringVar(value=str(cwd / "integrity.db")),
            "report": tk.StringVar(
                value=str(cwd / ("report.json" if mode == "index" else "verify.json"))
            ),
            "exclude_ext": tk.StringVar(value=""),
            "ignore_deleted": tk.BooleanVar(value=False),
            "workers": tk.StringVar(value="1"),
            "log": tk.StringVar(value=""),
            "verbose": tk.BooleanVar(value=False),
        }

        if mode == "verify":
            vars_map["cross_root"] = tk.BooleanVar(value=False)

        row = 0
        self._add_labeled_entry(
            parent,
            row=row,
            label_text="Root directory",
            variable=vars_map["root"],  # type: ignore[arg-type]
            browse_command=lambda: self._browse_directory(vars_map["root"]),  # type: ignore[arg-type]
            browse_label="Browse...",
        )
        row += 1
        self._add_labeled_entry(
            parent,
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
            parent,
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
            parent,
            row=row,
            label_text="Exclude extensions",
            variable=vars_map["exclude_ext"],  # type: ignore[arg-type]
        )
        row += 1
        self._add_labeled_entry(
            parent,
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

        if mode == "verify":
            ttk.Checkbutton(
                parent,
                text="Cross-root verify (hash-only, root can differ from index root)",
                variable=vars_map["cross_root"],
            ).grid(row=row, column=1, sticky="w", pady=(4, 0))
            row += 1

        self._add_labeled_entry(
            parent,
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

        run_btn_text = "Run index" if mode == "index" else "Run verify"
        if mode == "index":
            run_btn_cmd = lambda values=vars_map: self._start_run("index", values)
        else:
            run_btn_cmd = lambda values=vars_map: self._start_run("verify", values)
        run_button = ttk.Button(parent, text=run_btn_text, command=run_btn_cmd)
        run_button.grid(row=row, column=1, sticky="w", pady=(10, 0))
        self.run_buttons.append(run_button)

        parent.columnconfigure(1, weight=1)
        return vars_map

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
            row=row, column=0, sticky="w", padx=(0, 8), pady=4
        )
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky="ew", pady=4)

        if browse_command:
            ttk.Button(parent, text=browse_label, command=browse_command).grid(
                row=row, column=2, padx=(8, 0), pady=4
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

    def _start_run(self, mode: str, values: dict[str, tk.Variable]) -> None:
        if self.running:
            messagebox.showwarning("Run in progress", "Please wait for the current run to finish.")
            return

        run_config = self._collect_common_config(values)
        if run_config is None:
            return

        cross_root = bool(values["cross_root"].get()) if "cross_root" in values else False

        self._clear_output()
        self._append_output(f"Starting {mode} run...\n")
        self.status_var.set(f"Running {mode}...")
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
            messagebox.showerror("Invalid input", f"Root directory does not exist:\n{root}")
            return None
        if not root.is_dir():
            messagebox.showerror("Invalid input", f"Root path is not a directory:\n{root}")
            return None

        try:
            workers = int(workers_value)
            if workers < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid input", "Workers must be an integer >= 1.")
            return None

        exclude_exts = parse_exclude_extensions([exclude_value]) if exclude_value else set()

        log_path = Path(log_value).expanduser() if log_value else None

        return RunConfig(
            root=root.resolve(),
            db_path=Path(db_value).expanduser(),
            report_path=Path(report_value).expanduser(),
            exclude_exts=exclude_exts,
            ignore_deleted=bool(values["ignore_deleted"].get()),
            workers=workers,
            verbose=bool(values["verbose"].get()),
            log_path=log_path,
        )

    def _run_worker(self, mode: str, config: RunConfig, cross_root: bool) -> None:
        self._configure_logging(config.verbose, config.log_path)
        try:
            if mode == "index":
                report = index_files(
                    root=config.root,
                    db_path=config.db_path,
                    exclude_exts=config.exclude_exts,
                    report_path=config.report_path,
                    ignore_deleted=config.ignore_deleted,
                    workers=config.workers,
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
                )

            write_report(report, config.report_path)
            self.event_queue.put(("done", (mode, report, config.report_path)))
        except Exception:
            self.event_queue.put(("error", traceback.format_exc()))

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
                elif event_type == "done":
                    mode, report, report_path = payload  # type: ignore[misc]
                    self._finish_run(mode, report, report_path)
                elif event_type == "error":
                    self._finish_error(str(payload))
        except queue.Empty:
            pass
        finally:
            self.root_window.after(100, self._poll_events)

    def _finish_run(self, mode: str, report: dict[str, object], report_path: Path) -> None:
        stats = report.get("stats", {})
        assert isinstance(stats, dict)

        self.running = False
        self._set_buttons_enabled(True)

        self._append_output("\nRun complete.\n")
        self._append_output(self._format_report_summary(mode, stats, report_path))
        if mode == "verify":
            has_issues = bool(
                stats.get("mismatched", 0) or stats.get("missing", 0) or stats.get("errors", 0)
            )
            self.status_var.set(
                "Verify completed with issues." if has_issues else "Verify completed successfully."
            )
        else:
            self.status_var.set("Index completed successfully.")

    def _finish_error(self, details: str) -> None:
        self.running = False
        self._set_buttons_enabled(True)
        self.status_var.set("Run failed.")
        self._append_output("\nRun failed with an exception:\n")
        self._append_output(details)
        messagebox.showerror("Run failed", "The command failed. See output for details.")

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
                    f"  mismatched: {stats.get('mismatched', 0)}",
                    f"  missing: {stats.get('missing', 0)}",
                    f"  untracked: {stats.get('untracked', 0)}",
                ]
            )
        lines.append("")
        return "\n".join(lines)

    def _append_output(self, text: str) -> None:
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def _clear_output(self) -> None:
        self.output.config(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.config(state=tk.DISABLED)

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
