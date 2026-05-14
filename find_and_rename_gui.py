#!/usr/bin/env python3
"""Tkinter GUI for find_and_rename."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

LOG_PATH = Path(__file__).resolve().parent / "find_and_rename.log"


def log_to_file(line: str) -> None:
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {line}\n")
    except OSError:
        pass

from find_and_rename_core import (  # noqa: E402
    SearchOpts,
    ScanResult,
    walk,
    summarize,
    find_name_matches,
    find_content_matches,
    plan_renames,
    do_renames,
    rewrite_files,
)


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("find_and_rename")
        self.root.geometry("1100x680")
        self.root.minsize(820, 480)

        self.scan: ScanResult = ScanResult()
        self.name_matches: list = []
        self.content_hits: list = []
        self.content_errs: list = []
        self.op_errors: list[tuple[str, str, str]] = []  # (op_label, path, message)
        self.last_phrase: str = ""
        self.last_opts: SearchOpts = SearchOpts()
        self._msgq: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._busy = False
        self.scanned_dirs: set[str] = set()
        self.scanning_dirs: set[str] = set()

        self.PALETTE = {
            # pastels: status surfaces (listbox rows, hint label)
            "scanned":  {"bg": "#e7f3df", "fg": "#2a6d2a"},
            "scanning": {"bg": "#fdf0d9", "fg": "#a35c00"},
            "pending":  {"bg": "#fbe5e5", "fg": "#9b2a2a"},
            # saturated: call-to-action buttons (GitHub Primer palette)
            "btn_primary":  {"bg": "#2da44e", "fg": "#ffffff", "active": "#2c974b"},
            "btn_warning":  {"bg": "#bf8700", "fg": "#ffffff", "active": "#a37500"},
            "btn_danger":   {"bg": "#cf222e", "fg": "#ffffff", "active": "#a40e26"},
            "btn_disabled": {"bg": "#f6f8fa", "fg": "#8c959f", "active": "#f6f8fa"},
        }
        self.HINT_ICON = "ⓘ"

        self._build()
        self._refresh_dir_status()
        self._refresh_action_buttons()
        self.root.after(80, self._drain_queue)

    def _build(self) -> None:
        root = self.root
        root.columnconfigure(0, weight=1)
        root.rowconfigure(3, weight=1)

        dir_frame = ttk.LabelFrame(root, text="Directories to scan")
        dir_frame.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 2))
        dir_frame.columnconfigure(0, weight=1)
        self.dir_list = tk.Listbox(dir_frame, height=3, selectmode=tk.EXTENDED, exportselection=False,
                                   activestyle="none")
        self.dir_list.grid(row=0, column=0, rowspan=3, sticky="ew", padx=(6, 4), pady=4)
        btn_w = 18
        ttk.Button(dir_frame, text="Add folder...", width=btn_w, command=self.on_add_dir).grid(row=0, column=1, sticky="e", padx=4, pady=(4, 1))
        ttk.Button(dir_frame, text="Remove selected", width=btn_w, command=self.on_remove_dir).grid(row=1, column=1, sticky="e", padx=4, pady=1)
        self.scan_btn = tk.Button(dir_frame, text="Scan", width=btn_w, command=self.on_scan,
                                  relief="raised", bd=1)
        self.scan_btn.grid(row=2, column=1, sticky="e", padx=4, pady=(1, 4))
        self.dir_hint = tk.Label(dir_frame, text="", anchor="w", padx=6, pady=3,
                                 bg=self.PALETTE["pending"]["bg"], fg=self.PALETTE["pending"]["fg"])
        self.dir_hint.grid(row=3, column=0, columnspan=2, sticky="ew", padx=6, pady=(0, 4))

        search_frame = ttk.Frame(root)
        search_frame.grid(row=1, column=0, sticky="ew", padx=6, pady=2)
        search_frame.columnconfigure(1, weight=1)
        ttk.Label(search_frame, text="Find:").grid(row=0, column=0, padx=(2, 4), sticky="e")
        self.phrase_var = tk.StringVar()
        self.phrase_entry = ttk.Entry(search_frame, textvariable=self.phrase_var)
        self.phrase_entry.grid(row=0, column=1, sticky="ew", pady=2)
        self.phrase_entry.bind("<Return>", lambda _e: self.on_find())
        self.case_var = tk.BooleanVar(value=False)
        self.word_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(search_frame, text="Match case", variable=self.case_var).grid(row=0, column=2, padx=6)
        ttk.Checkbutton(search_frame, text="Whole word", variable=self.word_var).grid(row=0, column=3, padx=(0, 6))
        self.find_btn = tk.Button(search_frame, text="Find matches", command=self.on_find,
                                  relief="raised", bd=1, padx=10, pady=3)
        self.find_btn.grid(row=0, column=4, padx=(0, 2))

        rep_frame = ttk.Frame(root)
        rep_frame.grid(row=2, column=0, sticky="ew", padx=6, pady=(2, 4))
        rep_frame.columnconfigure(1, weight=1)
        ttk.Label(rep_frame, text="Replace with:").grid(row=0, column=0, padx=(2, 4), sticky="e")
        self.replacement_var = tk.StringVar()
        self.replacement_var.trace_add("write", lambda *_: self._refresh_action_buttons())
        ttk.Entry(rep_frame, textvariable=self.replacement_var).grid(row=0, column=1, sticky="ew", pady=2)
        self.rewrite_btn = tk.Button(rep_frame, text="Rewrite file contents", command=self.on_rewrite,
                                     relief="raised", bd=1, padx=10, pady=3)
        self.rewrite_btn.grid(row=0, column=2, padx=4)
        self.rename_btn = tk.Button(rep_frame, text="Rename files / folders", command=self.on_rename,
                                    relief="raised", bd=1, padx=10, pady=3)
        self.rename_btn.grid(row=0, column=3, padx=(0, 2))

        nb = ttk.Notebook(root)
        nb.grid(row=3, column=0, sticky="nsew", padx=6, pady=2)

        self.name_frame, self.name_tree = self._make_tree(
            nb, ("kind", "ext", "mtime", "path"), ("Type", "Ext", "Modified", "Path"),
            widths=(70, 80, 150, 700),
        )
        nb.add(self.name_frame, text="Name matches (0)")
        self._bind_context_menu(self.name_tree)

        self.content_frame, self.content_tree = self._make_tree(
            nb, ("count", "ext", "enc", "path"), ("Hits", "Ext", "Enc", "Path"),
            widths=(60, 80, 90, 760),
        )
        nb.add(self.content_frame, text="Content matches (0)")
        self._bind_context_menu(self.content_tree)

        self.error_frame, self.error_tree = self._make_tree(
            nb, ("path", "msg"), ("Path", "Message"),
            widths=(420, 480),
        )
        nb.add(self.error_frame, text="Errors (0)")
        self._bind_context_menu(self.error_tree)

        log_outer = ttk.Frame(nb)
        log_outer.columnconfigure(0, weight=1)
        log_outer.rowconfigure(0, weight=1)
        self.log = tk.Text(log_outer, wrap="none", height=10)
        self.log.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(log_outer, orient="vertical", command=self.log.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=sb.set)
        nb.add(log_outer, text="Log")
        self.nb = nb

        self.tip_label = tk.Label(
            root,
            text="Right-click a result for Open file  •  Open containing folder  •  Copy path.   Double-click to open.",
            fg="#6e7681",
            anchor="w",
            padx=6,
            font=("Segoe UI", 8),
        )
        self.tip_label.grid(row=4, column=0, sticky="ew", padx=6, pady=0)

        self.status_var = tk.StringVar(value="")  # kept for internal callers; not displayed
        style = ttk.Style(root)
        style.configure("Big.Horizontal.TProgressbar", thickness=18)
        self.progress = ttk.Progressbar(root, mode="determinate", style="Big.Horizontal.TProgressbar")
        self.progress.grid(row=5, column=0, sticky="ew", padx=6, pady=(2, 6))

        self.ctx_menu = tk.Menu(root, tearoff=0)
        self.ctx_menu.add_command(label="Open file", command=lambda: self._ctx_action("open_file"))
        self.ctx_menu.add_command(label="Open containing folder", command=lambda: self._ctx_action("open_folder"))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Copy path", command=lambda: self._ctx_action("copy_path"))
        self._ctx_tree: ttk.Treeview | None = None

    def _make_tree(self, parent, cols, headers, widths):
        frame = ttk.Frame(parent)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
        for c, h, w in zip(cols, headers, widths):
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor="w", stretch=(c == "path"))
        tree.grid(row=0, column=0, sticky="nsew")
        ysb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        xsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        return frame, tree

    def _bind_context_menu(self, tree: ttk.Treeview) -> None:
        tree.bind("<Button-3>", lambda e, t=tree: self._on_right_click(e, t))
        tree.bind("<Double-1>", lambda _e, t=tree: self._open_selected(t, "open_file"))

    def _on_right_click(self, event, tree: ttk.Treeview) -> None:
        row = tree.identify_row(event.y)
        if row and row not in tree.selection():
            tree.selection_set(row)
        if not tree.selection():
            return
        self._ctx_tree = tree
        try:
            self.ctx_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.ctx_menu.grab_release()

    def _ctx_action(self, action: str) -> None:
        if self._ctx_tree is None:
            return
        self._open_selected(self._ctx_tree, action)

    def _selected_paths(self, tree: ttk.Treeview) -> list[str]:
        cols = tree["columns"]
        if "path" in cols:
            idx = cols.index("path")
        else:
            idx = 0
        out = []
        for iid in tree.selection():
            vals = tree.item(iid, "values")
            if idx < len(vals):
                out.append(str(vals[idx]))
        return out

    def _open_selected(self, tree: ttk.Treeview, action: str) -> None:
        paths = self._selected_paths(tree)
        if not paths:
            return
        if action != "copy_path" and len(paths) > 8:
            ok = messagebox.askyesno(
                "find_and_rename",
                f"This will open {len(paths)} items. Continue?"
            )
            if not ok:
                return
        if action == "open_file":
            for p in paths:
                self._open_file(p)
        elif action == "open_folder":
            for p in paths:
                self._open_folder(p)
        elif action == "copy_path":
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(paths))
            self.status_var.set(f"Copied {len(paths)} path(s) to clipboard.")

    def _open_file(self, path: str) -> None:
        try:
            if os.path.isdir(path):
                os.startfile(path)  # type: ignore[attr-defined]
                return
            os.startfile(path)  # type: ignore[attr-defined]
        except OSError as e:
            self.log_line(f"open file failed: {path}  --  {e}")

    def _open_folder(self, path: str) -> None:
        try:
            if os.path.isdir(path):
                subprocess.Popen(["explorer.exe", path])
            else:
                subprocess.Popen(["explorer.exe", f"/select,{path}"])
        except OSError as e:
            self.log_line(f"open folder failed: {path}  --  {e}")

    def log_line(self, msg: str) -> None:
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def _set_busy(self, busy: bool, status: str = "") -> None:
        self._busy = busy
        if status:
            self.status_var.set(status)
        if not busy:
            self._progress_stop()
        self._refresh_dir_status()

    def _progress_indeterminate(self) -> None:
        self.progress.configure(mode="indeterminate")
        self.progress.start(80)

    def _progress_determinate(self, total: int) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=max(total, 1), value=0)

    def _progress_set(self, value: int) -> None:
        self.progress.configure(value=value)

    def _progress_stop(self) -> None:
        try:
            self.progress.stop()
        except tk.TclError:
            pass
        self.progress.configure(mode="determinate", value=0)

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self._msgq.get_nowait()
                self._handle_msg(kind, payload)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    def _handle_msg(self, kind: str, payload) -> None:
        if kind == "status":
            self.status_var.set(str(payload))
        elif kind == "log":
            self.log_line(str(payload))
        elif kind == "progress_det":
            done, total = payload  # type: ignore[misc]
            if self.progress["mode"] != "determinate" or self.progress["maximum"] != total:
                self._progress_determinate(total)
            self._progress_set(done)
        elif kind == "scan_done":
            result, paths = payload  # type: ignore[misc]
            self.scan = result
            self.scanned_dirs = set(paths)
            self.scanning_dirs = set()
            self._populate_after_scan()
            self._set_busy(False)
            self._refresh_dir_status()
        elif kind == "find_done":
            self.name_matches, self.content_hits, self.content_errs = payload
            self._populate_after_find()
            self._set_busy(False)
        elif kind == "rewrite_done":
            fc, occ, failed = payload
            summary = f"Rewrite: {fc} file(s) updated, {occ} occurrence(s); {len(failed)} failed."
            self.log_line(summary)
            log_to_file(summary)
            for p, m in failed:
                self.log_line(f"  failed: {p}  --  {m}")
                log_to_file(f"  rewrite failed: {p}  --  {m}")
                self.op_errors.append(("rewrite", str(p), m))
            self._append_op_errors()
            self._set_busy(False)
            self._notify_failures("Content rewrite", fc, failed)
        elif kind == "rename_done":
            done, failed = payload
            summary = f"Rename: {done} renamed; {len(failed)} failed."
            self.log_line(summary)
            log_to_file(summary)
            for s, d, m in failed:
                self.log_line(f"  failed: {s} -> {d}  --  {m}")
                log_to_file(f"  rename failed: {s} -> {d}  --  {m}")
                self.op_errors.append(("rename", f"{s}  ->  {d}", m))
            self._append_op_errors()
            self._set_busy(False)
            self._notify_failures("Rename", done, failed)
            self.on_scan()

    def on_add_dir(self) -> None:
        path = filedialog.askdirectory(title="Pick a folder to scan")
        if not path:
            return
        existing = set(self.dir_list.get(0, "end"))
        if path in existing:
            return
        self.dir_list.insert("end", path)
        self._refresh_dir_status()

    def on_remove_dir(self) -> None:
        removed = [self.dir_list.get(i) for i in self.dir_list.curselection()]
        for i in reversed(self.dir_list.curselection()):
            self.dir_list.delete(i)
        for p in removed:
            self.scanned_dirs.discard(p)
            self.scanning_dirs.discard(p)
        self._refresh_dir_status()

    def on_scan(self) -> None:
        if self._busy:
            return
        raw = list(self.dir_list.get(0, "end"))
        if not raw:
            messagebox.showinfo("find_and_rename", "Add at least one folder first.")
            return
        roots: list[Path] = []
        for r in raw:
            p = Path(r)
            if p.is_dir():
                roots.append(p.resolve())
        if not roots:
            messagebox.showerror("find_and_rename", "None of the listed paths are folders.")
            return
        self.scanning_dirs = {str(r) for r in roots} | set(raw)
        self.scanned_dirs = set()
        self.op_errors = []
        self._refresh_dir_status()
        self._set_busy(True, f"Scanning {len(roots)} root(s)...")
        self._progress_indeterminate()
        self.log_line(f"--- scan start, {len(roots)} root(s)")
        log_to_file(f"Scan start: {[str(r) for r in roots]}")

        scanned_paths = list(self.scanning_dirs)

        def worker():
            def progress(n: int) -> None:
                self._msgq.put(("status", f"Scanning... {n} entries"))
            try:
                result = walk(roots, on_progress=progress)
                self._msgq.put(("scan_done", (result, scanned_paths)))
            except Exception as e:
                self._msgq.put(("log", f"scan failed: {e!r}"))
                self._msgq.put(("scan_done", (ScanResult(), scanned_paths)))

        threading.Thread(target=worker, daemon=True).start()

    def _populate_after_scan(self) -> None:
        s = summarize(self.scan)
        c = s["counts"]
        self.status_var.set(
            f"Scan: {len(self.scan.entries)} entries  "
            f"(dirs={c['DIR']} text={c['TEXT']} bin={c['BIN']} big={c['BIG']} bad={c['UNREADABLE']})"
        )
        self.log_line(self.status_var.get())
        tree = self.error_tree
        tree.delete(*tree.get_children())
        for p, m in self.scan.errors[:5000]:
            tree.insert("", "end", values=(str(p), m))
        self.nb.tab(2, text=f"Errors ({len(self.scan.errors)})")
        self.name_matches = []
        self.content_hits = []
        self.content_errs = []
        self._populate_after_find()

    def on_find(self) -> None:
        if self._busy:
            return
        phrase = self.phrase_var.get()
        if not phrase:
            messagebox.showinfo("find_and_rename", "Type a search phrase first.")
            return
        if not self.scan.entries:
            messagebox.showinfo("find_and_rename", "Run a scan first.")
            return
        opts = SearchOpts(case_sensitive=self.case_var.get(), whole_word=self.word_var.get())
        self.last_phrase = phrase
        self.last_opts = opts
        n_text = sum(1 for e in self.scan.entries if e.kind == "TEXT")
        self._set_busy(True, f"Searching for {phrase!r} ({opts.label})... 0 / {n_text}")
        self._progress_determinate(max(n_text, 1))
        self.log_line(f"--- find {phrase!r}  ({opts.label})")

        entries = self.scan.entries

        def worker():
            try:
                names = find_name_matches(entries, phrase, opts)
                def on_prog(done, total):
                    self._msgq.put(("progress_det", (done, total)))
                    self._msgq.put(("status", f"Searching... {done} / {total} files"))
                hits, errs = find_content_matches(entries, phrase, opts, on_progress=on_prog)
                self._msgq.put(("find_done", (names, hits, errs)))
            except Exception as e:
                self._msgq.put(("log", f"find failed: {e!r}"))
                self._msgq.put(("find_done", ([], [], [])))

        threading.Thread(target=worker, daemon=True).start()

    def _populate_after_find(self) -> None:
        tree = self.name_tree
        tree.delete(*tree.get_children())
        for e in sorted(self.name_matches, key=lambda x: x.path.as_posix().lower())[:5000]:
            tree.insert("", "end", values=(e.kind, e.ext, e.stamp, str(e.path)))
        self.nb.tab(0, text=f"Name matches ({len(self.name_matches)})")

        tree = self.content_tree
        tree.delete(*tree.get_children())
        total = 0
        for entry, n in sorted(self.content_hits, key=lambda x: -x[1])[:5000]:
            total += n
            tree.insert("", "end", values=(n, entry.ext, entry.encoding or "", str(entry.path)))
        self.nb.tab(1, text=f"Content matches ({len(self.content_hits)} / {total} occ)")

        tree = self.error_tree
        for p, m in self.content_errs[:5000]:
            tree.insert("", "end", values=(str(p), f"(content) {m}"))
        n_err = len(self.scan.errors) + len(self.content_errs)
        self.nb.tab(2, text=f"Errors ({n_err})")

        self._refresh_action_buttons()

        total_occ = sum(n for _, n in self.content_hits)
        self.status_var.set(
            f"{len(self.name_matches)} name match(es); "
            f"{len(self.content_hits)} file(s) with content matches ({total_occ} occurrences)."
        )
        self.log_line(self.status_var.get())

    def _append_op_errors(self) -> None:
        tree = self.error_tree
        n_err = len(self.scan.errors) + len(self.content_errs) + len(self.op_errors)
        self.nb.tab(2, text=f"Errors ({n_err})")
        for op, path, msg in self.op_errors[-200:]:
            tree.insert("", "end", values=(path, f"({op}) {msg}"))

    def _notify_failures(self, op_label: str, ok_count: int, failed: list) -> None:
        if not failed:
            return
        lines = []
        for entry in failed[:5]:
            if len(entry) == 3:
                src, _, msg = entry
                lines.append(f"  - {src.name}: {msg}")
            else:
                path, msg = entry
                lines.append(f"  - {path.name}: {msg}")
        first = "\n".join(lines)
        more = f"\n  ... and {len(failed) - 5} more" if len(failed) > 5 else ""
        messagebox.showwarning(
            f"{op_label}: some files failed",
            f"{ok_count} succeeded.\n{len(failed)} failed.\n\n"
            f"See the Errors tab for the full list.\nLog file: {LOG_PATH}\n\n{first}{more}",
        )

    def _apply_btn(self, btn: tk.Button, kind: str, enabled: bool) -> None:
        pal = self.PALETTE[kind] if enabled else self.PALETTE["btn_disabled"]
        btn.configure(
            bg=pal["bg"], fg=pal["fg"],
            activebackground=pal.get("active", pal["bg"]),
            activeforeground=pal["fg"],
            disabledforeground=self.PALETTE["btn_disabled"]["fg"],
            state="normal" if enabled else "disabled",
        )

    def _refresh_action_buttons(self) -> None:
        has_repl = bool(self.replacement_var.get())
        self._apply_btn(self.rewrite_btn, "btn_danger", bool(self.content_hits and has_repl and not self._busy))
        self._apply_btn(self.rename_btn,  "btn_danger", bool(self.name_matches and has_repl and not self._busy))

    def _refresh_dir_status(self) -> None:
        paths = list(self.dir_list.get(0, "end"))
        for i, p in enumerate(paths):
            if p in self.scanning_dirs:
                pal = self.PALETTE["scanning"]
            elif p in self.scanned_dirs:
                pal = self.PALETTE["scanned"]
            else:
                pal = self.PALETTE["pending"]
            self.dir_list.itemconfig(
                i,
                bg=pal["bg"], fg=pal["fg"],
                selectbackground=pal["fg"], selectforeground=pal["bg"],
            )

        def _folders(n: int) -> str:
            return "1 folder" if n == 1 else f"{n} folders"

        if not paths:
            state, hint = "pending", "Add a folder to get started."
        elif self.scanning_dirs:
            state, hint = "scanning", f"Scanning {_folders(len(self.scanning_dirs))}…"
        else:
            scanned_in_list = [p for p in paths if p in self.scanned_dirs]
            unscanned = [p for p in paths if p not in self.scanned_dirs]
            if not scanned_in_list:
                state, hint = "pending", "Click Scan to enable Find matches."
            elif unscanned:
                state, hint = "scanning", f"{len(unscanned)} of {_folders(len(paths))} not yet scanned. Click Scan to include them."
            else:
                state, hint = "scanned", f"{_folders(len(paths))} scanned. Type a phrase and click Find matches."

        pal = self.PALETTE[state]
        self.dir_hint.configure(text=f"{self.HINT_ICON}  {hint}", bg=pal["bg"], fg=pal["fg"])

        if state == "scanned":
            self._apply_btn(self.find_btn, "btn_primary", not self._busy)
        elif state == "scanning" and self.scanned_dirs:
            self._apply_btn(self.find_btn, "btn_warning", not self._busy)
        else:
            self._apply_btn(self.find_btn, "btn_primary", False)

        has_unscanned = bool(paths) and any(p not in self.scanned_dirs for p in paths)
        scan_enabled = bool(paths) and not self._busy
        scan_kind = "btn_primary" if has_unscanned else "btn_disabled"
        self._apply_btn(self.scan_btn, scan_kind, scan_enabled)

    def on_rewrite(self) -> None:
        if self._busy or not self.content_hits or not self.replacement_var.get():
            return
        repl = self.replacement_var.get()
        if repl == self.last_phrase:
            messagebox.showinfo("find_and_rename", "Replacement equals the search phrase.")
            return
        n = len(self.content_hits)
        occ = sum(c for _, c in self.content_hits)
        big = "\n\n*** This is a large change. Review carefully. ***" if n > 100 else ""
        ok = messagebox.askyesno(
            "Confirm content rewrite",
            f"Rewrite '{self.last_phrase}' -> '{repl}' inside {n} file(s) "
            f"({occ} occurrence(s))?\n\nMode: {self.last_opts.label}\n\n"
            f"This modifies files in place and cannot be undone by this tool.{big}",
            default=messagebox.NO,
            icon=messagebox.WARNING,
        )
        if not ok:
            return
        self._set_busy(True, "Rewriting file contents...")
        self._progress_indeterminate()
        self.log_line(f"--- rewrite '{self.last_phrase}' -> '{repl}'  ({self.last_opts.label})")
        log_to_file(f"Rewrite start: '{self.last_phrase}' -> '{repl}'  ({self.last_opts.label}), {len(self.content_hits)} file(s)")

        hits = self.content_hits
        phrase = self.last_phrase
        opts = self.last_opts

        def worker():
            try:
                self._msgq.put(("rewrite_done", rewrite_files(hits, phrase, repl, opts)))
            except Exception as e:
                self._msgq.put(("log", f"rewrite failed: {e!r}"))
                self._msgq.put(("rewrite_done", (0, 0, [])))

        threading.Thread(target=worker, daemon=True).start()

    def on_rename(self) -> None:
        if self._busy or not self.name_matches or not self.replacement_var.get():
            return
        repl = self.replacement_var.get()
        if repl == self.last_phrase:
            messagebox.showinfo("find_and_rename", "Replacement equals the search phrase.")
            return
        plans = plan_renames(self.name_matches, self.last_phrase, repl, self.last_opts)
        if not plans:
            messagebox.showinfo("find_and_rename", "No basenames change with this replacement.")
            return
        preview = "\n".join(f"{s.name}  ->  {d.name}" for s, d in plans[:30])
        more = f"\n... {len(plans) - 30} more" if len(plans) > 30 else ""
        big = "\n\n*** This is a large change. Review carefully. ***" if len(plans) > 100 else ""
        ok = messagebox.askyesno(
            "Confirm rename",
            f"Rename {len(plans)} item(s) (deepest first)?\n\nMode: {self.last_opts.label}\n\n"
            f"{preview}{more}{big}",
            default=messagebox.NO,
            icon=messagebox.WARNING,
        )
        if not ok:
            return
        self._set_busy(True, "Renaming files / folders...")
        self._progress_indeterminate()
        self.log_line(f"--- rename {len(plans)} item(s)  ({self.last_opts.label})")
        log_to_file(f"Rename start: '{self.last_phrase}' -> '{repl}'  ({self.last_opts.label}), {len(plans)} item(s)")

        def worker():
            try:
                self._msgq.put(("rename_done", do_renames(plans)))
            except Exception as e:
                self._msgq.put(("log", f"rename failed: {e!r}"))
                self._msgq.put(("rename_done", (0, [])))

        threading.Thread(target=worker, daemon=True).start()


def main() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
