"""Shared logic for find_and_rename CLI and GUI."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


TIME_FMT = "%d-%m-%y-%H-%M-%S"
SNIFF_BYTES = 8192
CONTENT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB
TEXT_ENCODINGS = ("utf-8-sig", "utf-8", "cp1252", "latin-1")


def friendly_error(e: OSError | str) -> str:
    if isinstance(e, str):
        return e
    we = getattr(e, "winerror", None)
    en = getattr(e, "errno", None)
    table_win = {
        2:   "File or folder not found",
        3:   "Path not found",
        5:   "Access denied (read-only or no permission)",
        32:  "File is in use by another program",
        33:  "File is locked by another program",
        80:  "Target name already exists",
        87:  "Invalid path",
        123: "Invalid characters in name",
        145: "Folder is not empty",
        183: "Target name already exists",
        206: "Path is too long",
    }
    table_errno = {
        2:  "File or folder not found",
        13: "Permission denied",
        17: "Target name already exists",
        20: "Not a folder",
        21: "Is a folder",
        28: "Disk full",
        30: "Read-only filesystem",
        36: "Name too long",
        39: "Folder is not empty",
    }
    if we and we in table_win:
        return table_win[we]
    if en and en in table_errno:
        return table_errno[en]
    return str(e)

TEXT_EXTS = frozenset({
    ".txt", ".md", ".rst", ".adoc", ".tex", ".csv", ".tsv", ".log",
    ".json", ".json5", ".jsonc", ".jsonl", ".ndjson",
    ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg", ".conf", ".properties",
    ".env", ".editorconfig", ".gitignore", ".gitattributes", ".dockerignore",
    ".diff", ".patch", ".lock",
    ".py", ".pyi", ".pyx", ".pxd",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".d.ts",
    ".html", ".htm", ".xhtml", ".vue", ".svelte", ".astro",
    ".css", ".scss", ".sass", ".less", ".styl", ".svg",
    ".sh", ".bash", ".zsh", ".fish", ".ksh",
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".ipp", ".inl",
    ".cs", ".fs", ".fsx", ".vb",
    ".go", ".rs", ".swift", ".kt", ".kts",
    ".rb", ".pl", ".pm", ".php", ".phtml", ".lua", ".r", ".jl", ".dart",
    ".java", ".scala", ".sc", ".groovy", ".gradle",
    ".clj", ".cljs", ".cljc", ".edn", ".lisp", ".scm", ".rkt",
    ".ex", ".exs", ".erl", ".hrl", ".elm",
    ".hs", ".lhs", ".ml", ".mli", ".nim", ".cr",
    ".sql", ".graphql", ".gql", ".prisma",
    ".cmake", ".mk", ".make",
    ".tf", ".tfvars", ".hcl",
    ".proto", ".thrift", ".avsc",
})

BINARY_EXTS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o", ".a", ".lib",
    ".pdb", ".idb", ".ilk", ".exp",
    ".pyc", ".pyo", ".pyd", ".class", ".jar", ".war", ".ear", ".wasm",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff",
    ".webp", ".ico", ".icns", ".heic", ".heif", ".avif", ".jp2",
    ".psd", ".ai", ".sketch", ".fig",
    ".mp3", ".wav", ".flac", ".ogg", ".oga", ".aac", ".m4a", ".opus", ".wma",
    ".mp4", ".m4v", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm", ".mpg", ".mpeg",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".xz", ".txz",
    ".7z", ".rar", ".zst", ".lz", ".lz4", ".lzma", ".cab",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".pages", ".numbers", ".keynote",
    ".db", ".db3", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dat",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".iso", ".dmg", ".img", ".vhd", ".vhdx", ".vdi", ".qcow2", ".vmdk",
    ".pak", ".rpm", ".deb", ".msi", ".apk", ".ipa", ".appx", ".nupkg",
})


@dataclass
class Entry:
    path: Path
    is_dir: bool
    mtime: float
    size: int = 0
    kind: str = "DIR"  # DIR | TEXT | BIN | BIG | UNREADABLE
    encoding: str | None = None

    @property
    def stamp(self) -> str:
        return datetime.fromtimestamp(self.mtime).strftime(TIME_FMT)

    @property
    def ext(self) -> str:
        if self.is_dir:
            return ""
        return self.path.suffix.lower() or "<noext>"


@dataclass
class ScanResult:
    entries: list[Entry] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)


@dataclass(frozen=True)
class SearchOpts:
    case_sensitive: bool = False
    whole_word: bool = False

    @property
    def label(self) -> str:
        c = "case=ON " if self.case_sensitive else "case=off"
        w = " word=ON" if self.whole_word else " word=off"
        return c + w


def sniff_kind(path: Path, size: int) -> tuple[str, str | None]:
    if size > CONTENT_MAX_BYTES:
        return "BIG", None
    try:
        with open(path, "rb") as f:
            chunk = f.read(SNIFF_BYTES)
    except OSError:
        return "UNREADABLE", None
    if b"\x00" in chunk:
        return "BIN", None
    for enc in TEXT_ENCODINGS:
        try:
            chunk.decode(enc)
            return "TEXT", enc
        except UnicodeDecodeError:
            continue
    return "BIN", None


def classify(path_str: str, size: int) -> tuple[str, str | None]:
    if size > CONTENT_MAX_BYTES:
        return "BIG", None
    ext = os.path.splitext(path_str)[1].lower()
    if ext in BINARY_EXTS:
        return "BIN", None
    if ext in TEXT_EXTS:
        return "TEXT", "utf-8"
    return sniff_kind(Path(path_str), size)


def walk(roots: list[Path], on_progress=None) -> ScanResult:
    res = ScanResult()
    count = 0

    def record_error(p: Path, msg: str) -> None:
        res.errors.append((p, msg))

    def visit(start: Path) -> None:
        nonlocal count
        stack: list[str] = [str(start)]
        while stack:
            d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError as e:
                record_error(Path(d), str(e))
                continue
            with it:
                for de in it:
                    try:
                        is_dir = de.is_dir(follow_symlinks=False)
                    except OSError as e:
                        record_error(Path(de.path), str(e))
                        continue
                    if is_dir:
                        try:
                            st = de.stat(follow_symlinks=False)
                        except OSError as e:
                            record_error(Path(de.path), str(e))
                            continue
                        res.entries.append(Entry(Path(de.path), True, st.st_mtime))
                        count += 1
                        stack.append(de.path)
                    else:
                        try:
                            st = de.stat(follow_symlinks=False)
                        except OSError as e:
                            record_error(Path(de.path), str(e))
                            continue
                        kind, enc = classify(de.path, st.st_size)
                        res.entries.append(
                            Entry(Path(de.path), False, st.st_mtime, st.st_size, kind, enc)
                        )
                        count += 1
                    if on_progress and count % 500 == 0:
                        on_progress(count)

    for root in roots:
        try:
            st = root.stat()
        except OSError as e:
            record_error(root, str(e))
            continue
        res.entries.append(Entry(root, True, st.st_mtime))
        count += 1
        visit(root)

    if on_progress:
        on_progress(count)
    return res


def summarize(scan: ScanResult) -> dict:
    counts = {"DIR": 0, "TEXT": 0, "BIN": 0, "BIG": 0, "UNREADABLE": 0}
    ext_counts: dict[str, int] = {}
    for e in scan.entries:
        counts[e.kind] = counts.get(e.kind, 0) + 1
        if not e.is_dir:
            ext_counts[e.ext] = ext_counts.get(e.ext, 0) + 1
    return {"counts": counts, "ext_counts": ext_counts}


def _compile(phrase: str, opts: SearchOpts) -> re.Pattern[str]:
    flags = 0 if opts.case_sensitive else re.IGNORECASE
    body = re.escape(phrase)
    if opts.whole_word:
        body = r"\b" + body + r"\b"
    return re.compile(body, flags)


def find_name_matches(entries: list[Entry], phrase: str, opts: SearchOpts) -> list[Entry]:
    pat = _compile(phrase, opts)
    return [e for e in entries if pat.search(e.path.name)]


def _read_text(entry: Entry) -> tuple[str | None, str | None, bool]:
    try:
        raw = entry.path.read_bytes()
    except OSError as e:
        return None, str(e), False
    had_bom = raw.startswith(b"\xef\xbb\xbf")
    if had_bom:
        raw = raw[3:]
    enc_order: list[str] = []
    if entry.encoding and entry.encoding != "utf-8-sig":
        enc_order.append(entry.encoding)
    for enc in ("utf-8", "cp1252", "latin-1"):
        if enc not in enc_order:
            enc_order.append(enc)
    last_err = "no encoding worked"
    for enc in enc_order:
        try:
            return raw.decode(enc), enc, had_bom
        except UnicodeDecodeError as e:
            last_err = f"decode {enc}: {e}"
    return None, last_err, had_bom


def _count_in(text: str, pat: re.Pattern[str], phrase: str, opts: SearchOpts) -> int:
    if opts.whole_word:
        return len(pat.findall(text))
    if opts.case_sensitive:
        return text.count(phrase)
    return text.lower().count(phrase.lower())


def find_content_matches(
    entries: list[Entry], phrase: str, opts: SearchOpts, on_progress=None
) -> tuple[list[tuple[Entry, int]], list[tuple[Path, str]]]:
    pat = _compile(phrase, opts)
    targets = [e for e in entries if not e.is_dir and e.kind == "TEXT"]
    total = len(targets)
    hits: list[tuple[Entry, int]] = []
    errs: list[tuple[Path, str]] = []
    for i, e in enumerate(targets, 1):
        text, err, _ = _read_text(e)
        if text is None:
            errs.append((e.path, err or "read failed"))
        else:
            n = _count_in(text, pat, phrase, opts)
            if n:
                hits.append((e, n))
        if on_progress and (i % 200 == 0 or i == total):
            on_progress(i, total)
    return hits, errs


def _substitute(text: str, phrase: str, replacement: str, opts: SearchOpts) -> tuple[str, int]:
    pat = _compile(phrase, opts)
    new_text, n = pat.subn(lambda _: replacement, text)
    return new_text, n


def plan_renames(
    matches: list[Entry], phrase: str, replacement: str, opts: SearchOpts
) -> list[tuple[Path, Path]]:
    ordered = sorted(matches, key=lambda e: len(e.path.parts), reverse=True)
    plans: list[tuple[Path, Path]] = []
    for e in ordered:
        new_name, n = _substitute(e.path.name, phrase, replacement, opts)
        if n == 0 or new_name == e.path.name:
            continue
        plans.append((e.path, e.path.with_name(new_name)))
    return plans


def do_renames(plans: list[tuple[Path, Path]]) -> tuple[int, list[tuple[Path, Path, str]]]:
    done = 0
    failed: list[tuple[Path, Path, str]] = []
    for src, dst in plans:
        try:
            if dst.exists() and src.resolve() != dst.resolve():
                failed.append((src, dst, "Target name already exists"))
                continue
            src.rename(dst)
            done += 1
        except OSError as e:
            failed.append((src, dst, friendly_error(e)))
    return done, failed


def rewrite_files(
    hits: list[tuple[Entry, int]], phrase: str, replacement: str, opts: SearchOpts
) -> tuple[int, int, list[tuple[Path, str]]]:
    files_changed = 0
    occurrences = 0
    failed: list[tuple[Path, str]] = []
    for entry, _ in hits:
        text, enc, had_bom = _read_text(entry)
        if text is None:
            failed.append((entry.path, friendly_error(enc or "read failed")))
            continue
        new_text, n = _substitute(text, phrase, replacement, opts)
        if n == 0 or new_text == text:
            continue
        try:
            payload = new_text.encode(enc or "utf-8", errors="strict")
        except UnicodeEncodeError:
            payload = new_text.encode("utf-8")
        if had_bom:
            payload = b"\xef\xbb\xbf" + payload
        tmp = entry.path.with_suffix(entry.path.suffix + ".aifix-tmp")
        try:
            tmp.write_bytes(payload)
            os.replace(tmp, entry.path)
        except OSError as e:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            failed.append((entry.path, friendly_error(e)))
            continue
        files_changed += 1
        occurrences += n
    return files_changed, occurrences, failed
