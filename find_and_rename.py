#!/usr/bin/env python3
"""Interactive CLI for scanning, searching, and mass-renaming."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from find_and_rename_core import (  # noqa: E402
    SearchOpts,
    walk,
    summarize,
    find_name_matches,
    find_content_matches,
    plan_renames,
    do_renames,
    rewrite_files,
)


def prompt(msg: str) -> str:
    try:
        return input(msg)
    except EOFError:
        print()
        sys.exit(0)


def ask_directories() -> list[Path]:
    print("Enter directories to scan, one per line. Blank line to finish.")
    print("Example: c:\\claude")
    print("         C:\\Users\\w_user\\.claude")
    dirs: list[Path] = []
    while True:
        raw = prompt(f"  dir[{len(dirs) + 1}]> ").strip().strip('"').strip("'")
        if not raw:
            if dirs:
                return dirs
            print("  need at least one directory")
            continue
        p = Path(raw).expanduser()
        if not p.exists():
            print(f"  not found: {p}")
            continue
        if not p.is_dir():
            print(f"  not a directory: {p}")
            continue
        resolved = p.resolve()
        if resolved in dirs:
            print(f"  already added: {resolved}")
            continue
        dirs.append(resolved)


def show_summary(scan) -> None:
    s = summarize(scan)
    c = s["counts"]
    print(
        f"  totals: dirs={c['DIR']}  text={c['TEXT']}  binary={c['BIN']}  "
        f"oversized={c['BIG']}  unreadable={c['UNREADABLE']}"
    )
    ext = s["ext_counts"]
    if ext:
        top = sorted(ext.items(), key=lambda kv: -kv[1])[:10]
        print("  top extensions: " + "  ".join(f"{k}:{v}" for k, v in top))


def show_listing(entries, limit):
    items = sorted(entries, key=lambda e: e.path.as_posix().lower())
    shown = items if limit is None else items[:limit]
    if not shown:
        print("  (nothing to show)")
        return
    for e in shown:
        ext = "" if e.is_dir else f"  ({e.ext})"
        print(f"  {e.stamp}  {e.kind:<10}  {e.path}{ext}")
    if limit is not None and len(items) > limit:
        print(f"  ... {len(items) - limit} more")


def main() -> int:
    print("=== find_and_rename ===")
    roots = ask_directories()

    print()
    print("Scanning (classifying file types)...")
    scan = walk(roots)
    print(f"  scanned {len(scan.entries)} entries across {len(roots)} root(s)")
    show_summary(scan)
    if scan.errors:
        print(f"  {len(scan.errors)} entries unreadable (press 'e' to view)")

    opts = SearchOpts()
    while True:
        print()
        print(f"Mode: {opts.label}")
        print("Commands:")
        print("  l         list first 50 entries (l a = list all)")
        print("  t         show count by file type / extension")
        print("  e         show scan errors")
        print("  c         toggle case sensitivity")
        print("  w         toggle whole-word matching")
        print("  s         search by phrase, then optionally edit contents and/or rename")
        print("  r         rescan")
        print("  q         quit")
        cmd = prompt("> ").strip().lower()

        if cmd in {"q", "quit", "exit"}:
            return 0
        if cmd == "l":
            show_listing(scan.entries, 50)
            continue
        if cmd in {"l a", "la", "l all"}:
            show_listing(scan.entries, None)
            continue
        if cmd == "t":
            show_summary(scan)
            continue
        if cmd == "e":
            if not scan.errors:
                print("  no errors")
            for p, msg in scan.errors:
                print(f"  {p}  --  {msg}")
            continue
        if cmd == "c":
            opts = SearchOpts(case_sensitive=not opts.case_sensitive, whole_word=opts.whole_word)
            continue
        if cmd == "w":
            opts = SearchOpts(case_sensitive=opts.case_sensitive, whole_word=not opts.whole_word)
            continue
        if cmd == "r":
            scan = walk(roots)
            print(f"  scanned {len(scan.entries)} entries")
            show_summary(scan)
            continue
        if cmd != "s":
            print("  unknown command")
            continue

        phrase = prompt("  search phrase: ")
        if not phrase:
            print("  empty phrase, skipping")
            continue

        name_matches = find_name_matches(scan.entries, phrase, opts)
        print(f"  name matches: {len(name_matches)}  ({opts.label})")
        if name_matches:
            show_listing(name_matches, 200)

        print("  scanning text-file contents for the phrase...")
        content_hits, content_errs = find_content_matches(scan.entries, phrase, opts)
        total_occ = sum(n for _, n in content_hits)
        print(f"  content matches: {len(content_hits)} file(s), {total_occ} occurrence(s)")
        for entry, n in sorted(content_hits, key=lambda x: -x[1])[:50]:
            print(f"    {n:>4}x  {entry.path}  ({entry.ext}, {entry.encoding})")
        if len(content_hits) > 50:
            print(f"    ... {len(content_hits) - 50} more")
        if content_errs:
            print(f"  {len(content_errs)} file(s) unreadable for content scan:")
            for p, msg in content_errs[:20]:
                print(f"    {p}  --  {msg}")
            if len(content_errs) > 20:
                print(f"    ... {len(content_errs) - 20} more")

        if not name_matches and not content_hits:
            continue

        replacement = prompt(f"  replace '{phrase}' with (empty = cancel): ")
        if replacement == "":
            print("  cancelled")
            continue
        if replacement == phrase:
            print("  replacement equals phrase, nothing to do")
            continue

        if content_hits:
            confirm = prompt(
                f"  rewrite contents of {len(content_hits)} file(s)? type 'yes' to confirm: "
            ).strip().lower()
            if confirm == "yes":
                fc, occ, failed = rewrite_files(content_hits, phrase, replacement, opts)
                print(f"  contents: {fc} file(s) updated, {occ} occurrence(s) rewritten")
                for p, msg in failed:
                    print(f"    failed: {p}  --  {msg}")
            else:
                print("  contents skipped")

        if name_matches:
            plans = plan_renames(name_matches, phrase, replacement, opts)
            if not plans:
                print("  no basenames changed by the substitution")
            else:
                print(f"  {len(plans)} rename(s) planned (deepest first):")
                for src, dst in plans[:50]:
                    print(f"    {src.name}  ->  {dst.name}")
                if len(plans) > 50:
                    print(f"    ... {len(plans) - 50} more")
                confirm = prompt("  proceed with renames? type 'yes' to confirm: ").strip().lower()
                if confirm == "yes":
                    done, failed = do_renames(plans)
                    print(f"  renamed: {done}")
                    for src, dst, msg in failed:
                        print(f"    failed: {src} -> {dst}  --  {msg}")
                else:
                    print("  renames skipped")

        print("  rescanning to refresh paths and types...")
        scan = walk(roots)
        print(f"  scanned {len(scan.entries)} entries")
        show_summary(scan)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
