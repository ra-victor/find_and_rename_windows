"""Functional, security, longevity, and sanity tests for find_and_rename.

Run: python test_suite.py
Creates a sandbox under the OS temp dir and cleans up afterwards.
"""

from __future__ import annotations

import gc
import os
import shutil
import sys
import tempfile
import threading
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from find_and_rename_core import (  # noqa: E402
    SearchOpts,
    walk,
    summarize,
    find_name_matches,
    find_content_matches,
    plan_renames,
    plan_renames_ex,
    do_renames,
    rewrite_files,
    classify,
    sniff_kind,
)


PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

results: list[tuple[str, str, str]] = []  # (group, name, status_or_msg)


def record(group: str, name: str, status: str, detail: str = "") -> None:
    msg = status if not detail else f"{status} -- {detail}"
    results.append((group, name, msg))
    icon = "[ OK ]" if status == PASS else ("[FAIL]" if status == FAIL else "[SKIP]")
    print(f"  {icon} {name}{('  ' + detail) if detail else ''}")


def check(cond: bool, group: str, name: str, detail: str = "") -> None:
    record(group, name, PASS if cond else FAIL, detail if not cond else "")


def make_sandbox() -> Path:
    base = Path(tempfile.gettempdir()) / f"find_and_rename_test_{os.getpid()}"
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True)
    return base


def populate(base: Path) -> None:
    # Basic text files
    (base / "alpha_foo.txt").write_text("hello foo bar\nfoo foo\n", encoding="utf-8")
    (base / "beta_foo.md").write_text("# foo title\nFoo Bar\n", encoding="utf-8")
    (base / "gamma.json").write_text('{"key": "foo value"}', encoding="utf-8")

    # Subdirectory with claude-code-like files
    cd = base / "subdir" / "foo_inside"
    cd.mkdir(parents=True)
    (cd / "CLAUDE.md").write_text("Project: foo-bar\n", encoding="utf-8")
    (cd / "settings.json").write_text('{"x":"foo"}', encoding="utf-8")
    (cd / ".mcp.json").write_text('{"servers":{"foo": {}}}', encoding="utf-8")

    # Binary file (should NOT be content-scanned)
    (base / "image.bin").write_bytes(bytes(range(256)) * 4)  # has nulls -> BIN

    # File with no extension but text content
    (base / "README").write_text("foo bar baz\n", encoding="utf-8")

    # File with BOM
    (base / "bom_foo.txt").write_bytes(b"\xef\xbb\xbfprefix foo suffix\n")

    # Unicode in filename and content
    (base / "café_foo.txt").write_text("foo ünïcødé\n", encoding="utf-8")

    # Folder named with phrase
    fp = base / "foo_folder"
    fp.mkdir()
    (fp / "child.txt").write_text("no match here\n", encoding="utf-8")


# ---------- 1. Functional ----------

def test_functional(base: Path) -> None:
    grp = "functional"
    print(f"\n[{grp}]")

    r = walk([base])
    s = summarize(r)
    c = s["counts"]
    check(c["TEXT"] >= 8, grp, "scan picks up text files", f"text={c['TEXT']}")
    check(c["BIN"] >= 1, grp, "scan picks up binary files", f"bin={c['BIN']}")
    check(c["DIR"] >= 3, grp, "scan picks up directories", f"dirs={c['DIR']}")

    opts = SearchOpts()
    names = find_name_matches(r.entries, "foo", opts)
    check(len(names) >= 5, grp, "name search finds expected count", f"got {len(names)}")

    hits, errs = find_content_matches(r.entries, "foo", opts)
    check(len(hits) >= 6, grp, "content search finds expected files", f"got {len(hits)}")
    check(len(errs) == 0, grp, "no content scan errors", f"errs={errs}")

    # Verify Claude Code files specifically
    claude_files = [h for h, _ in hits if h.path.name in ("CLAUDE.md", "settings.json", ".mcp.json")]
    check(len(claude_files) == 3, grp, "CLAUDE.md/settings.json/.mcp.json all matched",
          f"got {[h.path.name for h in claude_files]}")

    # Rewrite contents
    fc, occ, failed = rewrite_files(hits, "foo", "bar", opts)
    check(fc >= 6, grp, "rewrite changed expected files", f"fc={fc}")
    check(len(failed) == 0, grp, "rewrite had no failures", f"failed={failed}")
    # Verify content
    after = (base / "alpha_foo.txt").read_text(encoding="utf-8")
    check("foo" not in after and "bar" in after, grp, "alpha_foo.txt rewritten correctly")

    # Verify BOM preserved
    bom_bytes = (base / "bom_foo.txt").read_bytes()
    check(bom_bytes.startswith(b"\xef\xbb\xbf"), grp, "BOM preserved after rewrite")

    # Re-scan and plan renames
    r2 = walk([base])
    names2 = find_name_matches(r2.entries, "foo", opts)
    plans = plan_renames(names2, "foo", "bar", opts)
    check(len(plans) >= 5, grp, "plan_renames produces plans", f"plans={len(plans)}")

    # Deepest-first ordering check
    depths = [len(s.parts) for s, _ in plans]
    check(depths == sorted(depths, reverse=True), grp, "plans ordered deepest-first")

    done, failed = do_renames(plans)
    check(done >= 5, grp, "do_renames succeeds", f"done={done}, failed={failed}")
    check(not (base / "alpha_foo.txt").exists(), grp, "old name gone")
    check((base / "alpha_bar.txt").exists(), grp, "new name present")


# ---------- 2. Security ----------

def test_security(base: Path) -> None:
    grp = "security"
    print(f"\n[{grp}]")
    sec = base / "_sec"
    sec.mkdir(exist_ok=True)
    (sec / "victim_foo.txt").write_text("foo content", encoding="utf-8")
    (sec / "noext_foo").write_text("foo here", encoding="utf-8")

    r = walk([sec])
    opts = SearchOpts()
    names = find_name_matches(r.entries, "foo", opts)

    # Replacement with path separators/invalid chars must be rejected, never traverse
    bad_replacements = ["../escape", "..\\escape", "foo/bar", "x\\y", ".", "..", "",
                        "a:b", "a*b", "a?b", "a|b", "a<b", "a>b", 'a"b']
    for repl in bad_replacements:
        try:
            plans, rejected = plan_renames_ex(names, "foo", repl, opts)
        except Exception as e:
            record(grp, f"replacement={repl!r} no crash", FAIL, f"{type(e).__name__}: {e}")
            continue
        # Every accepted plan must stay in the same parent dir (no traversal)
        all_in_parent = all(s.parent == d.parent for s, d in plans)
        check(all_in_parent, grp, f"replacement={repl!r} plans stay in parent dir")
        # Replacements containing a path separator or forbidden char must produce
        # at least one rejection (any of our test files would yield an invalid name).
        if repl and any(c in repl for c in '/\\:*?"<>|'):
            check(len(rejected) >= 1, grp, f"replacement={repl!r} produces rejections",
                  f"got {len(rejected)} rejected, {len(plans)} planned")

    # Whole-basename "." or ".." must be rejected
    exact = sec / "exact_match"
    exact.mkdir(exist_ok=True)
    (exact / "foo").write_text("x", encoding="utf-8")
    r_exact = walk([exact])
    names_e = find_name_matches(r_exact.entries, "foo", opts)
    _, rej_dot = plan_renames_ex(names_e, "foo", ".", opts)
    _, rej_ddot = plan_renames_ex(names_e, "foo", "..", opts)
    check(any("reserved" in r[1] for r in rej_dot), grp,
          "phrase=='foo', replacement='.', whole-name '.' rejected",
          f"rej={rej_dot}")
    check(any("reserved" in r[1] for r in rej_ddot), grp,
          "phrase=='foo', replacement='..', whole-name '..' rejected",
          f"rej={rej_ddot}")

    # Regex backref in replacement must be literal
    (sec / "alpha_foo_back.txt").write_text("foo content", encoding="utf-8")
    r2 = walk([sec])
    hits2, _ = find_content_matches(r2.entries, "foo", opts)
    fc, occ, failed = rewrite_files(hits2, "foo", r"\1backref", opts)
    after = ""
    for p in sec.iterdir():
        if p.is_file():
            after = p.read_text(encoding="utf-8")
            if "backref" in after:
                break
    check(r"\1backref" in after, grp, "regex backref in replacement is literal",
          f"file contents include literal: {after!r}")

    # Symlinks: walk should not follow them
    sym_target = sec / "_real_target"
    sym_target.mkdir(exist_ok=True)
    (sym_target / "real_foo.txt").write_text("foo", encoding="utf-8")
    sym_link = sec / "_symlink"
    try:
        if sym_link.exists() or sym_link.is_symlink():
            sym_link.unlink()
        os.symlink(sym_target, sym_link, target_is_directory=True)
    except (OSError, NotImplementedError):
        record(grp, "symlink not followed", SKIP, "cannot create symlink (need admin on Windows)")
    else:
        r3 = walk([sec])
        # entries should not contain a duplicate path under _symlink
        sym_entries = [e for e in r3.entries if "_symlink" in str(e.path)]
        # the symlink itself appears, but its target's children should NOT be enumerated through it
        has_descendants = any(
            "_symlink" in str(e.path) and e.path.name == "real_foo.txt"
            for e in r3.entries
        )
        check(not has_descendants, grp, "walk does not descend into symlinks")

    # Phrase with regex metacharacters is escaped (skip chars Windows refuses)
    safe_meta_name = "regex_test_(plus).txt"
    (sec / safe_meta_name).write_text("hello", encoding="utf-8")
    r4 = walk([sec])
    # "(.*)" would match every name if regex weren't escaped; verify it matches none
    bogus = find_name_matches(r4.entries, "(.*)", opts)
    check(bogus == [], grp, "regex metachars in phrase are escaped (no false matches)",
          f"got {[e.path.name for e in bogus]}")
    # Literal "(plus)" should match the one file we created
    literal = find_name_matches(r4.entries, "(plus)", opts)
    check(len(literal) == 1, grp, "literal parenthesized phrase matches exact substring",
          f"got {[e.path.name for e in literal]}")


# ---------- 3. Longevity ----------

def test_longevity(base: Path) -> None:
    grp = "longevity"
    print(f"\n[{grp}]")
    long_dir = base / "_long"
    long_dir.mkdir(exist_ok=True)
    for i in range(200):
        (long_dir / f"item_{i:04d}.txt").write_text(f"line {i} foo\n", encoding="utf-8")

    # Repeated scans must not leak memory significantly
    tracemalloc.start()
    gc.collect()
    snap1 = tracemalloc.take_snapshot()
    for _ in range(10):
        r = walk([long_dir])
        _ = summarize(r)
        opts = SearchOpts()
        _ = find_name_matches(r.entries, "foo", opts)
        _ = find_content_matches(r.entries, "foo", opts)
        del r
        gc.collect()
    snap2 = tracemalloc.take_snapshot()
    tracemalloc.stop()
    diff = sum(s.size_diff for s in snap2.compare_to(snap1, "filename"))
    check(diff < 5 * 1024 * 1024, grp, "no large memory growth across 10 scan/find cycles",
          f"net diff = {diff/1024:.1f} KB")

    # Threaded scans of disjoint dirs run independently
    errors_seen = []
    def runner():
        try:
            walk([long_dir])
        except Exception as e:
            errors_seen.append(e)
    threads = [threading.Thread(target=runner, daemon=True) for _ in range(4)]
    t0 = time.monotonic()
    for t in threads: t.start()
    for t in threads: t.join(timeout=30)
    elapsed = time.monotonic() - t0
    check(not errors_seen, grp, "concurrent scans complete without exceptions",
          f"errs={errors_seen}")
    check(elapsed < 30, grp, "concurrent scans don't deadlock", f"{elapsed:.2f}s")

    # Rewrite leaves no .aifix-tmp turds when succeeding
    r5 = walk([long_dir])
    hits, _ = find_content_matches(r5.entries, "foo", SearchOpts())
    rewrite_files(hits, "foo", "bar", SearchOpts())
    tmp_files = list(long_dir.glob("*.aifix-tmp"))
    check(not tmp_files, grp, "no .aifix-tmp leftovers after successful rewrite",
          f"leftover={tmp_files}")


# ---------- 4. Sanity ----------

def test_sanity(base: Path) -> None:
    grp = "sanity"
    print(f"\n[{grp}]")

    # Empty inputs
    r = walk([])
    check(r.entries == [] and r.errors == [], grp, "walk([]) returns empty result")

    # Non-existent dir is reported as error, not crash
    bogus = base / "_does_not_exist_xyzzy"
    r2 = walk([bogus])
    check(len(r2.errors) == 1, grp, "non-existent root yields one error")

    # Replacement equal to phrase yields no plans
    sane = base / "_sane"
    sane.mkdir(exist_ok=True)
    (sane / "abc_foo.txt").write_text("foo", encoding="utf-8")
    r3 = walk([sane])
    plans = plan_renames(find_name_matches(r3.entries, "foo", SearchOpts()),
                         "foo", "foo", SearchOpts())
    check(plans == [], grp, "replacement == phrase yields no plans")

    # Empty phrase: regex compiles to empty match -> would match everywhere; check it's at least not crashing
    try:
        find_name_matches(r3.entries, "", SearchOpts())
        record(grp, "empty phrase doesn't crash", PASS)
    except Exception as e:
        record(grp, "empty phrase doesn't crash", FAIL, str(e))

    # Whole word option
    (sane / "foobar_foo.txt").write_text("foobar foo bar\n", encoding="utf-8")
    r4 = walk([sane])
    opts_word = SearchOpts(whole_word=True)
    hits_word, _ = find_content_matches(r4.entries, "foo", opts_word)
    # Should match files containing standalone "foo" but count fewer occurrences than non-word mode
    opts_any = SearchOpts(whole_word=False)
    hits_any, _ = find_content_matches(r4.entries, "foo", opts_any)
    total_word = sum(n for _, n in hits_word)
    total_any = sum(n for _, n in hits_any)
    check(total_word <= total_any, grp, "whole_word counts <= substring counts",
          f"word={total_word} any={total_any}")

    # Case sensitivity
    (sane / "Mixed_FOO.txt").write_text("Foo FOO foo\n", encoding="utf-8")
    r5 = walk([sane])
    hits_cs, _ = find_content_matches(r5.entries, "foo", SearchOpts(case_sensitive=True))
    hits_ci, _ = find_content_matches(r5.entries, "foo", SearchOpts(case_sensitive=False))
    cs = sum(n for _, n in hits_cs)
    ci = sum(n for _, n in hits_ci)
    check(cs < ci, grp, "case_sensitive yields fewer hits than insensitive",
          f"cs={cs} ci={ci}")

    # Classify directly: text/binary edge cases
    txt = sane / "plain.txt"
    txt.write_text("hello", encoding="utf-8")
    kind, enc = classify(str(txt), txt.stat().st_size)
    check(kind == "TEXT", grp, "classify .txt as TEXT", f"got {kind}")

    nul = sane / "withnull.dat"
    nul.write_bytes(b"abc\x00def")
    kind2, _ = sniff_kind(nul, nul.stat().st_size)
    check(kind2 == "BIN", grp, "null byte sniff -> BIN", f"got {kind2}")

    # GUI module imports cleanly without DISPLAY-style failure
    try:
        import importlib
        gui = importlib.import_module("find_and_rename_gui")
        check(hasattr(gui, "App") and hasattr(gui, "main"), grp, "GUI module exports App and main")
    except Exception as e:
        record(grp, "GUI module imports", FAIL, str(e))

    # CLI module imports cleanly
    try:
        import importlib
        cli = importlib.import_module("find_and_rename")
        check(hasattr(cli, "main"), grp, "CLI module exports main")
    except Exception as e:
        record(grp, "CLI module imports", FAIL, str(e))


# ---------- runner ----------

def main() -> int:
    base = make_sandbox()
    print(f"sandbox: {base}")
    try:
        populate(base)
        test_functional(base)
        test_security(base)
        test_longevity(base)
        test_sanity(base)
    finally:
        try:
            shutil.rmtree(base, ignore_errors=True)
        except Exception:
            pass

    print("\n=== SUMMARY ===")
    by_status: dict[str, int] = {}
    for _, _, s in results:
        key = s.split(" -- ", 1)[0]
        by_status[key] = by_status.get(key, 0) + 1
    for k, v in by_status.items():
        print(f"  {k}: {v}")
    fails = [(g, n, s) for g, n, s in results if s.startswith(FAIL)]
    if fails:
        print("\nFailures:")
        for g, n, s in fails:
            print(f"  [{g}] {n}: {s}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
