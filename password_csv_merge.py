#!/usr/bin/env python3
"""Merge any compatible password CSV into a base CSV, locally.

Run: python3 password_csv_merge.py --show-passwords
Choose each difference: python3 password_csv_merge.py --review
For Apple and Chrome, add --base-label Apple --incoming-label Chrome.
File pickers choose incoming CSV, base CSV, and a NEW output CSV.
Or supply --incoming PATH --base PATH --output PATH.

Only matching Base Password fields change. All Base rows, header columns,
Notes, OTPAuth, and other values remain. Incoming-only rows are excluded unless
--add-incoming-only is supplied. Source files are never modified.

Matching uses exact, case-sensitive username plus normalized URL first;
otherwise exact hostname and non-default port plus username. Subdomains and
www. remain distinct. When Incoming has different passwords for the same
host/username, an exact URL match resolves it; otherwise that Base row is
left unchanged and counted as ambiguous. Empty Incoming passwords are skipped.

--review shows one difference at a time. 1 keeps Base, 2 chooses Incoming,
B goes back, and Q cancels without writing a CSV. Keys act immediately, with
no Enter needed. Choices stay in memory only. The output is written after
review finishes. Same-password and Base-only rows do not require review.

--show-passwords displays changed sites/usernames/old and new passwords directly on
/dev/tty in an alternate screen, with paging, cleared on dismissal. It refuses
redirected input/output. There are no network calls, password logs, clipboard
operations, or extra report files. The one new CSV is written with mode 0600.
This CANNOT defeat terminal recording, screen capture, endpoint monitoring,
swap, or other software on your Mac. Terminal settings may retain alternate
screen content. Python keeps credentials in memory while the script runs.
The source and merged CSVs contain plaintext credentials; store them securely.

No packages needed; Python 3.8+ standard library only.
"""

import argparse
import csv
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import textwrap
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class MergeError(Exception):
    """An error message that contains no credential values."""


@dataclass
class Table:
    headers: list
    rows: list
    columns: dict


def load_csv(path, source):
    try:
        with Path(path).open("r", encoding="utf-8-sig", newline="") as source_file:
            text = source_file.read()
    except (OSError, UnicodeError):
        raise MergeError("Cannot read the %s CSV as UTF-8. Use the original export." % source) from None
    delimiter = None
    for candidate in (",", ";", "\t"):
        try:
            header = next(csv.reader(io.StringIO(text, newline=""), delimiter=candidate, strict=True))
        except (csv.Error, StopIteration):
            continue
        normalized = [h.strip().casefold() for h in header]
        if {"url", "username", "password"}.issubset(normalized):
            delimiter = candidate
            break
    if delimiter is None:
        raise MergeError("%s CSV needs URL, Username, and Password columns." % source)
    try:
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
        headers = next(reader)
        rows = []
        for number, row in enumerate(reader, 2):
            if not row:
                continue
            if len(row) != len(headers):
                raise MergeError("%s CSV record %d has an unexpected number of fields." % (source, number))
            rows.append(row)
    except csv.Error:
        raise MergeError("Malformed %s CSV. Use the original export." % source) from None
    names = [h.strip().casefold() for h in headers]
    if len(set(names)) != len(names):
        raise MergeError("%s CSV has duplicate column headers." % source)
    return Table(headers, rows, dict(zip(names, range(len(names)))))


def normalized_url(raw):
    """Return (canonical URL, host with non-default port), or exact raw URL only."""
    raw = raw.strip()
    if not raw:
        return None, None
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.casefold() not in ("http", "https") or not parsed.hostname:
            return raw, None
        if parsed.username is not None or parsed.password is not None:
            return raw, None
        host = parsed.hostname.casefold().encode("idna").decode("ascii")
        if any(c.isspace() for c in host) or any(c in host for c in "\\;,\"<>"):
            return raw, None
        scheme = parsed.scheme.casefold()
        port = parsed.port
        if (scheme, port) in (("http", 80), ("https", 443)):
            port = None
        authority = ("[" + host + "]") if ":" in host else host
        if port is not None:
            authority += ":" + str(port)
        canonical = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))
        return canonical, authority
    except (ValueError, UnicodeError):
        return raw, None


def merge_tables(base, incoming, add_incoming_only=False, match="host"):
    if match not in ("host", "exact"):
        raise MergeError("Matching mode must be host or exact.")
    exact_index, host_index = defaultdict(list), defaultdict(list)
    for row in incoming.rows:
        username = row[incoming.columns["username"]]
        exact, host = normalized_url(row[incoming.columns["url"]])
        if exact:
            exact_index[(exact, username)].append(row)
        if host:
            host_index[(host, username)].append(row)

    output = [row[:] for row in base.rows]
    changes, reviews = [], []
    stats = Counter(base_rows=len(base.rows), incoming_rows=len(incoming.rows))
    seen_incoming_ids = set()
    for index, original in enumerate(base.rows):
        username = original[base.columns["username"]]
        raw_url = original[base.columns["url"]]
        exact, host = normalized_url(raw_url)
        candidates = exact_index.get((exact, username), []) if exact else []
        if not candidates and host and match == "host":
            candidates = host_index.get((host, username), [])
        if not candidates:
            stats["base_only"] += 1
            continue
        stats["matched"] += 1
        # Every same-host candidate is an overlap, even if an exact URL chose one.
        overlaps = host_index.get((host, username), candidates) if host and match == "host" else candidates
        seen_incoming_ids.update(id(r) for r in overlaps)
        passwords = {r[incoming.columns["password"]] for r in candidates}
        if len(passwords) != 1:
            stats["ambiguous"] += 1
            reviews.append((raw_url, username, "Incoming has conflicting passwords for this match"))
            continue
        new_password = next(iter(passwords))
        if not new_password:
            stats["empty_skipped"] += 1
            reviews.append((raw_url, username, "Incoming password is empty; Base retained"))
            continue
        if original[base.columns["password"]] == new_password:
            stats["already_same"] += 1
            continue
        output[index][base.columns["password"]] = new_password
        changes.append((raw_url, username, original[base.columns["password"]], new_password, index))
        stats["changed"] += 1

    incoming_only = [r for r in incoming.rows if id(r) not in seen_incoming_ids]
    stats["incoming_only"] = len(incoming_only)
    if add_incoming_only:
        appended = set()
        for row in incoming_only:
            exact, host = normalized_url(row[incoming.columns["url"]])
            username, password = row[incoming.columns["username"]], row[incoming.columns["password"]]
            key = (exact, username) if exact else None
            if not key or not password or key in appended:
                stats["additions_skipped"] += 1
                continue
            candidates = exact_index.get(key, [])
            if len({r[incoming.columns["password"]] for r in candidates}) > 1:
                stats["additions_skipped"] += 1
                continue
            new_row = [""] * len(base.headers)
            for name, position in base.columns.items():
                source_name = name
                if source_name not in incoming.columns:
                    source_name = {"title": "name", "name": "title", "notes": "note", "note": "notes"}.get(name, name)
                if source_name in incoming.columns:
                    new_row[position] = row[incoming.columns[source_name]]
            output.append(new_row)
            appended.add(key)
            stats["added"] += 1

    # Invariants protect Base-only records and every non-password column.
    for old, new in zip(base.rows, output):
        for column in range(len(base.headers)):
            if column != base.columns["password"] and old[column] != new[column]:
                raise MergeError("Preservation check failed. No output was written.")
    stats["output_rows"] = len(output)
    return Table(base.headers[:], output, dict(base.columns)), stats, changes, reviews


def write_new_csv(path, table, sources=()):
    path = Path(path).expanduser()
    if path.resolve() in {Path(p).expanduser().resolve() for p in sources}:
        raise MergeError("Output must be a new file, separate from both original CSVs.")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        fd = os.open(str(path), flags, 0o600)
        created = True
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as output:
            os.fchmod(output.fileno(), 0o600)
            writer = csv.writer(output, lineterminator="\r\n")
            writer.writerow(table.headers)
            writer.writerows(table.rows)
            output.flush()
            os.fsync(output.fileno())
        verified = load_csv(path, "output")
        if verified.headers != table.headers or verified.rows != table.rows:
            raise MergeError("Output verification failed.")
    except FileExistsError:
        raise MergeError("The output file already exists. Choose a new filename.") from None
    except (OSError, MergeError):
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise MergeError("Could not write and verify the new CSV. Check the folder and free space.") from None
    return path.resolve()


def escaped(text):
    """Avoid terminal escape/control injection; preserve visible string representation."""
    return json.dumps(str(text), ensure_ascii=True)


def summary(stats, base_label="Base", incoming_label="Incoming"):
    fields = [
        (base_label + " rows", "base_rows"), (incoming_label + " rows", "incoming_rows"),
        (base_label + " rows matched", "matched"), ("Passwords replaced", "changed"),
        ("Already identical", "already_same"), (base_label + "-only rows retained", "base_only"),
        ("Differences reviewed", "reviewed"), (base_label + " passwords kept by choice", "base_kept"),
        ("Ambiguous rows retained", "ambiguous"), ("Empty incoming passwords skipped", "empty_skipped"),
        (incoming_label + "-only rows", "incoming_only"), (incoming_label + "-only rows added", "added"),
        ("Incoming-only additions skipped", "additions_skipped"), ("Output rows", "output_rows"),
    ]
    return ["%s: %d" % (title, stats[key]) for title, key in fields]


def change_display(stats, changes, base_label="Base", incoming_label="Incoming"):
    """Trusted color names; all credential text is escaped before rendering."""
    lines = [("MERGE STATISTICS", "cyan")]
    lines.extend((line, "cyan") for line in summary(stats, base_label, incoming_label))
    lines.append(("", "plain"))
    for number, (site, user, old_password, new_password, _) in enumerate(changes, 1):
        lines.extend([
            ("%d. Site: %s" % (number, escaped(site)), "blue"),
            ("   Username: " + escaped(user), "plain"),
            ("   Old %s password: " % base_label + escaped(old_password), "yellow"),
            ("   New %s password: " % incoming_label + escaped(new_password), "green"),
            ("", "plain"),
        ])
    return lines


@contextmanager
def terminal_session():
    """Open a cleared, non-echoing alternate terminal screen; restore it on exit."""
    if not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)):
        raise MergeError("Password display requires a direct interactive terminal without redirection or pipes.")
    try:
        import termios
        import tty
        fd = os.open("/dev/tty", os.O_RDWR)
    except (ImportError, OSError):
        raise MergeError("No controlling terminal is available for the private password display.") from None
    old_attributes = termios.tcgetattr(fd)
    def terminal_write(text):
        data = text.encode("utf-8")
        while data:
            written = os.write(fd, data)
            if written == 0:
                raise MergeError("The terminal could not display the local report.")
            data = data[written:]
    try:
        terminal_write("\x1b[?1049h")
        tty.setcbreak(fd)
        yield fd, terminal_write
    finally:
        # Screen cleanup is best effort, not a guarantee against external recording.
        try:
            terminal_write("\x1b[0m\x1b[2J\x1b[H\x1b[?1049l")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attributes)
            os.close(fd)


def colored_pages(lines):
    size = shutil.get_terminal_size((100, 30))
    width, height = max(20, size.columns - 2), max(1, size.lines - 4)
    colors = {"plain": "", "cyan": "\x1b[1;36m", "blue": "\x1b[1;34m", "yellow": "\x1b[33m", "green": "\x1b[32m"}
    wrapped = []
    for line, color in lines:
        # Wrap before adding trusted colors. Credential escapes stay literal text.
        for fragment in textwrap.wrap(line, width, replace_whitespace=False, drop_whitespace=False) or [""]:
            wrapped.append(colors.get(color, "") + fragment + "\x1b[0m")
    return [wrapped[i:i + height] for i in range(0, len(wrapped), height)] or [[]]


def read_key(fd):
    data = os.read(fd, 1)
    return data.decode("ascii", errors="ignore").lower() or ("" if not data else "\x00")


def draw_page(write, page, footer):
    write("\x1b[2J\x1b[H")
    write("\r\n".join(page) + "\r\n\r\n")
    write(footer)


def private_display(lines):
    """Render credentials only to the controlling terminal, never a report file."""
    pages = colored_pages(lines)
    with terminal_session() as (fd, write):
        for number, page in enumerate(pages, 1):
            draw_page(write, page, "\x1b[2mPage %d/%d. Enter: next/close. q: close.\x1b[0m " % (number, len(pages)))
            while True:
                key = read_key(fd)
                if key in ("q", "\x1b", ""):
                    return
                if key in ("\r", "\n", " "):
                    break


def review_choices(changes, base_label="Base", incoming_label="Incoming"):
    """One key per difference, undoable. Quit never commits a partial review."""
    decisions = [None] * len(changes)
    index, page_number = 0, 0
    with terminal_session() as (fd, write):
        while True:
            if index == len(changes):
                incoming_count = decisions.count("c")
                pages = colored_pages([
                    ("REVIEW COMPLETE", "cyan"),
                    ("Keep %s: %d" % (base_label, decisions.count("a")), "yellow"),
                    ("Use %s: %d" % (incoming_label, incoming_count), "green"),
                    ("No CSV has been written yet.", "plain"),
                ])
                draw_page(write, pages[0], "FINISH> Enter: finish and save | B: go back | Q: cancel ")
                key = read_key(fd)
                if key in ("\r", "\n"):
                    return decisions
                if key == "b" and index:
                    index -= 1
                    page_number = 0
                elif key in ("q", "\x1b", ""):
                    raise MergeError("Review cancelled. No output CSV was written.")
                continue
            site, username, base_password, incoming_password, _ = changes[index]
            previous = {"a": base_label, "c": incoming_label, None: "not chosen"}[decisions[index]]
            pages = colored_pages([
                ("DIFFERENCE %d / %d" % (index + 1, len(changes)), "cyan"),
                ("Site: " + escaped(site), "blue"),
                ("Username: " + escaped(username), "plain"),
                ("", "plain"),
                (base_label.upper() + ": " + escaped(base_password), "yellow"),
                (incoming_label.upper() + ": " + escaped(incoming_password), "green"),
                ("", "plain"),
                ("Current choice: " + previous, "plain"),
            ])
            page_number = min(page_number, len(pages) - 1)
            footer = "CHOICE> 1: keep %s | 2: use %s | B: back | Q: cancel" % (base_label, incoming_label)
            if len(pages) > 1:
                footer += " | Space/P: page %d/%d" % (page_number + 1, len(pages))
            draw_page(write, pages[page_number], footer + " ")
            key = read_key(fd)
            key = {"1": "a", "2": "c"}.get(key, key)
            if key in ("a", "c"):
                decisions[index] = key
                index += 1
                page_number = 0
            elif key == "b" and index:
                index -= 1
                page_number = 0
            elif key == " " and page_number + 1 < len(pages):
                page_number += 1
            elif key == "p" and page_number:
                page_number -= 1
            elif key in ("q", "\x1b", ""):
                raise MergeError("Review cancelled. No output CSV was written.")


def apply_choices(merged, stats, changes, decisions):
    if len(decisions) != len(changes) or any(choice not in ("a", "c") for choice in decisions):
        raise MergeError("The review is incomplete. No output CSV was written.")
    output = Table(merged.headers[:], [r[:] for r in merged.rows], dict(merged.columns))
    selected_changes = []
    for change, choice in zip(changes, decisions):
        site, username, old_password, new_password, row_index = change
        if choice == "a":
            output.rows[row_index][output.columns["password"]] = old_password
        else:
            selected_changes.append(change)
    updated_stats = stats.copy()
    updated_stats["changed"] = len(selected_changes)
    updated_stats["reviewed"] = len(changes)
    updated_stats["base_kept"] = decisions.count("a")
    return output, updated_stats, selected_changes


def choose_path(prompt, output=False):
    if sys.platform == "darwin":
        action = 'choose file name with prompt "%s" default name "Passwords-Merged.csv"' if output else 'choose file with prompt "%s"'
        script = "POSIX path of (" + action % prompt + ")"
        try:
            result = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, text=True, check=False)
        except OSError:
            raise MergeError("Cannot open the file picker. Supply --incoming, --base, and --output paths.") from None
        if result.returncode:
            raise MergeError("File selection was cancelled or unavailable.")
        return Path(result.stdout.rstrip("\r\n"))
    raw = input(prompt + " ").strip()
    direct = Path(raw).expanduser()
    if direct.exists():
        return direct
    try:
        parts = shlex.split(raw)
    except ValueError:
        raise MergeError("Invalid file path.") from None
    return Path(parts[0] if len(parts) == 1 else raw).expanduser()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Merge password CSVs locally; preserve base rows and metadata, and choose matching passwords interactively.")
    parser.add_argument("--incoming", "--chrome", dest="incoming", type=Path, help="Incoming CSV; otherwise opens a file picker on Mac")
    parser.add_argument("--base", "--apple", dest="base", type=Path, help="Base CSV whose rows and metadata are preserved")
    parser.add_argument("--base-label", default="Base", help="Display name for the base, e.g. Apple")
    parser.add_argument("--incoming-label", default="Incoming", help="Display name for the incoming CSV, e.g. Chrome")
    parser.add_argument("--match", choices=("host", "exact"), default="host", help="Match username and URL, with optional host fallback (default: host)")
    parser.add_argument("--output", type=Path, help="New merged CSV; refuses to overwrite an existing file")
    parser.add_argument("--show-passwords", action="store_true", help="Show changed site, username, old Base password and new Incoming password in a colored, cleared, terminal-only paged screen")
    parser.add_argument("--review", action="store_true", help="1 keeps base, 2 uses incoming, B goes back, Q cancels; saves only after review")
    parser.add_argument("--add-incoming-only", "--add-chrome-only", dest="add_incoming_only", action="store_true", help="Also append incoming-only logins; default preserves the base row count")
    args = parser.parse_args(argv)
    try:
        for label in (args.base_label, args.incoming_label):
            if not label or len(label) > 32 or not label.isprintable():
                raise MergeError("Display labels must contain 1-32 printable characters.")
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ImportError, ValueError, OSError):
            pass
        csv.field_size_limit(16 * 1024 * 1024)
        def interrupt(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupt)
        if (args.show_passwords or args.review) and not all(s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr)):
            raise MergeError("Password display/review requires an interactive terminal. Do not pipe or redirect this command.")
        incoming_path = args.incoming or choose_path("Choose the Incoming passwords CSV")
        base_path = args.base or choose_path("Choose the Base Passwords CSV")
        incoming_path, base_path = incoming_path.expanduser(), base_path.expanduser()
        if incoming_path.resolve() == base_path.resolve():
            raise MergeError("Incoming and Base must be two different input files.")
        incoming, base = load_csv(incoming_path, "incoming"), load_csv(base_path, "base")
        merged, stats, changes, reviews = merge_tables(base, incoming, args.add_incoming_only, args.match)
        if args.review and changes:
            print("Reviewing locally: 1 keeps %s; 2 uses %s; B goes back; Q cancels." % (args.base_label, args.incoming_label))
            decisions = review_choices(changes, args.base_label, args.incoming_label)
            merged, stats, changes = apply_choices(merged, stats, changes, decisions)
        output_path = args.output or choose_path("Save the NEW merged CSV", output=True)
        saved = write_new_csv(output_path, merged, (incoming_path, base_path))
        print("New CSV saved: " + escaped(saved))
        print("\n".join(summary(stats, args.base_label, args.incoming_label)))
        if args.show_passwords and changes and not args.review:
            print("\nShowing changes locally. Terminal recording/screen capture cannot be prevented by this script.")
            private_display(change_display(stats, changes, args.base_label, args.incoming_label))
        else:
            for site, user, _, _, _ in changes:
                print("CHANGED: Site: %s  Username: %s" % (escaped(site), escaped(user)))
        for site, user, reason in reviews:
            print("UNCHANGED: Site: %s  Username: %s  Reason: %s" % (escaped(site), escaped(user), reason))
        print("\nBoth source CSVs are unchanged. Notes, OTPAuth and all other Base fields were preserved.")
        return 0
    except KeyboardInterrupt:
        print("\nStopped. If the saved-file message appeared, the verified CSV was already created.", file=sys.stderr)
        return 130
    except MergeError as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1
    except Exception:
        # No traceback or raw exception, which could contain credential text.
        print("Error: processing failed. No credential values or traceback were printed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
