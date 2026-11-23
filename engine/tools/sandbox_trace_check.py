#!/usr/bin/env python3
"""Compares the system calls a program really makes once it is confined with the allow list
of the Linux system-call filter (r-01's ruling B-3627: the list must come from a trace of the
real worker, not from memory).

Usage:
  sandbox_trace_check.py --source engine/src/sandbox/sandbox_posix.cpp [--keep TRACE_FILE]
                         [--after REGEX | --whole] -- COMMAND [ARGUMENTS...]

It runs COMMAND under `strace -f` (the command may start the worker as a child: forks are
followed) and reads the trace.

Which calls count: by default the calls a process makes AFTER it installed the filter, that
is after its line `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...) = 0`, and the calls of the
threads it starts afterwards. The program runs CONFINED: a call that is not on the list shows
in the trace as refused (EPERM), and the program may then have taken another way than it
would with the call allowed. So: add the call (with its line in SANDBOX_NOTES.md), run again,
until nothing is refused. `--after REGEX` takes another line as the starting point (for a
program run without the filter that marks the point some other way); `--whole` counts every
call of every process.

Result, one line each:
  USED AND ALLOWED      the call is on the list, tagged TRACED
  USED, TAGGED MARGIN   the call is on the list as a margin call and was now seen: retag it TRACED
  USED, NOT ON THE LIST the call was made after the starting point and is not on the list  -> FAIL
  REFUSED BY ARGUMENT   the call is on the list but this use was refused (EPERM)           -> FAIL
  WARNING               tagged TRACED but not seen in this trace (not a failure: a file set
                        may not exercise it)
  MARGIN, NOT USED      a margin call, with the one reason written in the source
  ALLOWED WITHOUT A TAG / MARGIN WITHOUT A REASON   the source line lacks its tag             -> FAIL
Exit code 0: every call used is allowed. 1: a FAIL line. 2: the check could not be run
(strace missing, starting point never seen, list not readable); never counted as passed.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

SECCOMP_LINE = r"prctl\(PR_SET_SECCOMP, SECCOMP_MODE_FILTER.*=\s*0\s*$"
# Calls the filter answers on purpose without allowing them; seeing them refused is expected.
ANSWERED_ON_PURPOSE = {
    "newfstatat": "refused on purpose: it takes a path. Newer C libraries ask the kind of an open stream "
                  "this way; the stream works without the answer. If the worker itself needs it, that is "
                  "a finding, not something to allow",
}
# The calls of ending and of the kernel itself that a trace shows after the starting point even
# for an empty program are on the list like any other; nothing is exempt here.


ALLOW_LINE = re.compile(r"filter\.allow\w*\(\s*SYS_(\w+)\b")
TAG = re.compile(r"\b(TRACED|MARGIN|SANITIZER)\b(?:\(\s*\"((?:[^\"\\\\]|\\\\.)*)\"\s*\))?\s*\)\s*;")


def allow_list(source_path):
    """The calls of the SHIPPED filter: name -> (tag, reason). The tag is TRACED (seen in a
    trace of the real worker), MARGIN (never seen; the reason is the text in the source) or
    None when the line carries no tag, which is an error. The lines inside
    `#if MIE_SANITIZER_BUILD` (up to its #else / #endif) are the sanitizer build's and are
    left out."""
    calls = {}
    skipping_depth = None  # nesting depth at which a sanitizer-only part began
    depth = 0
    with open(source_path, encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped.startswith("#if"):
                depth += 1
                if skipping_depth is None and re.match(r"#if\s+MIE_SANITIZER_BUILD\b", stripped):
                    skipping_depth = depth
                continue
            if stripped.startswith("#else") or stripped.startswith("#elif"):
                if skipping_depth == depth:
                    skipping_depth = None
                continue
            if stripped.startswith("#endif"):
                if skipping_depth == depth:
                    skipping_depth = None
                depth -= 1
                continue
            if skipping_depth is not None:
                continue
            found = ALLOW_LINE.search(line)
            if found:
                tag = TAG.search(line)
                calls[found.group(1)] = (tag.group(1), tag.group(2) or "") if tag else (None, "")
    return calls


LINE = re.compile(r"^(?P<pid>\d+)\s+(?:<\.\.\. (?P<resumed>\w+) resumed>|(?P<name>\w+)\()(?P<rest>.*)$")


def read_trace(path, start_pattern, whole):
    """Returns (used: name -> count, refused: name -> one example line, seen_start)."""
    used = {}
    refused = {}
    counted = set()   # process / thread numbers whose calls count
    seen_start = whole
    start = re.compile(start_pattern)
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            found = LINE.match(line)
            if not found:
                continue  # signals, exits
            pid = found.group("pid")
            name = found.group("name") or found.group("resumed")
            is_start = bool(start.search(line))
            if whole or pid in counted:
                if found.group("name") and not is_start:
                    used[name] = used.get(name, 0) + 1   # counted once, where the call begins
                if re.search(r"=\s*-1\s+EPERM\b", line):
                    refused.setdefault(name, line[:200])
                # a thread or process started by a counted one counts too
                made = re.search(r"=\s*(\d+)\s*$", line)
                if name in ("clone", "clone3", "fork", "vfork") and made:
                    counted.add(made.group(1))
            if is_start:
                counted.add(pid)
                seen_start = True
    return used, refused, seen_start


def main():
    parser = argparse.ArgumentParser(description="trace a command and compare with the sandbox allow list")
    parser.add_argument("--source", required=True, help="path of sandbox_posix.cpp")
    parser.add_argument("--keep", help="write the strace output here and keep it")
    parser.add_argument("--after", default=SECCOMP_LINE, help="regular expression of the starting line")
    parser.add_argument("--whole", action="store_true", help="count every call of every process")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command[1:] if arguments.command[:1] == ["--"] else arguments.command
    if not command:
        parser.error("no command given")

    try:
        allowed = allow_list(arguments.source)
    except OSError as error:
        print("NOT RUN  the allow list could not be read: %s" % error)
        return 2
    if not allowed:
        print("NOT RUN  no filter.allow*(SYS_...) line found in %s" % arguments.source)
        return 2
    strace = shutil.which("strace")
    if strace is None:
        print("NOT RUN  strace is not installed (CI: sudo apt-get install -y strace)")
        return 2

    folder = None
    trace_path = arguments.keep
    if trace_path is None:
        folder = tempfile.mkdtemp(prefix="mie-trace-")
        trace_path = os.path.join(folder, "trace.txt")
    try:
        done = subprocess.run([strace, "-f", "-qq", "-o", trace_path, "--"] + command)
        print("command exit code: %d" % done.returncode)
        used, refused, seen_start = read_trace(trace_path, arguments.after, arguments.whole)
    finally:
        if folder is not None:
            shutil.rmtree(folder, ignore_errors=True)
    if not seen_start:
        print("NOT RUN  the starting line was never seen in the trace (pattern %r): the program did not "
              "install the filter, or strace could not follow it" % arguments.after)
        return 2

    failed = False
    for name in sorted(allowed):
        tag, reason = allowed[name]
        if tag is None:
            failed = True
            print("ALLOWED WITHOUT A TAG %-20s the source line has neither TRACED nor MARGIN(\"reason\")" % name)
        elif tag == "SANITIZER":
            failed = True
            print("SANITIZER CALL IN THE SHIPPED LIST %-20s" % name)
        elif tag == "MARGIN" and not reason.strip():
            failed = True
            print("MARGIN WITHOUT A REASON %-20s" % name)
    for name in sorted(used):
        if name in allowed:
            tag = allowed[name][0]
            if name in refused:
                failed = True
                print("REFUSED BY ARGUMENT   %-20s used %d times; example: %s" % (name, used[name], refused[name]))
            elif tag == "MARGIN":
                print("USED, TAGGED MARGIN   %-20s used %d times: now seen in a trace, retag it TRACED" % (
                    name, used[name]))
            else:
                print("USED AND ALLOWED      %-20s used %d times" % (name, used[name]))
        elif name in ANSWERED_ON_PURPOSE:
            print("ANSWERED ON PURPOSE   %-20s used %d times; %s" % (name, used[name], ANSWERED_ON_PURPOSE[name]))
        else:
            failed = True
            print("USED, NOT ON THE LIST %-20s used %d times%s" % (
                name, used[name], "; example: " + refused[name] if name in refused else ""))
    for name in sorted(allowed):
        tag, reason = allowed[name]
        if name in used:
            continue
        if tag == "TRACED":
            print("WARNING               %-20s tagged TRACED but not seen in THIS trace (this command or "
                  "file set may not exercise it)" % name)
        elif tag == "MARGIN":
            print("MARGIN, NOT USED      %-20s reason: %s" % (name, reason))
    traced = sum(1 for tag, _ in allowed.values() if tag == "TRACED")
    margin = sum(1 for tag, _ in allowed.values() if tag == "MARGIN")
    print("sandbox_trace_check: %d calls used after the starting point; the list has %d (TRACED %d, MARGIN %d): %s"
          % (len(used), len(allowed), traced, margin, "FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
