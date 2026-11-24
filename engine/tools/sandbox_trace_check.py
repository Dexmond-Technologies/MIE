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

The waiting shape (a worker that reports "stage1", prepares, and installs the filter only
when it is handed its file) is traced the same way: the calls AFTER the filter are compared
with the list as before, and the calls between the stage-1 report and the filter are printed
as a separate list, BEFORE THE SEAL: they run without the filter, on our own rule files.

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
# The waiting shape (ruling M-13): the worker reports "stage1 ..." on its status pipe, prepares
# (reads OUR rules, compiles them) and only later installs the filter. The calls between the
# two are listed apart: they run without the filter.
# The report is ONE write(2) of "stage1 <what>\n" on the status descriptor (number 4 at start;
# see status_line in sandbox_posix.cpp); a short write would repeat write() for the rest. The
# pattern also takes a descriptor decorated by strace -y ("4<pipe:[123]>") and the writev form.
# The worker makes itself not dumpable at stage 1 (by design), so strace can no longer read its
# buffers and prints the stage-1 report as write(4, 0x..., N) (run 45310215569). The last step of
# stage 1 is landlock_restrict_self; that call, which strace shows whole, marks stage 1 as well.
STAGE1_LINE = r"\bwrite\w*\(\d+(?:<[^>]*>)?,\s*(?:\[\{iov_base=)?\"stage1 "
STAGE1_LINE = r"(?:" + STAGE1_LINE + r")|landlock_restrict_self\(.*=\s*0\s*$"
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
    """Returns (used: name -> count, refused: name -> one example line, seen_start,
    before_seal: name -> count of the calls between the stage-1 report and the filter, or None
    if no stage-1 report was seen (the one-shot shape))."""
    before_seal = None
    in_stage1 = set()  # process numbers that reported stage 1 and have not yet sealed
    # Without a stage-1 report: the calls of each process from its successful execve to its
    # seal, kept as a second measure (exec_to_seal) so that the list is never simply missing.
    since_exec = {}    # pid -> name -> count, from its execve on, until it seals
    exec_to_seal = {}
    stage1 = re.compile(STAGE1_LINE)
    used = {}
    refused = {}
    counted = set()   # process / thread numbers whose calls count
    seen_start = whole
    start = re.compile(start_pattern)
    pending = {}  # pid -> the beginning of a call strace printed as "<unfinished ...>"
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            # With several processes at once strace splits a call into "name(args <unfinished ...>"
            # and later "<... name resumed>rest". Join the two halves, so that the starting line
            # (the filter's prctl ... = 0) is seen whole; the call is still counted once, at its
            # beginning (run 45216107042: in the pre-started shape the start was never seen).
            head = re.match(r"^(\d+)\s+(.*) <unfinished \.\.\.>$", line)
            if head:
                pending[head.group(1)] = head.group(2)
            tail = re.match(r"^(\d+)\s+<\.\.\. \w+ resumed>(.*)$", line)
            if tail and tail.group(1) in pending:
                joined = pending.pop(tail.group(1)) + tail.group(2)
                if start.search(joined) or stage1.search(joined):
                    line = tail.group(1) + " " + joined   # a whole call line, beginning included
            found = LINE.match(line)
            if not found:
                continue  # signals, exits
            pid = found.group("pid")
            name = found.group("name") or found.group("resumed")
            is_start = bool(start.search(line))
            if pid in in_stage1 and not is_start and found.group("name"):
                before_seal[name] = before_seal.get(name, 0) + 1
            if pid in since_exec and not is_start and found.group("name"):
                since_exec[pid][name] = since_exec[pid].get(name, 0) + 1
            if name == "execve" and re.search(r"=\s*0\s*$", line):
                since_exec[pid] = {}  # a new program in this process: count from here
            if stage1.search(line):
                in_stage1.add(pid)
                if before_seal is None:
                    before_seal = {}
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
                in_stage1.discard(pid)
                seen_start = True
                for call, number in since_exec.pop(pid, {}).items():
                    exec_to_seal[call] = exec_to_seal.get(call, 0) + number
    return used, refused, seen_start, before_seal, exec_to_seal


def whole_calls(handle):
    """Yields the trace's lines with every call strace split in two ('name(args <unfinished ...>' and
    later '<... name resumed>rest') joined into one line, placed where the call ended. Without this a
    split seal or recvmsg is not seen, and the calls after the real seal look like calls before it
    (run 45314594332)."""
    pending = {}
    for raw in handle:
        line = raw.rstrip("\n")
        head = re.match(r"^(\d+)\s+(.*) <unfinished \.\.\.>$", line)
        if head:
            pending[head.group(1)] = head.group(2)
            continue
        tail = re.match(r"^(\d+)\s+<\.\.\. \w+ resumed>(.*)$", line)
        if tail and tail.group(1) in pending:
            yield tail.group(1) + " " + pending.pop(tail.group(1)) + tail.group(2)
            continue
        yield line


def descriptor_check(path, start_pattern):
    """Reviewer's condition on the pre-started shape (M-13 condition 1, ruling on run 45310215569):
    per worker, between the recvmsg that brings the file and the seal, nothing may read, pread,
    readv or mmap the handed-over descriptor; and every read before the seal must be on standard
    input or the channel. The received descriptor is the one the worker asks fcntl(N, F_GETFL)
    about after recvmsg (strace cannot show recvmsg's control message: the worker is not dumpable).
    Returns (lines to print, failed)."""
    call = re.compile(r"^(\d+)\s+(read|pread64|readv|preadv|preadv2|mmap|fcntl|recvmsg)\((.*)$")
    start = re.compile(start_pattern)
    state = {}   # pid -> {'stage': 'start'|'after_recv'|'sealed', 'fd': None, 'reads_before': {fd: n}, 'touch': []}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in whole_calls(handle):
            pid_match = re.match(r"^(\d+)\s", line)
            if not pid_match:
                continue
            pid = pid_match.group(1)
            if re.search(STAGE1_LINE, line):
                state[pid] = {"stage": "start", "fd": None, "reads_before": {}, "touch": [], "recv": 0}
                continue
            s = state.get(pid)
            if s is None or s["stage"] == "sealed":
                continue
            if start.search(line):
                s["stage"] = "sealed"
                continue
            m = call.match(line)
            if not m:
                continue
            name, args = m.group(2), m.group(3)
            first = re.match(r"\s*(-?\d+)", args)
            fd = int(first.group(1)) if first else None
            if name == "recvmsg":
                result = re.search(r"=\s*(-?\d+)\s*$", args)
                if result and int(result.group(1)) > 0:
                    s["recv"] += 1
                    s["stage"] = "after_recv"
                else:
                    s["empty_recv"] = s.get("empty_recv", 0) + 1   # end of the channel: no file came
                continue
            if name == "fcntl" and s["stage"] == "after_recv" and "F_GETFL" in args and s["fd"] is None:
                s["fd"] = fd
                continue
            if name == "mmap":
                parts = [x.strip() for x in args.split(",")]
                fd = int(parts[4]) if len(parts) > 4 and re.fullmatch(r"-?\d+", parts[4]) else None
            if name in ("read", "pread64", "readv", "preadv", "preadv2"):
                s["reads_before"][fd] = s["reads_before"].get(fd, 0) + 1
            if s["stage"] == "after_recv" and fd is not None:
                s["touch"].append((name, fd))
    lines, failed = [], False
    workers = {pid: s for pid, s in state.items() if s["recv"]}
    without = sorted(pid for pid, s in state.items() if not s["recv"] and s.get("empty_recv"))
    if not workers:
        return ["HANDED-OVER DESCRIPTOR CHECK: no worker received a file by recvmsg in this trace (one-shot shape)"], False
    fds = sorted({s["fd"] for s in workers.values() if s["fd"] is not None})
    reads = {}
    bad = []
    for pid, s in workers.items():
        for fd, n in s["reads_before"].items():
            reads[fd] = reads.get(fd, 0) + n
        if s["fd"] is None:
            bad.append("%s: the received descriptor was never named by fcntl(F_GETFL)" % pid)
            continue
        for name, fd in s["touch"]:
            if fd == s["fd"] and name in ("read", "pread64", "readv", "preadv", "preadv2", "mmap"):
                bad.append("%s: %s on the received descriptor %d before the seal" % (pid, name, fd))
    allowed_read_fds = {0, 3}   # standard input (the preparation) and the channel (descriptor 3)
    other = {fd: n for fd, n in reads.items() if fd not in allowed_read_fds}
    lines.append("HANDED-OVER DESCRIPTOR CHECK: %d workers received a file; received descriptor number(s): %s; "
                 "%d workers reached the end of the channel without a file (process ids %s)"
                 % (len(workers), fds, len(without), ", ".join(without[:10])))
    mapped = sum(1 for s in workers.values() for name, fd in s["touch"] if name == "mmap" and fd == s["fd"])
    lines.append("HANDED-OVER DESCRIPTOR CHECK: mmap calls naming the received descriptor between recvmsg and the "
                 "seal: %d (mmap's fifth argument is read)" % mapped)
    lines.append("HANDED-OVER DESCRIPTOR CHECK: reads before the seal by descriptor: %s (allowed: 0 standard input, "
                 "3 the channel)" % dict(sorted((str(k), v) for k, v in reads.items())))
    for fd, n in sorted(other.items(), key=lambda x: str(x[0])):
        bad.append("a read before the seal on descriptor %s (%d times), neither standard input nor the channel" % (fd, n))
    for item in bad[:20]:
        lines.append("HANDED-OVER DESCRIPTOR CHECK: FAIL  " + item)
    failed = bool(bad)
    lines.append("HANDED-OVER DESCRIPTOR CHECK: %s" % ("FAIL" if failed else
                 "PASS (no read, pread, readv or mmap of the received descriptor between recvmsg and the seal; "
                 "reads before the seal only on standard input and the channel)"))
    return lines, failed


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
        used, refused, seen_start, before_seal, exec_to_seal = read_trace(trace_path, arguments.after,
                                                                          arguments.whole)
        check_lines, check_failed = descriptor_check(trace_path, arguments.after)
    finally:
        if folder is not None:
            shutil.rmtree(folder, ignore_errors=True)
    if not seen_start:
        print("NOT RUN  the starting line was never seen in the trace (pattern %r): the program did not "
              "install the filter, or strace could not follow it" % arguments.after)
        return 2

    if before_seal is None:
        print("BEFORE THE SEAL       (no stage-1 report in this trace: the one-shot shape, where the filter is "
              "installed before the worker reads anything, or the report was not recognised; pattern %r)"
              % STAGE1_LINE)
        if exec_to_seal:
            print("FROM EXEC TO THE SEAL (not filtered; the whole start of each sealed process, stage 1 and its "
                  "preparation included): %d different calls" % len(exec_to_seal))
            for name in sorted(exec_to_seal):
                print("FROM EXEC TO THE SEAL %-20s used %d times%s" % (
                    name, exec_to_seal[name], "" if name in allowed else "   (not on the allow list)"))
    else:
        print("BEFORE THE SEAL (not filtered; our own rule files and table only): %d different calls between "
              "the stage-1 report and the filter" % len(before_seal))
        for name in sorted(before_seal):
            print("BEFORE THE SEAL       %-20s used %d times%s" % (
                name, before_seal[name], "" if name in allowed else "   (not on the allow list)"))
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
    for text in check_lines:
        print(text)
    failed = failed or check_failed
    print("sandbox_trace_check: %d calls used after the starting point; the list has %d (TRACED %d, MARGIN %d): %s"
          % (len(used), len(allowed), traced, margin, "FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
