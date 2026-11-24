#!/usr/bin/env python3
"""Worker confinement: what a confined child can and cannot do (conditions M-2, M-9; r-01's
ruling B-3627: five things shown from inside the confined worker on each system).

Usage: sandbox_cases.py <mie-sandbox-testparent> <mie-sandbox-testchild> <mie-sandbox-shippedchild>

The first two programs are built with the test build of the sandbox library (test switches
compiled in). The third is the same test child built with the SHIPPED library, in which the
test switches do not exist (reviewer's finding SB-1).

Every case starts the test child through mie::sandbox::run_confined (by way of the test
parent) and looks at the ChildResult. One line per case: PASS, FAIL or NOT RUN with the
reason; a PASS line says what was tried. NOT RUN is never counted as passed, and the run
FAILS if a required case is NOT RUN.

The first two cases only START a child (10 s limit). If the confined child cannot start,
the test prints what the parent saw and STOPS: no other case could pass, and each would
only wait for its time limit.
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile

GIB = 1024 * 1024 * 1024
WALL = "20"  # seconds, the limit of every case that does not set its own

P1 = "r-01 point 1: a network connection from the confined child fails"
P1B = "r-01 point 1 (not the local loop): a connection to the machine's own network address fails"
SW1 = "SW-1: what a confined worker can write in its own folder, nothing outside it, and the folder goes with it"
CROSS = "M-13 one profile per worker: a file left by one worker is not seen by another worker pre-started before it"
SWEEP = "M-13 clean-up after a crash: profiles left by a hard-killed parent are removed by the next start's sweep"
WINDOWS_MUST_RUN = []  # filled on Windows: the cases above must run there
PROFILE_COST = {"create": [], "delete": []}  # milliseconds per start / per end (Windows)
TIMELINE = {"process_ended_ms": [], "output_drained_ms": [], "job_closed_ms": [], "returned_ms": []}
SHIPPED = "SB-1: a child built with the shipped library ignores the test switches in its environment"
P2 = "r-01 point 2: reading a file in the user's profile that was not handed over fails"
P3 = "r-01 point 3: starting another process from the confined child fails"
P4 = "r-01 point 4: writing a file outside what was handed over fails"
P5A = "r-01 point 5: the handed-over file is readable through its handle (hash equals the file's)"
P5B = "r-01 point 5: the handed-over file is read-only (writing through the handle fails)"
P5C = "r-01 point 5: the handed-over file is the only thing inherited besides the three standard streams"
MEMORY = "memory: the limit ends the child, the parent carries on"
# The waiting shape (ruling M-13): the same things shown with a worker that is started first
# and handed its file while it runs.
W = "M-13 (waiting worker) "
W_START = W + "start: the worker reports stage 1, reads its preparation, waits, is handed a file, answers"
W_P1 = W + "r-01 point 1: a network connection fails"
W_P1B = W + "r-01 point 1 (not the local loop): a connection to the machine's own network address fails"
W_P2 = W + "r-01 point 2: reading a file in the user's profile that was not handed over fails"
W_P3 = W + "r-01 point 3: starting another process fails"
W_P4 = W + "r-01 point 4: writing a file outside what was handed over fails"
W_P5A = W + "r-01 point 5: the handed-over file is readable through its handle (hash equals the file's)"
W_P5B = W + "r-01 point 5: the handed-over file is read-only"
W_P5C = W + "r-01 point 5: before the hand-over only the standard streams (and the channel); after it " \
    "exactly one more handle; enumerated before the first read"
W_ONE = W + "one file per worker: a second hand-over is refused and nothing more is served"
W_SHIPPED = W + "SB-1: a worker built with the shipped library ignores the test switches"
MUST_RUN = (P1, P1B, P2, P3, P4, P5A, P5B, P5C, MEMORY, SHIPPED,
            W_START, W_P1, W_P1B, W_P2, W_P3, W_P4, W_P5A, W_P5B, W_P5C, W_ONE, W_SHIPPED)
SANITIZER = {"seen": False}  # set when the test parent says it is a sanitizer build

results = []  # (status, name, text)


def record(status, name, text=""):
    results.append((status, name, text))
    print(("%-7s %s" % (status, name)) + (": " + text if text else ""), flush=True)


def run_parent(parent, child, options, action, wall=WALL):
    """Returns (ChildResult as dict, the child's own JSON line as dict or None)."""
    command = [parent, child, "--wall", wall] + options + ["--"] + action
    done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=int(wall) + 40)
    lines = [line for line in done.stdout.split(b"\n") if line.strip()]
    if not lines:
        return {"end": "no_output", "detail": "the test parent printed nothing; its exit code %d, its standard "
                "error: %s" % (done.returncode, done.stderr.decode("ascii", "replace")[:500]),
                "confinement": "", "output": ""}, None
    result = json.loads(lines[-1].decode("ascii"))
    if result.get("sanitizer_build"):
        SANITIZER["seen"] = True
    note_profile_cost(result)
    inner = None
    for line in result.get("output", "").split("\n"):
        if line.strip().startswith("{"):
            try:
                inner = json.loads(line)
            except ValueError:
                inner = None
    return result, inner


def note_profile_cost(result, retired=None):
    """Windows: the time the worker's own profile took to create and (in retire(), after the
    result) to delete; and, for a waiting worker, the moments of collect() after the hand-over."""
    retired = retired or result.get("retired") or {}
    if result.get("profile_create_ms", 0) > 0:
        PROFILE_COST["create"].append(result["profile_create_ms"])
    deleted = retired.get("total_ms", -1) if retired else result.get("profile_delete_ms", 0)
    if deleted and deleted > 0:
        PROFILE_COST["delete"].append(deleted)
    for key, value in (result.get("timeline") or {}).items():
        if key in TIMELINE and value is not None and value >= 0:
            TIMELINE[key].append(value)


def brief(result, inner):
    cost = ""
    retired = result.get("retired") or {}
    if result.get("profile_create_ms", 0) > 0:
        cost = " profile: create %.1f ms, delete %.1f ms (emptied %.1f, DeleteAppContainerProfile %.1f), %s;" % (
            result.get("profile_create_ms", 0), retired.get("total_ms", result.get("profile_delete_ms", 0)),
            retired.get("emptied_ms", -1), retired.get("deleted_ms", -1),
            retired.get("text", result.get("profile_removal", "")))
    timeline = result.get("timeline") or {}
    if timeline.get("returned_ms", -1) >= 0:
        cost += " collect after the hand-over: ended %.1f, drained %.1f, job closed %.1f, returned %.1f ms;" % (
            timeline.get("process_ended_ms", -1), timeline.get("output_drained_ms", -1),
            timeline.get("job_closed_ms", -1), timeline.get("returned_ms", -1))
    return "end=%s exit=%s inner=%s detail=%r applied=%r%s" % (
        result.get("end"), result.get("exit_code"), json.dumps(inner, sort_keys=True),
        result.get("detail", "")[:700], result.get("confinement", ""), cost)


def case(name, function):
    try:
        status, text = function()
    except subprocess.TimeoutExpired:
        status, text = "FAIL", "the test parent itself did not end in time (the parent must never hang)"
    except Exception as error:  # a broken test is a failure, not a pass
        status, text = "FAIL", "test error: %r" % (error,)
    record(status, name, text)
    return status


def summary():
    passed = sum(1 for status, _, _ in results if status == "PASS")
    failed = sum(1 for status, _, _ in results if status == "FAIL")
    not_run = sum(1 for status, _, _ in results if status == "NOT RUN")
    for kind in ("create", "delete"):
        figures = sorted(PROFILE_COST[kind])
        if figures:
            print("profile cost (%s, ms, per worker): %d measured, median %.1f, 90th %.1f, max %.1f" % (
                kind, len(figures), figures[len(figures) // 2], figures[min(len(figures) - 1, len(figures) * 9 // 10)],
                figures[-1]))
    for key in ("process_ended_ms", "output_drained_ms", "job_closed_ms", "returned_ms"):
        figures = sorted(TIMELINE[key])
        if figures:
            print("collect() after the hand-over, %s: %d measured, median %.1f, max %.1f" % (
                key, len(figures), figures[len(figures) // 2], figures[-1]))
    blocking = [name for name in MUST_RUN + tuple(WINDOWS_MUST_RUN)
                if not any(status in ("PASS", "FAIL") and case_name == name for status, case_name, _ in results)]
    print("sandbox_cases: %d passed, %d failed, %d not run%s" % (
        passed, failed, not_run,
        " [SANITIZER BUILD: the system-call filter here is the WIDER sanitizer list; these results "
        "are NOT evidence for the shipped filter]" if SANITIZER["seen"] else ""))
    for name in blocking:
        print("FAIL    required case was not run: %s" % name)
    return 1 if failed or blocking else 0


def windows_setup(parent, child):
    """Inside an AppContainer a program and the libraries beside it can only be loaded from a
    folder the container may read. The test grants read-and-execute on the folder of the two
    test programs to the worker's AppContainer SID and to ALL APPLICATION PACKAGES
    (S-1-15-2-1). The installer has to grant the same on the real worker's folder."""
    done = subprocess.run([parent, "--sid"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    try:
        sid = json.loads(done.stdout.split(b"\n")[0].decode("ascii")).get("sid", "")
    except ValueError:
        sid = ""
    print("setup: AppContainer SID %r (raw answer %r)" % (sid, done.stdout[:300]), flush=True)
    folders = sorted({os.path.dirname(os.path.abspath(parent)), os.path.dirname(os.path.abspath(child))})
    for folder in folders:
        for who in [sid, "S-1-15-2-1"]:
            if not who:
                continue
            granted = subprocess.run(["icacls", folder, "/grant", "*%s:(OI)(CI)(RX)" % who],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            print("setup: icacls %s grant %s read+execute: exit %d, %s" % (
                folder, who, granted.returncode, granted.stdout.decode("ascii", "replace").strip()[-200:]),
                flush=True)
    listed = subprocess.run(["icacls", os.path.abspath(child)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=60)
    print("setup: access list of the test child now:\n%s" % listed.stdout.decode("ascii", "replace"), flush=True)


def main():
    if len(sys.argv) < 3:
        print("usage: sandbox_cases.py <mie-sandbox-testparent> <mie-sandbox-testchild> "
              "<mie-sandbox-shippedchild>")
        return 2
    parent, child = sys.argv[1], sys.argv[2]
    shipped_child = sys.argv[3] if len(sys.argv) > 3 else None
    windows = os.name == "nt"
    linux = sys.platform.startswith("linux")

    # The test files live in the user's REAL profile / home folder (r-01 point 2).
    home = os.path.expanduser("~")
    work = tempfile.mkdtemp(prefix="mie-sandbox-test-", dir=home)
    try:
        return run_cases(parent, child, shipped_child, windows, linux, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def own_network_address():
    """A non-loopback IPv4 address of this machine, found WITHOUT sending anything: connecting
    a UDP socket only chooses the local address for a route (no packet leaves), and the host
    name is resolved by the machine itself. Returns (address or None, how)."""
    tried = []
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 9))  # documentation-only address; UDP connect sends nothing
            address = probe.getsockname()[0]
        finally:
            probe.close()
        if address and not address.startswith("127.") and address != "0.0.0.0":
            return address, "local address the system would use for a route (UDP connect, nothing sent)"
        tried.append("route lookup gave %s" % address)
    except OSError as error:
        tried.append("route lookup failed: %s" % error)
    try:
        for address in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not address.startswith("127."):
                return address, "address of the machine's own host name"
        tried.append("the host name has only loopback addresses")
    except OSError as error:
        tried.append("host name lookup failed: %s" % error)
    return None, "; ".join(tried)


def run_cases(parent, child, shipped_child, windows, linux, work):
    sample = os.path.join(work, "handed-over.bin")
    with open(sample, "wb") as handle:
        handle.write(b"MIE sandbox test file\n" * 1000)
    with open(sample, "rb") as handle:
        sample_hash = hashlib.sha256(handle.read()).hexdigest()
    private = os.path.join(work, "not-handed-over.txt")
    with open(private, "wb") as handle:
        handle.write(b"a file in the user's profile that the worker was not given\n")
    target = os.path.join(work, "written-by-child.txt")
    print("setup: test folder %s" % work, flush=True)

    if windows:
        windows_setup(parent, child)

    # ---- start: can a child be started at all? ------------------------------------------------
    def start(options):
        def run():
            result, inner = run_parent(parent, child, options, ["whoami"], wall="10")
            good = result.get("end") == "exited" and result.get("exit_code") == 0 and inner is not None
            return ("PASS" if good else "FAIL"), "started the child with action whoami, 10 s limit; " \
                + brief(result, inner)
        return run

    case("start: a child WITHOUT confinement starts and answers (control)", start(["--unconfined"]))
    if case("start: a CONFINED child starts and answers", start([])) != "PASS":
        print("DIAGNOSIS: the confined child did not start. Read the FAIL line above: 'detail' holds the "
              "parent's diagnosis (ResumeThread, exit code in hex, bytes received) and the child's first "
              "line 'main reached' if main() was reached.", flush=True)
        if windows:
            case("start (diagnosis only): in the container WITHOUT the mitigation and child-process policies",
                 start(["--no-mitigations"]))
            print("DIAGNOSIS: if the line above is PASS, a policy keeps the child from starting; if it "
                  "fails the same way, the AppContainer itself (access to the program folder, the "
                  "environment, the pipes) does.", flush=True)
        print("STOPPED: no further case is run; each would only wait for its time limit.", flush=True)
        return summary() or 1

    # ---- generic: an action that works without confinement and is refused with it -------------
    def refused(tried, action, key, control_needed=True, options=None, error_number=None, no_control_why=""):
        """error_number: the error the confined child must report (1 = EPERM, the Linux filter's
        answer)."""
        options = options or []

        def run():
            text = "tried: " + tried + "; "
            if control_needed:
                control, control_inner = run_parent(parent, child, ["--unconfined"] + options, action)
                if control_inner is None or control_inner.get(key) is not True:
                    return "FAIL", text + "the control run (no confinement) did not succeed, so a refusal " \
                        "proves nothing: " + brief(control, control_inner)
                text += "control run without confinement succeeded; "
            else:
                text += "no control run (" + no_control_why + "); "
            result, inner = run_parent(parent, child, options, action)
            good = result.get("end") == "exited" and inner is not None and inner.get("confined") is True \
                and inner.get(key) is False
            if good and error_number is not None:
                good = inner.get("error") == error_number
            return ("PASS" if good else "FAIL"), text + "confined: " + brief(result, inner)
        return run

    # ---- r-01 point 1: network ------------------------------------------------------------------
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = str(listener.getsockname()[1])
    # The child waits at most 5 s for the connection (a confined Windows child gets no answer
    # at all). The control run has the same 5 s and must connect within them: only then does
    # "timed out" in the confined run count as "the connection fails".
    case(P1, refused("TCP connection to a listener of this test on 127.0.0.1:" + port + ", waiting at most 5 s; "
                     "a time-out counts as failed only because the control run (same listener, same 5 s) "
                     "connected; see 'how' in the child's answer",
                     ["connect", "127.0.0.1", port], "connected"))
    listener.close()
    # r-01's ruling 2a: 127.0.0.1 shows only that the local loop is closed. The same attempt
    # against a listener of this test on the machine's own NETWORK address. Nothing outside
    # the machine is contacted.
    address, how_found = own_network_address()
    if address is None:
        record("NOT RUN", P1B, "this machine has no IPv4 address other than the local loop (%s)" % how_found)
    else:
        try:
            outside = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            outside.bind((address, 0))
            outside.listen(8)
        except OSError as error:
            record("FAIL", P1B, "could not listen on the machine's own address %s (%s): %s" % (
                address, how_found, error))
        else:
            outside_port = str(outside.getsockname()[1])
            case(P1B, refused("TCP connection to a listener of this test on %s:%s (%s), waiting at most 5 s; a "
                              "time-out counts as failed only because the control run connected. Whether "
                              "Windows treats the machine's own address as 'local loop' for a container is "
                              "not shown by this case" % (address, outside_port, how_found),
                              ["connect", address, outside_port], "connected"))
            outside.close()
    if windows:
        def no_capability():
            result, inner = run_parent(parent, child, [], ["whoami"])
            text_self = (inner or {}).get("self", "")
            return ("PASS" if "capabilities=0" in text_self else "FAIL"), \
                "tried: read the capability list of the child's own token; the network capabilities " \
                "(internetClient and the like) are what would open the network, and there must be none; " \
                + brief(result, inner)
        case("r-01 point 1 (capabilities): the confined child's token holds no capability (Windows)",
             no_capability)
    else:
        record("NOT RUN", "r-01 point 1 (capabilities): the confined child's token holds no capability (Windows)",
               "Windows only: capabilities are a Windows AppContainer notion")
    if linux:
        case("network: creating a socket fails when confined (Linux)",
             refused("socket(AF_INET, SOCK_STREAM)", ["socket"], "socket_created", error_number=1))
    else:
        record("NOT RUN", "network: creating a socket fails when confined (Linux)",
               "Linux only: on Windows a socket can be created, the connection is what is refused")

    # ---- r-01 point 2: a file of the user that was not handed over -------------------------------
    case(P2, refused("open and read %s by its path" % private, ["open-path", private], "opened"))
    case("path: opening the HANDED-OVER file by its path fails as well",
         refused("open %s by its path" % sample, ["open-path", sample], "opened"))

    # ---- r-01 point 3: another process ----------------------------------------------------------
    if linux:
        case(P3, refused("fork(), and execve(/bin/true) when fork is refused", ["spawn"], "spawned"))
    else:
        case(P3, refused("CreateProcessW(cmd.exe /c exit 0)", ["spawn"], "spawned", control_needed=False,
                         no_control_why="the one-process limit of the job applies to an unconfined test "
                         "child too, so it cannot start a process either"))

    # ---- r-01 point 4: writing ------------------------------------------------------------------
    case(P4, refused("create and write %s" % target, ["write-path", target], "opened"))

    # ---- r-01 point 5: the handed-over file ------------------------------------------------------
    def read_handle():
        result, inner = run_parent(parent, child, ["--file", sample], ["read-handle"])
        good = result.get("end") == "exited" and inner is not None and inner.get("confined") is True \
            and inner.get("read") is True and inner.get("sha256") == sample_hash
        return ("PASS" if good else "FAIL"), "tried: read the whole file through the inherited handle and " \
            "hash it; expected sha256 %s; %s" % (sample_hash, brief(result, inner))
    case(P5A, read_handle)

    def write_handle():
        result, inner = run_parent(parent, child, ["--file", sample], ["write-handle"])
        good = result.get("end") == "exited" and inner is not None and inner.get("confined") is True \
            and inner.get("handle_present") is True and inner.get("wrote") is False
        if good and linux:
            # 9 = "bad file descriptor": the descriptor itself refuses (opened read-only); the
            # call write is on the filter's allow list, so this is not the filter's refusal.
            good = inner.get("error") == 9
        with open(sample, "rb") as handle:
            unchanged = hashlib.sha256(handle.read()).hexdigest() == sample_hash
        return ("PASS" if good and unchanged else "FAIL"), "tried: write one byte through the inherited " \
            "handle (no control run: the handle is read-only with or without confinement); file " \
            "unchanged=%s; %s" % (unchanged, brief(result, inner))
    case(P5B, write_handle)

    def only_handle():
        result, inner = run_parent(parent, child, ["--file", sample], ["handles"])
        inner = inner or {}
        if linux:
            good = inner.get("open_descriptors") == [0, 1, 2, inner.get("file_descriptor")]
            tried = "asked every descriptor number below %s whether it is open (system call fstat); " \
                "expected exactly 0, 1, 2 and the file (read-only is shown by the case before). NOT " \
                "SHOWN: numbers at or above that bound, the kernel's default ceiling" % inner.get("scanned")
        elif windows:
            if not inner:
                return "FAIL", "the child gave no answer; " + brief(result, None)
            expected = sorted(set(inner.get("standard_handles", [])) | {inner.get("file_handle")})
            listed = inner.get("inheritable_handles")
            if listed is None:
                return "FAIL", "the child could not read the system's list of its handles (%s), so the point " \
                    "is not shown; %s" % (inner.get("method"), brief(result, inner))
            good = len(expected) == 4 and sorted(listed) == expected \
                and inner.get("file_handle_can_write") is False
            tried = "read the system's own list of this process's handles (%s): %s handles in all, of which " \
                "those marked inheritable (a handle that came from the parent keeps that mark) must be exactly " \
                "the three standard handles and the file, and the file's granted access (0x%x) must hold no " \
                "write right. NOT SHOWN: the other handles are the ones Windows opens in every process or " \
                "the program opened itself; they are counted, not examined one by one" % (
                    inner.get("method"), inner.get("total_handles"), inner.get("file_granted_access") or 0)
        else:
            return "NOT RUN", "no confinement is written for this system"
        good = good and result.get("end") == "exited" and inner.get("confined") is True
        return ("PASS" if good else "FAIL"), "tried: " + tried + "; " + brief(result, inner)
    case(P5C, only_handle)
    if windows:
        # r-01's ruling 2b: the other handles, by type, and the names of files and keys.
        result, inner = run_parent(parent, child, ["--file", sample], ["handles"])
        inner = inner or {}
        types = inner.get("handle_types")
        if types is None:
            print("handles: the child gave no table of handle types (%s)" % brief(result, inner), flush=True)
        else:
            print("handles: %s in all; types not given by the system for %s of them; file names not asked "
                  "for %s (pipes, consoles, devices, sockets)" % (
                      inner.get("total_handles"), inner.get("types_refused"),
                      inner.get("file_names_not_asked")), flush=True)
            for name in sorted(types):
                print("handles:   %-40s %d" % (name, types[name]), flush=True)
            for entry in inner.get("file_and_key_handles", []):
                print("handles:   %s" % entry, flush=True)

    linux_only = (
        ("handle: fchmod on the handed-over descriptor is refused by the filter (Linux)",
         refused("fchmod(descriptor, 0600)", ["fchmod-handle"], "changed", options=["--file", sample],
                 error_number=1)),
        ("handle: ftruncate on the handed-over descriptor is refused by the filter (Linux)",
         refused("ftruncate(descriptor, 0)", ["ftruncate-handle"], "changed", control_needed=False,
                 options=["--file", sample], error_number=1,
                 no_control_why="ftruncate fails on a read-only descriptor even without the filter; the "
                 "error number 1 (EPERM) is the filter's answer")),
        ("filter: a system call that is not on the allow list (setpriority) is refused (Linux)",
         refused("setpriority(PRIO_PROCESS, 0, 1)", ["unlisted-call"], "changed", error_number=1)),
    )
    for name, function in linux_only:
        if linux:
            case(name, function)
        else:
            record("NOT RUN", name, "Linux only: the case is about the Linux system-call filter; on Windows "
                   "the handle's own access rights are what is tested (r-01 point 5, read-only)")

    # ---- what the worker must be able to do ----------------------------------------------------
    def echo():
        result, inner = run_parent(parent, child, ["--stdin", "hello worker"], ["echo"])
        expected = hashlib.sha256(b"hello worker").hexdigest()
        good = result.get("end") == "exited" and result.get("exit_code") == 0 and inner is not None \
            and inner.get("confined") is True and inner.get("sha256") == expected
        return ("PASS" if good else "FAIL"), brief(result, inner)
    case("echo: input reaches the confined child and its answer comes back", echo)

    # ---- limits; the parent must carry on ----------------------------------------------------
    sanitizer = {"value": False}

    def memory():
        result, inner = run_parent(parent, child, ["--memory", str(GIB), "--then-echo"], ["allocate"], wall="60")
        sanitizer["value"] = bool(result.get("sanitizer_build"))
        after = result.get("after") or {}
        peak = result.get("peak_memory_bytes", 0)
        text = "peak_memory_bytes=%s (limit %d) after.end=%s %s" % (peak, GIB, after.get("end"), brief(result, inner))
        good = result.get("end") == "killed_by_memory_limit" and after.get("end") == "exited" \
            and after.get("exit_code") == 0
        if good and not sanitizer["value"]:
            good = 0 < peak <= GIB
        return ("PASS" if good else "FAIL"), text
    case(MEMORY, memory)
    if sanitizer["value"]:
        record("NOT RUN", "memory: peak at most 1 GiB as measured by the system",
               "sanitizer build: no address-space limit can be set, only the parent's watch on resident "
               "memory, which can overshoot; the bound is checked in the normal builds")

    def spin():
        result, inner = run_parent(parent, child, ["--then-echo"], ["spin"], wall="3")
        after = result.get("after") or {}
        seconds = result.get("seconds", 1e9)
        good = result.get("end") == "killed_by_time_limit" and seconds <= 3 + 5 and after.get("end") == "exited"
        return ("PASS" if good else "FAIL"), "seconds=%s after.end=%s %s" % (seconds, after.get("end"),
                                                                             brief(result, inner))
    case("time: a child that never ends is killed within the limit plus 5 s, parent carries on", spin)

    def crash():
        result, inner = run_parent(parent, child, ["--then-echo"], ["crash"])
        after = result.get("after") or {}
        good = result.get("end") == "crashed" and after.get("end") == "exited"
        return ("PASS" if good else "FAIL"), "after.end=%s %s" % (after.get("end"), brief(result, inner))
    case("crash: a crashed child is a result, parent carries on", crash)

    def output_limit():
        result, inner = run_parent(parent, child, ["--max-output", "16", "--stdin", "x"], ["echo"])
        good = result.get("end") == "crashed" and len(result.get("output", "")) <= 16
        return ("PASS" if good else "FAIL"), brief(result, None)
    case("output: more output than allowed stops the child", output_limit)

    # ---- the confinement itself ---------------------------------------------------------------
    def whoami():
        result, inner = run_parent(parent, child, [], ["whoami"])
        text_self = (inner or {}).get("self", "")
        if windows:
            good = "appcontainer=1" in text_self and "in_job=1" in text_self and "integrity=0x1000" in text_self
        elif linux:
            good = "no_new_privs=1" in text_self and "seccomp=2" in text_self
        else:
            return "NOT RUN", "no confinement is written for this system: " + brief(result, inner)
        return ("PASS" if good and result.get("end") == "exited" else "FAIL"), brief(result, inner)
    case("whoami: the child's own view shows the confinement", whoami)

    def never_silently_weaker():
        result, inner = run_parent(parent, child, ["--break", "--stdin", "secret"], ["echo"])
        good = result.get("end") == "start_failed" and "sha256" not in (inner or {})
        return ("PASS" if good else "FAIL"), brief(result, inner)
    case("refusal: a confinement that cannot be applied is start_failed, not a weaker run",
         never_silently_weaker)

    def weaker_only_when_asked():
        result, inner = run_parent(parent, child, ["--break", "--allow-weaker", "--stdin", "x"], ["echo"])
        said = "WEAKER" in result.get("confinement", "") or "WEAKER" in (inner or {}).get("what_applied", "")
        good = result.get("end") == "exited" and said
        return ("PASS" if good else "FAIL"), brief(result, inner)
    case("refusal: with allow_weaker (tests only) the run goes on and SAYS it is weaker",
         weaker_only_when_asked)

    # =========================================================================================
    # The waiting shape (ruling M-13): start_waiting, preparation, hand_over_file, collect.
    # =========================================================================================
    waiting = ["--waiting", "--file", sample]

    def lines_of(text):
        found = []
        for line in (text or "").split("\n"):
            if line.strip().startswith("{"):
                try:
                    found.append(json.loads(line))
                except ValueError:
                    pass
        return found

    def phases(result):
        """The worker's "before" line (taken by the parent as the ready message) and its
        "after" line (first line after the seal)."""
        before = next((line for line in lines_of(result.get("first_output")) if line.get("phase") == "before"), {})
        after = next((line for line in lines_of(result.get("output")) if line.get("phase") == "after"), {})
        return before, after

    def waiting_start():
        preparation = "our own rules: " + "r" * 5000
        result, inner = run_parent(parent, child, waiting + ["--prep", preparation, "--job", "the job"], ["whoami"])
        before, after = phases(result)
        good = result.get("state_after_start") == "waiting" and result.get("hand_over_ok") is True \
            and result.get("end") == "exited" and inner is not None and inner.get("confined") is True \
            and before.get("preparation_sha256") == hashlib.sha256(preparation.encode("ascii")).hexdigest() \
            and after.get("job") == "the job"
        if linux:
            good = good and "seccomp=2" in inner.get("self", "") and "stage 1" in result.get("confinement_at_start", "")
        return ("PASS" if good else "FAIL"), "tried: start a waiting worker, send %d bytes of preparation, wait " \
            "for its first line, hand over a file with a job, collect. At start: %r; stage 1 said: %r; after the " \
            "seal: %r; %s" % (len(preparation), result.get("confinement_at_start"), before.get("stage1"),
                              after.get("what_applied"), brief(result, inner))
    if case(W_START, waiting_start) != "PASS":
        print("STOPPED the waiting shape: the worker cannot be started that way; its other cases would only "
              "fail the same way.", flush=True)
        waiting = None

    if waiting:
        loop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        loop.bind(("127.0.0.1", 0))
        loop.listen(8)
        case(W_P1, refused("TCP connection to a listener of this test on 127.0.0.1, 5 s bound, from a waiting "
                           "worker after its seal", ["connect", "127.0.0.1", str(loop.getsockname()[1])],
                           "connected", options=waiting))
        loop.close()
        if address is None:
            record("NOT RUN", W_P1B, "this machine has no IPv4 address other than the local loop")
        else:
            try:
                outside = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                outside.bind((address, 0))
                outside.listen(8)
            except OSError as error:
                record("FAIL", W_P1B, "could not listen on the machine's own address %s: %s" % (address, error))
            else:
                case(W_P1B, refused("TCP connection to a listener of this test on %s, 5 s bound, from a waiting "
                                    "worker after its seal" % address,
                                    ["connect", address, str(outside.getsockname()[1])], "connected",
                                    options=waiting))
                outside.close()
        case(W_P2, refused("open and read %s by its path, from a waiting worker after its seal" % private,
                           ["open-path", private], "opened", options=waiting))
        if linux:
            case(W_P3, refused("fork(), and execve(/bin/true) when fork is refused", ["spawn"], "spawned",
                               options=waiting))
        else:
            case(W_P3, refused("CreateProcessW(cmd.exe /c exit 0)", ["spawn"], "spawned", control_needed=False,
                               options=waiting, no_control_why="the job's one-process limit binds the "
                               "unconfined test child too"))
        case(W_P4, refused("create and write %s" % target, ["write-path", target], "opened", options=waiting))

        def waiting_read():
            result, inner = run_parent(parent, child, waiting, ["read-handle"])
            good = result.get("end") == "exited" and inner is not None and inner.get("confined") is True \
                and inner.get("read") is True and inner.get("sha256") == sample_hash
            return ("PASS" if good else "FAIL"), "tried: the waiting worker reads the whole handed-over file " \
                "after its seal and hashes it; expected %s; %s" % (sample_hash, brief(result, inner))
        case(W_P5A, waiting_read)

        def waiting_write():
            result, inner = run_parent(parent, child, waiting, ["write-handle"])
            good = result.get("end") == "exited" and inner is not None and inner.get("confined") is True \
                and inner.get("handle_present") is True and inner.get("wrote") is False
            if good and linux:
                good = inner.get("error") == 9  # the descriptor's own refusal, not the filter's
            with open(sample, "rb") as handle:
                unchanged = hashlib.sha256(handle.read()).hexdigest() == sample_hash
            return ("PASS" if good and unchanged else "FAIL"), "tried: write one byte through the handed-over " \
                "handle; file unchanged=%s; %s" % (unchanged, brief(result, inner))
        case(W_P5B, waiting_write)

        def waiting_handles():
            result, inner = run_parent(parent, child, waiting, ["whoami"])
            before, after = phases(result)
            if not before or not after:
                return "FAIL", "the worker did not print both enumerations; " + brief(result, inner)
            if linux:
                had = before.get("open_descriptors")
                has = after.get("open_descriptors")
                file_number = after.get("file_descriptor")
                good = had == [0, 1, 2, 3, 4] and has == [0, 1, 2, file_number] and file_number not in had
                tried = "every descriptor number below %s asked with fstat. BEFORE the hand-over: %s (0, 1, 2 the " \
                    "standard streams, 3 the channel, 4 the write-only status pipe to the parent: NOTE two " \
                    "besides the standard streams, not one). AFTER the seal and before any read: %s (the " \
                    "channel and the status pipe are closed; %s is the file). Read-only was checked by the " \
                    "worker with fcntl before the filter (it refuses otherwise) and is shown by the case " \
                    "before. NOT SHOWN: numbers at or above the bound" % (
                        after.get("scanned"), had, has, file_number)
            else:
                def table(phase):
                    entries = {}
                    for entry in phase.get("all_handles", []):
                        value, kind, mark, access = entry.split(":")
                        entries[int(value)] = (kind, mark, int(access, 16))
                    return entries
                had, has = table(before), table(after)
                file_handle = after.get("file_handle")
                new = sorted(set(has) - set(had))
                new_files = [value for value in new if has[value][0] == "File"]
                change_rights = 0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000
                inherited_before = sorted(value for value, entry in had.items() if entry[1] == "I")
                inherited_after = sorted(value for value, entry in has.items() if entry[1] == "I")
                good = bool(had) and inherited_before == sorted(before.get("standard_handles", [])) \
                    and set(inherited_after) <= set(inherited_before) and new_files == [file_handle] \
                    and has[file_handle][1] == "N" and (has[file_handle][2] & change_rights) == 0
                tried = "the system's own list of the worker's handles, taken BEFORE the hand-over and AFTER it " \
                    "(before any read). Before: %d handles, inherited from the parent exactly the three " \
                    "standard handles %s. After: %d handles; inherited ones %s (standard input was closed after " \
                    "the one job); new handles since before: %s, of which files: %s (expected exactly the " \
                    "handed-over file %s, not inheritable, access 0x%x without any write right). NOT SHOWN: " \
                    "new handles that are not files are listed here by type, not examined: %s" % (
                        len(had), inherited_before, len(has), inherited_after, new, new_files, file_handle,
                        has.get(file_handle, ("", "", 0))[2],
                        [(value, has[value][0]) for value in new if has[value][0] != "File"])
            return ("PASS" if good and result.get("end") == "exited" else "FAIL"), "tried: " + tried + "; " \
                + brief(result, inner)
        case(W_P5C, waiting_handles)

        def one_file_only():
            result, inner = run_parent(parent, child, waiting + ["--second-hand-over"], ["whoami"])
            answers = [line for line in lines_of(result.get("output")) if "action" in line]
            good = result.get("hand_over_ok") is True and result.get("second_hand_over_ok") is False \
                and result.get("end") == "exited" and len(answers) == 1
            return ("PASS" if good else "FAIL"), "tried: hand a second file to the same worker; the call said: " \
                "%r; answers the worker gave: %d (expected 1); %s" % (
                    result.get("second_hand_over_error"), len(answers), brief(result, inner))
        case(W_ONE, one_file_only)

        def malformed(kind, words):
            def run():
                result, inner = run_parent(parent, child, waiting + ["--malformed", kind], ["whoami"])
                answers = [line for line in lines_of(result.get("output")) if "action" in line]
                good = result.get("end") == "start_failed" and not answers and result.get("exit_code") == 87
                return ("PASS" if good else "FAIL"), "tried: hand over %s; expected: the worker ends with exit " \
                    "code 87 and no answer, the parent reports start_failed; %s" % (words, brief(result, inner))
            return run
        for kind, words, linux_only_kind in (("none", "a job message without a file", False),
                                             ("two", "two descriptors in one message", True),
                                             ("notfile", "something that is not a regular file", False),
                                             ("writable", "the file opened for reading and writing", False),
                                             ("short", "a message shorter than the fixed size", False)):
            name = W + "hand-over refused by the worker: " + words
            if linux_only_kind and not linux:
                record("NOT RUN", name, "Linux only: on Windows the message names one handle value")
            else:
                case(name, malformed(kind, words))

        def unsealed_answer():
            result, inner = run_parent(parent, child, waiting, ["skip-seal"])
            good = result.get("end") == "start_failed" and result.get("output", "") == ""
            return ("PASS" if good else "FAIL"), "tried: a worker that answers without having reported its " \
                "full confinement; expected: the parent discards the answer (empty output, start_failed); " \
                + brief(result, inner)
        if linux:
            case(W + "the answer of a worker that did not report its full confinement is discarded (Linux)",
                 unsealed_answer)
        else:
            record("NOT RUN", W + "the answer of a worker that did not report its full confinement is "
                   "discarded (Linux)", "Linux only: on Windows the parent applies the whole confinement when "
                   "it creates the worker; there is no later report to miss")

        def ended_unused():
            result, inner = run_parent(parent, child, waiting + ["--end-unused"], ["whoami"])
            good = result.get("state_after_end") == "ended" and result.get("hand_over_ok") is False \
                and result.get("end") == "start_failed"
            return ("PASS" if good else "FAIL"), "tried: end a waiting worker that was never used, then try to " \
                "hand it a file; the call said: %r; %s" % (result.get("hand_over_error"), brief(result, inner))
        case(W + "a worker ended unused cannot be handed a file", ended_unused)

        def died_waiting():
            result, inner = run_parent(parent, child, waiting + ["--delay-hand-over", "1"], ["die-waiting"])
            good = result.get("hand_over_ok") is False and result.get("end") == "start_failed"
            return ("PASS" if good else "FAIL"), "tried: a worker that dies while it waits (exit code 9), then a " \
                "hand-over one second later; the call said: %r; the parent's record: %r; %s" % (
                    result.get("hand_over_error"), result.get("failure_text"), brief(result, inner))
        case(W + "a worker that dies while waiting is noticed; no file is handed to it", died_waiting)

        def parent_gone():
            command = [parent, child, "--wall", "20"] + waiting + ["--abandon", "--", "whoami"]
            done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            answer = lines_of(done.stdout.decode("ascii", "replace"))
            before = lines_of(answer[-1].get("first_output") if answer else "")
            pid = before[0].get("pid") if before else None
            if not pid:
                return "FAIL", "the worker's process number was not learnt: %r" % (done.stdout[:300],)
            import time
            gone = False
            for _ in range(50):
                if windows:
                    listed = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/NH"], stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, timeout=30).stdout.decode("ascii", "replace")
                    gone = str(pid) not in listed
                else:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        gone = True
                    except PermissionError:
                        gone = False
                if gone:
                    break
                time.sleep(0.1)
            return ("PASS" if gone else "FAIL"), "tried: the parent leaves at once while worker %d waits; " \
                "expected: the worker is gone within 5 s; gone=%s" % (pid, gone)
        case(W + "a waiting worker ends when its parent goes away", parent_gone)

        def waiting_time():
            result, inner = run_parent(parent, child, waiting + ["--delay-hand-over", "2"], ["spin"], wall="3")
            seconds = result.get("seconds", 1e9)
            good = result.get("end") == "killed_by_time_limit" and 2.5 <= seconds <= 3 + 1.5
            return ("PASS" if good else "FAIL"), "tried: wait 2 s, hand over, the worker never ends, 3 s limit; " \
                "expected: killed about 3 s after the HAND-OVER (not after the start); seconds=%s; %s" % (
                    seconds, brief(result, inner))
        case(W + "time: the limit runs from the hand-over", waiting_time)

        def waiting_memory():
            result, inner = run_parent(parent, child, waiting + ["--memory", str(GIB)], ["allocate"], wall="60")
            peak = result.get("peak_memory_bytes", 0)
            good = result.get("end") == "killed_by_memory_limit"
            if good and not SANITIZER["seen"]:
                good = 0 < peak <= GIB
            return ("PASS" if good else "FAIL"), "peak_memory_bytes=%s (limit %d) %s" % (peak, GIB,
                                                                                         brief(result, inner))
        case(W + "memory: the limit ends the worker", waiting_memory)

        def waiting_shipped():
            hooked, hooked_inner = run_parent(parent, child, waiting + ["--break", "--allow-weaker"], ["whoami"])
            if "WEAKER" not in hooked.get("confinement", "") + hooked.get("confinement_at_start", ""):
                return "FAIL", "the control (test-build worker with the switches) did not run WEAKER, so " \
                    "nothing is shown: " + brief(hooked, hooked_inner)
            result, inner = run_parent(parent, shipped_child, waiting + ["--break", "--allow-weaker"], ["whoami"])
            inner = inner or {}
            if linux:
                good = result.get("end") == "exited" and "WEAKER" not in result.get("confinement", "") \
                    and "seccomp=2" in inner.get("self", "")
                expected = "the worker applies stage 1 and the seal in full (seccomp=2, no WEAKER text)"
            else:
                good = result.get("end") == "start_failed" and result.get("hand_over_ok") is False \
                    and "self" not in inner
                expected = "the worker, started outside a container, refuses at stage 1 and is given no file"
            return ("PASS" if good else "FAIL"), "tried: the waiting shape with %s and the test switches in its " \
                "environment; control: the test-build worker ran WEAKER; expected: %s; %s" % (
                    os.path.basename(shipped_child), expected, brief(result, inner))
        if shipped_child:
            case(W_SHIPPED, waiting_shipped)
        else:
            record("NOT RUN", W_SHIPPED, "the test was not given the third program (mie-sandbox-shippedchild)")

    # ---- per-worker profiles (Windows): SW-1, no state across workers, clean-up after a crash ----
    def cross_scan():
        command = [parent, child, "--cross-scan", "--file", sample]
        done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        lines = [line for line in done.stdout.split(b"\n") if line.strip()]
        answer = json.loads(lines[-1].decode("ascii")) if lines else {}
        for side in ("a", "b"):
            if isinstance(answer.get(side), dict):
                note_profile_cost(answer[side], answer.get("retired_" + side))
        return answer

    def child_line(result):
        for line in (result or {}).get("output", "").split("\n"):
            if line.strip().startswith("{") and '"action"' in line:
                try:
                    return json.loads(line)
                except ValueError:
                    pass
        return {}

    if windows:
        WINDOWS_MUST_RUN.extend([SW1, CROSS, SWEEP])
        seen_env, seen_inner = run_parent(parent, child, [], ["environment"])
        print("SW-1: folder variables as a confined worker sees them: %s" % json.dumps(
            {name: (seen_inner or {}).get(name) for name in ("TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE")},
            sort_keys=True), flush=True)
        try:
            cross = cross_scan()
        except Exception as error:  # reported by the cases below
            cross = {"error": repr(error)}
        folder_a, folder_b = cross.get("folder_a", ""), cross.get("folder_b", "")
        print("M-13: worker A's own folder: %s" % folder_a, flush=True)
        print("M-13: worker B's own folder (B started before A, waiting while A ran): %s" % folder_b, flush=True)
        line_a, line_b = child_line(cross.get("a")), child_line(cross.get("b"))

        def real(path):
            # Long and short forms of the same folder (C:\Users\runneradmin and C:\Users\RUNNER~1)
            # compare equal only after the system has resolved them: realpath on what exists,
            # and on the nearest existing parent otherwise.
            head, tail = path, []
            while head and not os.path.exists(head):
                head, part = os.path.split(head)
                if not part:
                    break
                tail.insert(0, part)
            return os.path.normcase(os.path.join(os.path.realpath(head) if head else head, *tail))

        def inside(path, folder):
            return bool(folder) and real(path).startswith(real(folder) + os.sep)

        def sw1():
            if not folder_a:
                return "FAIL", "the cross-scan run gave no folder for worker A: %r" % (cross,)
            written = line_a.get("written", [])
            outside_own = [path for path in written if not inside(path, folder_a)]
            # Paths are compared after the system resolved them (os.path.realpath), so that a
            # long and a short form of the same folder are one folder. A's folder no longer
            # exists at this point, so its resolution is the one taken by the parent at start.
            text = "tried: worker A, after its seal, created a file in its folder's root, AC and AC\\Temp, in " \
                "worker B's folder, and in the TEMP and TMP it sees. WRITTEN: %s. Refused: %s. Written outside " \
                "its own folder: %s. A's folder still on disk after A ended: %s (%s). %s" % (
                    written or "none", line_a.get("not_written", []) or "none", outside_own or "none",
                    cross.get("folder_a_exists_after_a"), (cross.get("retired_a") or {}).get("text"),
                    brief(cross.get("a") or {}, line_a))
            good = bool(line_a) and not outside_own and cross.get("folder_a_exists_after_a") is False
            for path in outside_own:
                try:
                    os.remove(path)
                except OSError:
                    pass
            return ("PASS" if good else "FAIL"), text
        case(SW1, sw1)

        def no_cross():
            if not folder_a or not folder_b:
                return "FAIL", "the cross-scan run gave no folders: %r" % (cross,)
            seen_by_b = line_b.get("seen", [])
            on_disk = [path for path, present in (cross.get("on_disk_after_a") or {}).items() if present]
            text = "tried: worker B was started and waited; worker A (own folder %s) was handed a file and wrote " \
                "what it could (%s), including into B's folder %s, and ended; then B was handed a file and " \
                "looked for every one of those files. B saw: %s. On disk after A ended, as this unconfined test " \
                "sees it: %s. Folder note given with B's hand-over: %r. %s" % (
                    folder_a, line_a.get("written", []) or "nothing", folder_b, seen_by_b or "none",
                    on_disk or "none", (cross.get("b") or {}).get("container_folder_note"),
                    brief(cross.get("b") or {}, line_b))
            own_writes = [path for path in line_a.get("written", []) if inside(path, folder_a)]
            into_b = [path for path in line_a.get("written", []) if inside(path, folder_b)]
            text += " Worker A's attempts into B's folder: %s." % (
                "WRITTEN: %s" % into_b if into_b else "refused")
            if not own_writes:
                return "FAIL", "worker A wrote nothing into its own folder, so 'B saw nothing' shows nothing. " + text
            good = os.path.normcase(folder_a) != os.path.normcase(folder_b) and bool(line_b) \
                and not seen_by_b and not on_disk and (cross.get("b") or {}).get("end") == "exited" \
                and (cross.get("b") or {}).get("container_folder_note", "") == ""
            return ("PASS" if good else "FAIL"), text
        case(CROSS, no_cross)

        def sweep_after_crash():
            import threading
            packages = json.loads(subprocess.run([parent, "--sid"], stdout=subprocess.PIPE, timeout=60)
                                  .stdout.split(b"\n")[0].decode("ascii")).get("folder", "")

            def ours_on_disk():
                try:
                    return sorted(name.lower() for name in os.listdir(packages)
                                  if name.lower().startswith("dexmond.mie.worker"))
                except OSError:
                    return []
            before = subprocess.run([parent, "--sweep"], stdout=subprocess.PIPE, timeout=120).stdout
            print("M-13 sweep before the crash run: %s" % before.decode("ascii", "replace").strip(), flush=True)
            held = subprocess.Popen([parent, child, "--hold", "3"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            first = {}

            def read_first():
                first["line"] = held.stdout.readline()
            reader = threading.Thread(target=read_first, daemon=True)
            reader.start()
            reader.join(60)
            held.kill()  # TerminateProcess: the parent cleans nothing up
            held.wait(30)
            import time
            time.sleep(2)  # the workers die when the parent's job handles close; give that a moment
            try:
                folders = json.loads(first.get("line", b"{}").decode("ascii")).get("folders", [])
            except ValueError:
                folders = []
            names = [os.path.basename(folder).lower() for folder in folders if folder]
            if len(names) != 3:
                return "FAIL", "the parent with three waiting workers did not report three folders: %r" % (
                    first.get("line"),)
            left_after_kill = [name for name in names if name in ours_on_disk()]
            if len(left_after_kill) != 3:
                return "FAIL", "the hard kill left %d of the three profiles on disk (%s; on disk: %s), so the " \
                    "sweep has nothing to show" % (len(left_after_kill), names, ours_on_disk())
            swept = json.loads(subprocess.run([parent, "--sweep"], stdout=subprocess.PIPE, timeout=120)
                               .stdout.split(b"\n")[0].decode("ascii"))
            remaining = ours_on_disk()
            text = "tried: a parent started three waiting workers (%s) and was killed hard; left on disk after the " \
                "kill: %s; the next start's sweep said: %s; removed: %s; failed: %s; left alone: %s; profiles " \
                "with the prefix on disk afterwards: %s (no worker of this test is alive at this point)" % (
                    names, left_after_kill, swept.get("text"), swept.get("names_removed"),
                    swept.get("names_failed"), swept.get("names_left_alone"), remaining or "none")
            removed_names = [name.lower() for name in swept.get("names_removed", [])]
            good = all(name in removed_names for name in left_after_kill) \
                and not any(name in remaining for name in names)
            return ("PASS" if good else "FAIL"), text
        case(SWEEP, sweep_after_crash)
    else:
        for name in (SW1, CROSS, SWEEP):
            record("NOT RUN", name, "Windows only: on Linux a confined worker has no profile and no folder; it "
                   "can open no path at all (r-01 points 2 and 4)")

    # ---- SB-1: the shipped library has no test switches -----------------------------------------
    def shipped_ignores_switches():
        # The test parent (test build) puts MIE_SANDBOX_ALLOW_WEAKER=1 in the child's
        # environment, and on Linux MIE_SANDBOX_TEST_BREAK=1 as well. The child here is built
        # with the SHIPPED library.
        hooked, hooked_inner = run_parent(parent, child, ["--break", "--allow-weaker"], ["whoami"])
        hooked_said = "WEAKER" in hooked.get("confinement", "") or "WEAKER" in (hooked_inner or {}).get(
            "what_applied", "")
        if not hooked_said:
            return "FAIL", "the control (the test-build child with the same switches) did not run WEAKER, " \
                "so the switches were not in effect and nothing is shown: " + brief(hooked, hooked_inner)
        result, inner = run_parent(parent, shipped_child, ["--break", "--allow-weaker"], ["whoami"])
        inner = inner or {}
        if linux:
            # The child must confine itself in full, whatever the variables say.
            good = result.get("end") == "exited" and inner.get("confined") is True \
                and "WEAKER" not in inner.get("what_applied", "") and "seccomp=2" in inner.get("self", "") \
                and "test hook" not in inner.get("what_applied", "")
            expected = "the child applies the whole confinement (seccomp=2, no WEAKER text)"
        else:
            # On Windows the test parent leaves the AppContainer out; a child without the switch
            # must REFUSE to work outside a container instead of going on weaker.
            good = inner.get("confined") is False and "self" not in inner and result.get("exit_code") == 3
            expected = "the child, started outside a container, refuses to work (exit code 3) instead of " \
                "going on weaker"
        return ("PASS" if good else "FAIL"), "tried: started %s with the test switches in its environment; " \
            "the test-build child with the same switches ran WEAKER (control); expected: %s; %s" % (
                os.path.basename(shipped_child), expected, brief(result, inner))
    if shipped_child:
        case(SHIPPED, shipped_ignores_switches)
    else:
        record("NOT RUN", SHIPPED, "the test was not given the third program (mie-sandbox-shippedchild)")

    return summary()


if __name__ == "__main__":
    sys.exit(main())
