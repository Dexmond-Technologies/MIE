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
SHIPPED = "SB-1: a child built with the shipped library ignores the test switches in its environment"
P2 = "r-01 point 2: reading a file in the user's profile that was not handed over fails"
P3 = "r-01 point 3: starting another process from the confined child fails"
P4 = "r-01 point 4: writing a file outside what was handed over fails"
P5A = "r-01 point 5: the handed-over file is readable through its handle (hash equals the file's)"
P5B = "r-01 point 5: the handed-over file is read-only (writing through the handle fails)"
P5C = "r-01 point 5: the handed-over file is the only thing inherited besides the three standard streams"
MEMORY = "memory: the limit ends the child, the parent carries on"
MUST_RUN = (P1, P1B, P2, P3, P4, P5A, P5B, P5C, MEMORY, SHIPPED)
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
    inner = None
    for line in result.get("output", "").split("\n"):
        if line.strip().startswith("{"):
            try:
                inner = json.loads(line)
            except ValueError:
                inner = None
    return result, inner


def brief(result, inner):
    return "end=%s exit=%s inner=%s detail=%r applied=%r" % (
        result.get("end"), result.get("exit_code"), json.dumps(inner, sort_keys=True),
        result.get("detail", "")[:700], result.get("confinement", ""))


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
    blocking = [name for name in MUST_RUN
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
