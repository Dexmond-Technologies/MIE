#!/usr/bin/env python3
"""Worker confinement: what a confined child can and cannot do (conditions M-2 and M-9).

Usage: sandbox_cases.py <mie-sandbox-testparent> <mie-sandbox-testchild>

Every case starts the test child through mie::sandbox::run_confined (by way of the test
parent) and looks at the ChildResult. One line per case: PASS, FAIL or NOT RUN with the
reason. NOT RUN is never counted as passed, and the run FAILS if the network case or the
memory case is NOT RUN.
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile

GIB = 1024 * 1024 * 1024
MUST_RUN = ("network: connection refused when confined", "memory: limit ends the child, parent carries on")

results = []  # (status, name, text)


def record(status, name, text=""):
    results.append((status, name, text))
    print(("%-7s %s" % (status, name)) + (": " + text if text else ""), flush=True)


def run_parent(parent, child, options, action, timeout=120):
    """Returns (ChildResult as dict, the child's own JSON line as dict or None)."""
    command = [parent, child] + options + ["--"] + action
    done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    lines = [line for line in done.stdout.split(b"\n") if line.strip()]
    if not lines:
        return {"end": "no_output", "detail": done.stderr.decode("ascii", "replace")[:500],
                "confinement": "", "output": ""}, None
    result = json.loads(lines[-1].decode("ascii"))
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
        result.get("detail", "")[:300], result.get("confinement", ""))


def case(name, function):
    try:
        outcome = function()
    except subprocess.TimeoutExpired:
        record("FAIL", name, "the test parent itself did not end in time (the parent must never hang)")
        return
    except Exception as error:  # a broken test is a failure, not a pass
        record("FAIL", name, "test error: %r" % (error,))
        return
    status, text = outcome
    record(status, name, text)


def main():
    if len(sys.argv) < 3:
        print("usage: sandbox_cases.py <mie-sandbox-testparent> <mie-sandbox-testchild>")
        return 2
    parent, child = sys.argv[1], sys.argv[2]
    windows = os.name == "nt"
    linux = sys.platform.startswith("linux")

    work = tempfile.mkdtemp(prefix="mie-sandbox-")
    sample = os.path.join(work, "sample.bin")
    with open(sample, "wb") as handle:
        handle.write(b"MIE sandbox test file\n" * 1000)
    with open(sample, "rb") as handle:
        sample_hash = hashlib.sha256(handle.read()).hexdigest()
    target = os.path.join(work, "written-by-child.txt")

    if windows:
        # Inside an AppContainer a program can only be loaded from a folder its SID may read.
        # The test gives the worker's AppContainer SID read-and-execute on the folder of the
        # test child. (An installer has to do the same for the real worker.)
        done = subprocess.run([parent, "--sid"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        try:
            sid = json.loads(done.stdout.split(b"\n")[0].decode("ascii")).get("sid", "")
        except ValueError:
            sid = ""
        if sid:
            granted = subprocess.run(["icacls", os.path.dirname(os.path.abspath(child)), "/grant",
                                      "*%s:(OI)(CI)(RX)" % sid], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print("setup: AppContainer SID %s, icacls exit %d" % (sid, granted.returncode), flush=True)
        else:
            print("setup: the AppContainer SID could not be read: %r" % (done.stdout[:300],), flush=True)

    # ---- what the worker must be able to do -------------------------------------------------
    def echo():
        result, inner = run_parent(parent, child, ["--stdin", "hello worker"], ["echo"])
        expected = hashlib.sha256(b"hello worker").hexdigest()
        good = result.get("end") == "exited" and result.get("exit_code") == 0 and inner is not None \
            and inner.get("confined") is True and inner.get("sha256") == expected
        return ("PASS" if good else "FAIL"), brief(result, inner)
    case("echo: input reaches the confined child and its answer comes back", echo)

    def read_handle():
        result, inner = run_parent(parent, child, ["--file", sample], ["read-handle"])
        good = result.get("end") == "exited" and inner is not None and inner.get("confined") is True \
            and inner.get("read") is True and inner.get("sha256") == sample_hash
        return ("PASS" if good else "FAIL"), brief(result, inner)
    case("handle: the handed-over file is readable and its hash is the file's", read_handle)

    # ---- what it must not be able to do; each with a control run without confinement --------
    def refused(action, key, control_needed=True):
        def run():
            if control_needed:
                control, control_inner = run_parent(parent, child, ["--unconfined"], action)
                if control_inner is None or control_inner.get(key) is not True:
                    return "FAIL", "control run (no confinement) did not succeed, so a refusal proves nothing: " \
                        + brief(control, control_inner)
            result, inner = run_parent(parent, child, [], action)
            good = result.get("end") == "exited" and inner is not None and inner.get("confined") is True \
                and inner.get(key) is False
            return ("PASS" if good else "FAIL"), brief(result, inner)
        return run

    case("path: opening the same file BY PATH fails when confined", refused(["open-path", sample], "opened"))
    case("path: writing a file fails when confined", refused(["write-path", target], "opened"))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = str(listener.getsockname()[1])
    case(MUST_RUN[0], refused(["connect", "127.0.0.1", port], "connected"))
    listener.close()

    if linux:
        case("network: socket creation fails when confined (Linux)", refused(["socket"], "socket_created"))
    else:
        record("NOT RUN", "network: socket creation fails when confined (Linux)",
               "Linux only: on Windows a socket can be created, the connection is what is refused")

    def spawn():
        result, inner = run_parent(parent, child, [], ["spawn"])
        good = result.get("end") == "exited" and inner is not None and inner.get("spawned") is False
        return ("PASS" if good else "FAIL"), brief(result, inner)
    case("process: the confined child cannot start another process", spawn)

    # ---- limits; the parent must carry on ----------------------------------------------------
    sanitizer = {"value": False}

    def memory():
        result, inner = run_parent(parent, child, ["--memory", str(GIB), "--wall", "60", "--then-echo"],
                                   ["allocate"], timeout=180)
        sanitizer["value"] = bool(result.get("sanitizer_build"))
        after = result.get("after") or {}
        peak = result.get("peak_memory_bytes", 0)
        text = "peak_memory_bytes=%s (limit %d) after.end=%s %s" % (peak, GIB, after.get("end"), brief(result, inner))
        good = result.get("end") == "killed_by_memory_limit" and after.get("end") == "exited" \
            and after.get("exit_code") == 0
        if good and not sanitizer["value"]:
            good = 0 < peak <= GIB
        return ("PASS" if good else "FAIL"), text
    case(MUST_RUN[1], memory)
    if sanitizer["value"]:
        record("NOT RUN", "memory: peak at most 1 GiB as measured by the system",
               "sanitizer build: no address-space limit can be set, only the parent's watch on resident "
               "memory, which can overshoot; the bound is checked in the normal builds")

    def spin():
        result, inner = run_parent(parent, child, ["--wall", "3", "--then-echo"], ["spin"], timeout=60)
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

    passed = sum(1 for status, _, _ in results if status == "PASS")
    failed = sum(1 for status, _, _ in results if status == "FAIL")
    not_run = [name for status, name, _ in results if status == "NOT RUN"]
    blocking = [name for name in MUST_RUN
                if not any(status in ("PASS", "FAIL") and case_name == name for status, case_name, _ in results)]
    print("sandbox_cases: %d passed, %d failed, %d not run" % (passed, failed, len(not_run)))
    for name in blocking:
        print("FAIL    required case was not run: %s" % name)
    return 1 if failed or blocking else 0


if __name__ == "__main__":
    sys.exit(main())
