#!/usr/bin/env python3
"""Tests for services_view.py and ssh_probe.py classification.

BOTH MODULES EXIST TO KEEP AN ABSENCE OF EVIDENCE APART FROM EVIDENCE OF
ABSENCE, and both fail silently when they get it wrong. A host nobody has
port-scanned rendering as "not running ssh" throws nothing, logs nothing, and
looks exactly like a working answer -- it is only wrong. On this network that is
37 of 78 hosts, so the wrong version of this logic would be wrong about nearly
half the network while appearing entirely healthy.

The ssh classifier has the same shape: a changed host key and a missing key
both fail, and treating the first as the second sends someone to install a key
that was never the problem.

Run: python3 tools/test_network_inventory_services.py
"""

from __future__ import annotations

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# network_inventory merged into cyber_estate's scan/ subpackage.
PKG = os.path.join(HERE, "..", "scan")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(PKG, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sv = load("ni_services_view", "services_view.py")
# ssh_probe imports services_view by relative name; give it one it can resolve.
sys.modules["ni_ssh_probe_deps"] = sv


def load_ssh():
    path = os.path.join(PKG, "ssh_probe.py")
    with open(path) as fh:
        src = fh.read()
    src = src.replace("from .services_view import", "from ni_services_view import")
    mod = type(sys)("ni_ssh_probe")
    mod.__dict__["__file__"] = path
    sys.modules["ni_ssh_probe"] = mod
    exec(compile(src, path, "exec"), mod.__dict__)
    return mod


ssh = load_ssh()

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


def host(ports=None, scanned_at="2026-08-15T03:26:16+00:00", **kw):
    h = {
        "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "192.0.2.9",
        "status": "up",
        "ports": ports or [],
        "port_list": [f"{p['proto']}/{p['port']}" for p in (ports or [])],
        "open_port_count": len(ports or []),
        "ports_scanned_at": scanned_at,
    }
    h.update(kw)
    return h


SSH_PORT = {"port": 22, "proto": "tcp", "service": "ssh",
            "product": "OpenSSH", "version": "10.0p2"}
HTTP_80 = {"port": 80, "proto": "tcp", "service": "http"}
HTTP_8080 = {"port": 8080, "proto": "tcp", "service": "http",
             "product": "nginx", "version": "1.24"}
BARE = {"port": 49152, "proto": "tcp"}


print("\nservices_for_host")
r = sv.services_for_host(host([SSH_PORT, HTTP_80, HTTP_8080]))
check("services keyed by name, not port", sorted(r), ["http", "ssh"])
check("same service on two ports collapses", r["http"].ports, [80, 8080])
check("ssh port recorded", r["ssh"].ports, [22])
check("product captured", r["ssh"].product, "OpenSSH")
check("descriptor joins product and version", r["ssh"].descriptor, "OpenSSH 10.0p2")
check("descriptor is None when unidentified",
      sv.services_for_host(host([HTTP_80]))["http"].descriptor, None)
check("unnamed port buckets as unknown",
      list(sv.services_for_host(host([BARE]))), ["unknown"])
check("slug is entity-id safe", sv.service_slug("ms-wbt-server"), "ms_wbt_server")
check("empty name falls back", sv.service_slug(""), "unknown")

print("\nreading_for -- the three states")
scanned_with_ssh = host([SSH_PORT])
scanned_without = host([HTTP_80])
never = host([], scanned_at=None)

check("open when observed", sv.reading_for(scanned_with_ssh, "ssh").state, "open")
check("closed when scanned and absent",
      sv.reading_for(scanned_without, "ssh").state, "closed")
check("NEVER_SCANNED when nobody looked",
      sv.reading_for(never, "ssh").state, "never_scanned")
check("never_scanned is NOT closed -- the whole point",
      sv.reading_for(never, "ssh").state == "closed", False)
check("a host scanned with nothing open is still an observation",
      sv.reading_for(host([]), "ssh").state, "closed")
check("host_was_port_scanned reads the timestamp, not the port list",
      sv.host_was_port_scanned(host([])), True)
check("...and is False with no timestamp",
      sv.host_was_port_scanned(never), False)

print("\ncensus -- the unproven count travels with the answer")
c = sv.census({
    "a": host([SSH_PORT]),
    "b": host([SSH_PORT, HTTP_80]),
    "c": host([HTTP_80]),
    "d": never,
    "e": host([], scanned_at=None),
})
check("ssh host count", c["services"]["ssh"]["hosts"], 2)
check("http host count", c["services"]["http"]["hosts"], 2)
check("versions collected", c["services"]["ssh"]["versions"], ["OpenSSH 10.0p2"])
check("scanned count", c["hosts_port_scanned"], 3)
check("never-scanned count is reported, not hidden",
      c["hosts_never_port_scanned"], 2)
check("coverage percentage", c["coverage_pct"], 60.0)
check("distinct services", c["distinct_services"], 2)
check("an empty inventory does not divide by zero", sv.census({})["coverage_pct"], 0.0)

print("\nssh_probe.host_runs_ssh -- tri-state")
check("runs ssh", ssh.host_runs_ssh(scanned_with_ssh), True)
check("does not run ssh", ssh.host_runs_ssh(scanned_without), False)
check("UNKNOWN when never scanned", ssh.host_runs_ssh(never), None)
check("None is not False", ssh.host_runs_ssh(never) is False, False)
check("ssh ports listed", ssh.ssh_ports(scanned_with_ssh), [22])

print("\nssh_probe.classify")
check("rc 0 is authorized", ssh.classify(0, "").state, "authorized")
check("permission denied is refused",
      ssh.classify(255, "user@h: Permission denied (publickey).").state, "refused")
check("changed host key is NOT refused",
      ssh.classify(255,
                   "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n"
                   "Host key verification failed.").state,
      "host_key_changed")
check("plain host key failure classified",
      ssh.classify(255, "Host key verification failed.").state, "host_key_changed")
check("connection refused is unreachable",
      ssh.classify(255, "ssh: connect to host h port 22: Connection refused").state,
      "unreachable")
check("timeout is unreachable",
      ssh.classify(255, "ssh: connect to host h port 22: Connection timed out").state,
      "unreachable")
check("no route is unreachable",
      ssh.classify(255, "ssh: connect to host h: No route to host").state,
      "unreachable")
check("unrecognised failure is unreachable, not guessed as refused",
      ssh.classify(255, "some novel sshd error").state, "unreachable")
check("...and keeps the message",
      ssh.classify(255, "some novel sshd error").detail, "some novel sshd error")
check("accept-new warning is not mistaken for the reason",
      ssh.classify(255, "Warning: Permanently added 'h' (ED25519)...\n"
                        "ssh: connect to host h port 22: Connection refused").detail,
      "ssh: connect to host h port 22: Connection refused")

# --- self-test --------------------------------------------------------------
print("\nSELF-TEST (must report failures to prove the gate works)")
_p, _f = PASS, FAIL
check("deliberately wrong", "open", "closed")
detected = FAIL - _f
PASS, FAIL = _p, _f
if detected == 1:
    PASS += 1
    print("  PASS  self-test: the deliberate failure was detected")
else:
    FAIL += 1
    print(f"  FAIL  self-test: expected 1 detected failure, saw {detected}")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
