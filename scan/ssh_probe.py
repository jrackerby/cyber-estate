"""Can Home Assistant actually SSH into this host?

THE PROBE MUST RUN FROM HOME ASSISTANT OR IT ANSWERS A DIFFERENT QUESTION.
"Is the public key installed" is not a property of the host alone -- it is a
property of a (client, key, user, host) tuple. Running this from the scanner
box, or from a laptop, would produce a confident answer about a machine nobody
asked about. LAW section 9: for a network service, the only proof is a client
connecting from where it actually runs.

SIX STATES, BECAUSE FOUR OF THEM ARE FAILURES THAT MEAN DIFFERENT THINGS and
lead to different actions:

  authorized        connected and ran a command. The key is installed.
  refused           SSH answered and rejected the credentials. The host is
                    fine; the key is not installed for this user.
  host_key_changed  the host key does not match the one on record. This is
                    either a reimage or a machine-in-the-middle, and it is
                    never something to paper over -- see LAW section 13, where
                    exactly this trap makes a healthy kiosk look dead.
  unreachable       nothing answered on the port. The host is off or filtered.
  no_ssh            the scan found no ssh service here, so nothing was tried.
  never_scanned     the host has never been port-scanned, so we do not know
                    whether it runs ssh at all.

The last two are the reason this is not a binary sensor. `no_ssh` is a finding;
`never_scanned` is the absence of one, and a device nobody has scanned must not
render as one that has no SSH.

BATCHMODE IS NON-NEGOTIABLE. Without it a host offering password auth prompts,
and the probe blocks until it is killed -- one sleeping laptop would stall
every subsequent probe in the pass.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from typing import Any

from .services_view import host_was_port_scanned, services_for_host

_LOGGER = logging.getLogger(__name__)

STATE_AUTHORIZED = "authorized"
STATE_REFUSED = "refused"
STATE_HOST_KEY_CHANGED = "host_key_changed"
STATE_UNREACHABLE = "unreachable"
STATE_NO_SSH = "no_ssh"
STATE_NEVER_SCANNED = "never_scanned"

# Long enough for a sleepy Pi on wireless, short enough that a full pass over
# a handful of hosts stays well inside a coordinator refresh.
CONNECT_TIMEOUT = 8
# Backstop for the whole ssh invocation, in case it hangs somewhere BatchMode
# does not cover (a half-open TCP connection, a wedged sshd).
PROCESS_TIMEOUT = 20

SSH_SERVICE_NAMES = frozenset({"ssh"})


@dataclass(slots=True)
class SshResult:
    """One probe outcome."""

    state: str
    user: str | None = None
    detail: str | None = None

    @property
    def reachable(self) -> bool:
        return self.state == STATE_AUTHORIZED


def host_runs_ssh(host: dict[str, Any]) -> bool | None:
    """True / False / None, where None means nobody has looked.

    Returning None rather than False for an unscanned host is the same
    distinction the service sensors draw, kept here so the probe cannot report
    `no_ssh` about a host it has no evidence for.
    """
    if not host_was_port_scanned(host):
        return None
    return bool(SSH_SERVICE_NAMES & set(services_for_host(host)))


def ssh_ports(host: dict[str, Any]) -> list[int]:
    """Every port on which this host was seen offering ssh."""
    readings = services_for_host(host)
    ports: list[int] = []
    for name in SSH_SERVICE_NAMES:
        reading = readings.get(name)
        if reading:
            ports.extend(reading.ports)
    return sorted(set(ports))


def classify(returncode: int, stderr: str) -> SshResult:
    """Map one ssh invocation's outcome onto a state.

    ORDERED MOST-SPECIFIC FIRST. The host-key message also contains the word
    "denied" in some OpenSSH builds, so a naive check for "denied" would
    classify a changed host key as a missing key -- and then the operator
    installs a key to fix something that was never a key problem.
    """
    text = (stderr or "").lower()

    if returncode == 0:
        return SshResult(state=STATE_AUTHORIZED)

    if (
        "host key verification failed" in text
        or "remote host identification has changed" in text
        or "host key for" in text and "has changed" in text
    ):
        return SshResult(
            state=STATE_HOST_KEY_CHANGED,
            detail="the host key on record does not match the one offered",
        )

    if (
        "connection refused" in text
        or "connection timed out" in text
        or "no route to host" in text
        or "operation timed out" in text
        or "network is unreachable" in text
        or "connection closed by remote host" in text
    ):
        return SshResult(state=STATE_UNREACHABLE, detail=_first_line(stderr))

    if "permission denied" in text or "too many authentication failures" in text:
        return SshResult(
            state=STATE_REFUSED,
            detail="the server rejected this key for this user",
        )

    # An unrecognised failure is reported as unreachable WITH the message
    # attached, never silently bucketed as refused -- "we could not connect and
    # here is why" is honest, "the key is missing" would be a guess.
    return SshResult(state=STATE_UNREACHABLE, detail=_first_line(stderr))


def _first_line(text: str) -> str | None:
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("Warning: Permanently added"):
            return line[:200]
    return None


def find_ssh() -> str | None:
    """Absolute path to the ssh client, or None. Blocking -- use an executor."""
    return shutil.which("ssh")


class SshProber:
    """Probes hosts for key-based reachability, one at a time."""

    def __init__(
        self,
        hass,
        binary: str,
        key_path: str,
        users: list[str],
        known_hosts: str | None = None,
    ) -> None:
        self._hass = hass
        self._binary = binary
        self._key_path = key_path
        # Tried IN ORDER, first success wins. A host reachable as `kiosk` and
        # as `root` is reported under whichever answered first, and the user is
        # recorded on the entity so the answer is not ambiguous.
        self._users = users
        self._known_hosts = known_hosts

    async def async_probe(self, address: str, port: int = 22) -> SshResult:
        """Try each configured user against one host."""
        last = SshResult(state=STATE_UNREACHABLE, detail="no users configured")
        for user in self._users:
            result = await self._probe_one(address, port, user)
            result.user = user
            if result.state == STATE_AUTHORIZED:
                return result
            # A changed host key is a property of the HOST, not of the user, so
            # trying the next user would ask a question already answered and
            # return the same failure with a different name on it.
            if result.state == STATE_HOST_KEY_CHANGED:
                return result
            last = result
        return last

    async def _probe_one(self, address: str, port: int, user: str) -> SshResult:
        args = [
            "-i", self._key_path,
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            # accept-new, not `no`: an unknown host is a first sighting and
            # should be learned, while a CHANGED key must still fail loudly.
            # `no` would silently accept an impersonated host.
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={CONNECT_TIMEOUT}",
            "-o", "PreferredAuthentications=publickey",
            "-p", str(port),
        ]
        if self._known_hosts:
            args += ["-o", f"UserKnownHostsFile={self._known_hosts}"]
        # `true` runs nothing and changes nothing. The probe must never have a
        # side effect on the host it is measuring.
        args += [f"{user}@{address}", "true"]

        try:
            proc = await asyncio.create_subprocess_exec(
                self._binary, *args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as err:
            return SshResult(state=STATE_UNREACHABLE, detail=str(err))

        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), PROCESS_TIMEOUT)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return SshResult(
                state=STATE_UNREACHABLE,
                detail=f"no answer within {PROCESS_TIMEOUT}s",
            )

        return classify(
            proc.returncode if proc.returncode is not None else -1,
            stderr.decode(errors="replace") if stderr else "",
        )
