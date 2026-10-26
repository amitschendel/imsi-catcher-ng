"""Driving gr-gsm: grgsm_scanner for discovery, grgsm_livemon_headless for capture."""

from __future__ import annotations

import os
import re
import selectors
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

SCANNER = "grgsm_scanner"
LIVEMON = "grgsm_livemon_headless"
BANDS = ("GSM900", "DCS1800", "GSM850", "PCS1900", "GSM450", "GSM480", "GSM-R")

_SCAN_LINE = re.compile(
    r"ARFCN:\s*(\d+),\s*Freq:\s*([\d.]+)M,\s*CID:\s*(\d+),\s*LAC:\s*(\d+),\s*"
    r"MCC:\s*(\d+),\s*MNC:\s*(\d+),\s*Pwr:\s*(-?\d+)"
)
_NEIGH_LINE = re.compile(r"Neighbour Cells:\s*([\d, ]*)")
_CELL_ARFCNS = re.compile(r"Cell ARFCNs:\s*([\d, ]*)")
_CCCH = re.compile(r"Configuration:\s*(.+)")


@dataclass
class ScanResult:
    arfcn: int
    freq_mhz: float
    cid: int
    lac: int
    mcc: int
    mnc: int  # grgsm_scanner prints the MNC as an integer, so leading zeros are lost
    power_db: int
    neighbours: list[int]
    cell_arfcns: list[int]
    ccch: str | None = None


def require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise SystemExit(f"{tool} not found in PATH. Install gr-gsm (Debian/Ubuntu: apt install gr-gsm).")
    return path


def parse_scan_output(text: str) -> list[ScanResult]:
    results: list[ScanResult] = []
    for line in text.splitlines():
        m = _SCAN_LINE.search(line)
        if m:
            a, f, cid, lac, mcc, mnc, pwr = m.groups()
            results.append(ScanResult(int(a), float(f), int(cid), int(lac), int(mcc), int(mnc),
                                      int(pwr), [], []))
            continue
        if not results:
            continue
        if (m := _NEIGH_LINE.search(line)):
            results[-1].neighbours = [int(x) for x in re.findall(r"\d+", m.group(1))]
        elif (m := _CELL_ARFCNS.search(line)):
            results[-1].cell_arfcns = [int(x) for x in re.findall(r"\d+", m.group(1))]
        elif (m := _CCCH.search(line)):
            results[-1].ccch = m.group(1).strip()
    return results


_PROGRESS = re.compile(r"Scanning:\s*([\d.]+)% done|Try scan CCCH on (\d+)-(\d+)|Found CCCH arfcn:\s*(\d+)")


STALL_S = 90.0
RTL_IDS = {("0bda", "2832"), ("0bda", "2838")}


class ReceiverError(RuntimeError):
    pass


def cpu_seconds(pid: int) -> float | None:
    """User plus system CPU time of a process (Linux /proc), or None if unknown."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return None


def reset_rtlsdr() -> int:
    """USB-reset every RTL2832U dongle; needs write access to /dev/bus/usb (plugdev).

    A dongle left mid-stream by a killed process can keep enumerating but
    deliver no samples until it is reset or replugged.
    """
    import fcntl

    usbdevfs_reset = 0x5514  # _IO('U', 20)
    done = 0
    for dev in Path("/sys/bus/usb/devices").glob("*"):
        try:
            ids = ((dev / "idVendor").read_text().strip(), (dev / "idProduct").read_text().strip())
            if ids not in RTL_IDS:
                continue
            bus, num = int((dev / "busnum").read_text()), int((dev / "devnum").read_text())
            fd = os.open(f"/dev/bus/usb/{bus:03d}/{num:03d}", os.O_WRONLY)
        except (OSError, ValueError):
            continue
        try:
            fcntl.ioctl(fd, usbdevfs_reset, 0)
            done += 1
        except OSError:
            pass
        finally:
            os.close(fd)
    if done:
        time.sleep(2)
    return done


class StallWatch:
    """Notices a child that stopped using CPU, the symptom of a wedged dongle."""

    def __init__(self, pid: int, limit: float = STALL_S) -> None:
        self.pid = pid
        self.limit = limit
        self.cpu = cpu_seconds(pid)
        self.since = time.monotonic()

    def stalled(self) -> bool:
        cpu = cpu_seconds(self.pid)
        if cpu is None:
            return False
        now = time.monotonic()
        if self.cpu is None or cpu - self.cpu > 0.5:
            self.cpu, self.since = cpu, now
            return False
        return now - self.since > self.limit


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _scan_once(cmd: list[str], progress) -> tuple[subprocess.Popen, str, bool]:
    # It is a Python script: unbuffered, or progress only shows up at exit.
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            env=env, bufsize=1)
    assert proc.stdout is not None
    lines = []
    watch = StallWatch(proc.pid)
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    stalled = False
    try:
        while True:
            if sel.select(5.0):
                line = proc.stdout.readline()
                if not line:
                    break
                lines.append(line)
                if progress and _PROGRESS.search(line):
                    progress(line.strip())
            elif proc.poll() is not None:
                break
            elif watch.stalled():
                stalled = True
                break
    except KeyboardInterrupt:
        _stop(proc)
        raise
    finally:
        sel.close()
    _stop(proc)
    return proc, "".join(lines), stalled


def scan(band: str = "GSM900", *, gain: float = 30.0, ppm: float = 0.0, speed: int = 15,
         args: str = "", log: Path | None = None,
         progress: Callable[[str], None] | None = None) -> list[ScanResult]:
    """Run grgsm_scanner; `progress` receives its progress lines as they appear."""
    exe = require(SCANNER)
    # grgsm_scanner only accepts an integer ppm.
    cmd = [exe, "-b", band, "-g", str(gain), "-p", str(round(ppm)), "--speed", str(speed), "-v"]
    if args:
        cmd += ["--args", args]
    for attempt in range(2):
        proc, out, stalled = _scan_once(cmd, progress)
        if not stalled:
            break
        if attempt == 0 and progress:
            progress(f"{SCANNER} stopped using CPU for {STALL_S:.0f}s; resetting the dongle and retrying")
        if attempt == 1 or not reset_rtlsdr():
            raise ReceiverError(f"{SCANNER} stalled (the receiver delivers no samples). "
                                "Replug the SDR and try again.")
    if log:
        log.write_text(out)
    results = parse_scan_output(out)
    if proc.returncode not in (0, -signal.SIGINT) and not results:
        # grgsm_scanner sends its own output to /dev/null while each step runs,
        # so a failure usually comes with no message.
        hint = " (is the band within the receiver's tuning range?)" if band in ("DCS1800", "PCS1900") else ""
        raise RuntimeError(f"{SCANNER} exited with code {proc.returncode} and found no cells{hint}")
    return sorted(results, key=lambda r: -r.power_db)


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Livemon:
    """One grgsm_livemon_headless process sending GSMTAP to our collector port."""

    def __init__(self, freq_hz: float, *, collector_port: int, gain: float = 30.0, ppm: float = 0.0,
                 args: str = "", samp_rate: float = 2e6, log: Path | None = None) -> None:
        self.freq_hz = freq_hz
        self.cmd = [require(LIVEMON), "-f", f"{freq_hz:.0f}", "-g", str(gain), "-p", str(ppm),
                    "-s", f"{samp_rate:.0f}", "--collector", "127.0.0.1",
                    "--collectorport", str(collector_port),
                    # livemon also opens a UDP server; keep it off the collector port.
                    "--serverport", str(free_udp_port())]
        if args:
            self.cmd += ["--args", args]
        if log is None:
            # Keep the output somewhere so a failing receiver can be explained.
            log = Path(tempfile.gettempdir()) / "imsi-catcher-livemon.log"
        self.log_path = log
        self.proc: subprocess.Popen | None = None
        self._log = None
        self.started = 0.0

    def start(self) -> None:
        self._log = open(self.log_path, "ab")
        self.started = time.monotonic()
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.DEVNULL, stdout=self._log,
                                     stderr=subprocess.STDOUT, start_new_session=True)

    def log_tail(self, lines: int = 12) -> str:
        try:
            text = Path(self.log_path).read_text(errors="replace")
        except OSError:
            return ""
        return "\n".join(text.strip().splitlines()[-lines:])

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self, timeout: float = 5.0) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self._log is not None:
            self._log.close()
            self._log = None
        self.proc = None


class Hopper:
    """Rotates a single receiver across frequencies, `dwell` seconds each."""

    MAX_QUICK_FAILURES = 3

    def __init__(self, freqs_hz: list[float], dwell: float, **livemon_kw) -> None:
        if not freqs_hz:
            raise ValueError("no frequencies to hop over")
        self.freqs = freqs_hz
        self.dwell = dwell
        self.kw = livemon_kw
        self.index = -1
        self.current: Livemon | None = None
        self.started = 0.0
        self.quick_failures = 0
        self.stalls = 0
        self.watch: StallWatch | None = None

    def tick(self, now: float | None = None) -> bool:
        """Start or advance the receiver when due. Returns True when it retuned."""
        now = time.monotonic() if now is None else now
        if self.current is not None and self.current.alive() and self.watch and self.watch.stalled():
            # A decoding livemon always uses CPU; an idle one is waiting on a wedged dongle.
            self.stalls += 1
            self.current.stop()
            if self.stalls > 2 or not reset_rtlsdr():
                raise ReceiverError(f"{LIVEMON} stalled (the receiver delivers no samples). "
                                    "Replug the SDR and try again.")
        died = self.current is not None and not self.current.alive()
        if died and now - self.current.started < 15:
            self.quick_failures += 1
            if self.quick_failures >= self.MAX_QUICK_FAILURES:
                tail = self.current.log_tail()
                self.current.stop()
                raise ReceiverError(f"{LIVEMON} keeps exiting right after start. Last output "
                                    f"({self.current.log_path}):\n{tail}")
        due = self.current is None or died or (len(self.freqs) > 1 and now - self.started >= self.dwell)
        if not due:
            return False
        if self.current:
            self.current.stop()
        if not died:
            # A receiver that died is restarted on the same frequency.
            self.quick_failures = 0
            self.index = (self.index + 1) % len(self.freqs)
        self.current = Livemon(self.freqs[self.index], **self.kw)
        self.current.start()
        self.watch = StallWatch(self.current.proc.pid)
        self.started = now
        return True

    def stop(self) -> None:
        if self.current:
            self.current.stop()
            self.current = None
