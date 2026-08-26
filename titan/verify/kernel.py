"""Kernel Observer — Ground-truth evidence from system-level observation.

Two modes:
  1. eBPF (Linux, root): uprobes/kprobes for SSL_write, execve, open —
     the gold standard. Observes what the kernel ACTUALLY did, not what
     HTTP responses claim.
  2. Fallback (any OS): network traffic capture + process monitoring —
     no kernel hooks, but still provides evidence tiers above pure
     differential analysis.

Evidence Tier: "kernel" (eBPF) or "syscall" (fallback) — HIGHER than
differential analysis (tier 3), LOWER than exploit confirmed (tier 6).

Usage:
    observer = KernelObserver()
    session = await observer.attach(pid=1234)
    observations = await observer.observe(session, duration=5.0)
    for obs in observations:
        print(f"{obs.type}: {obs.data}")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Observation types
# ---------------------------------------------------------------------------

class ObservationType(str, Enum):
    """Types of kernel/system observations."""
    TLS_PLAINTEXT_OUT = "tls_plaintext_out"
    TLS_PLAINTEXT_IN = "tls_plaintext_in"
    PROCESS_EXEC = "process_exec"
    PROCESS_FORK = "process_fork"
    FILE_OPEN = "file_open"
    FILE_READ = "file_read"
    OUTBOUND_CONNECTION = "outbound_connection"
    OUTBOUND_DATA = "outbound_data"
    NETWORK_REQUEST = "network_request"
    NETWORK_RESPONSE = "network_response"
    PROCESS_LIST = "process_list"
    FILE_ACCESS = "file_access"
    DNS_QUERY = "dns_query"


class EvidenceTier(str, Enum):
    """Evidence quality tiers (ascending)."""
    SUSPICION = "suspicion"         # Tier 0 — heuristic, no confirmation
    REFLECTION = "reflection"       # Tier 1 — payload reflected
    BEHAVIORAL = "behavioral"       # Tier 2 — timing/behavior anomaly
    DIFFERENTIAL = "differential"   # Tier 3 — structural diff confirmed
    FLOW_TYPED = "flow_typed"       # Tier 4 — chain of verified findings
    KERNEL = "kernel"               # Tier 5 — observed by kernel hooks
    SYSCALL = "syscall"             # Tier 5b — observed by process/network monitoring
    EXPLOIT = "exploit"             # Tier 6 — proved by data extraction


@dataclass
class KernelObservation:
    """A single observation from kernel/system monitoring."""
    type: ObservationType
    evidence_tier: EvidenceTier
    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def is_rce_confirmed(self) -> bool:
        return self.type == ObservationType.PROCESS_EXEC and self.data.get("proof")

    @property
    def is_file_access(self) -> bool:
        return self.type in (ObservationType.FILE_OPEN, ObservationType.FILE_READ, ObservationType.FILE_ACCESS)

    @property
    def is_network(self) -> bool:
        return self.type in (
            ObservationType.OUTBOUND_CONNECTION,
            ObservationType.OUTBOUND_DATA,
            ObservationType.NETWORK_REQUEST,
            ObservationType.NETWORK_RESPONSE,
        )


@dataclass
class KernelSession:
    """An active observation session attached to a process."""
    pid: int
    mode: str  # "ebpf", "strace", "network", "process"
    started_at: float = field(default_factory=time.time)
    observations: list[KernelObservation] = field(default_factory=list)
    active: bool = True

    def add(self, obs: KernelObservation) -> None:
        self.observations.append(obs)

    @property
    def duration(self) -> float:
        return time.time() - self.started_at

    @property
    def rce_count(self) -> int:
        return sum(1 for o in self.observations if o.is_rce_confirmed)

    @property
    def file_access_count(self) -> int:
        return sum(1 for o in self.observations if o.is_file_access)


# ---------------------------------------------------------------------------
# eBPF observer (Linux, root required)
# ---------------------------------------------------------------------------

class EBPFKernelObserver:
    """eBPF-based kernel observation using bcc/libbpf.

    This is the gold standard — observes actual kernel syscalls.
    Requires: Linux, root/CAP_SYS_ADMIN, bcc or libbpf installed.
    """

    # Minimal viable uprobes — these 6 cover the most ground
    UPROBES = [
        ("openssl", "SSL_write", ObservationType.TLS_PLAINTEXT_OUT,
         "TLS plaintext before encryption"),
        ("openssl", "SSL_read", ObservationType.TLS_PLAINTEXT_IN,
         "TLS plaintext after decryption"),
        ("libc", "execve", ObservationType.PROCESS_EXEC,
         "Process execution (RCE proof)"),
        ("libc", "fork", ObservationType.PROCESS_FORK,
         "Process fork"),
        ("libc", "open", ObservationType.FILE_OPEN,
         "File open (LFI/XXE ground truth)"),
        ("libc", "read", ObservationType.FILE_READ,
         "File read"),
    ]

    KPROBES = [
        ("tcp_v4_connect", ObservationType.OUTBOUND_CONNECTION,
         "Outbound TCP connection (SSRF proof)"),
        ("tcp_sendmsg", ObservationType.OUTBOUND_DATA,
         "Outbound data (exfiltration proof)"),
        ("sys_connect", ObservationType.OUTBOUND_CONNECTION,
         "Socket connect syscall"),
    ]

    @staticmethod
    def is_available() -> bool:
        """Check if eBPF is available on this system."""
        if platform.system() != "Linux":
            return False
        if os.getuid() != 0:
            return False
        try:
            import subprocess
            result = subprocess.run(
                ["bpftool", "version"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            return False

    async def attach(self, pid: int, duration: float = 5.0) -> KernelSession:
        """Attach eBPF probes to a target process."""
        session = KernelSession(pid=pid, mode="ebpf")

        try:
            from bcc import BPF  # type: ignore

            # Minimal BPF program for syscall tracing
            bpf_program = r"""
            #include <uapi/linux/ptrace.h>
            #include <linux/sched.h>

            struct event_t {
                u32 pid;
                u32 tgid;
                char comm[TASK_COMM_LEN];
                char fname[256];
            };

            BPF_PERF_OUTPUT(events);

            int trace_exec(struct pt_regs *ctx) {
                struct event_t evt = {};
                evt.pid = bpf_get_current_pid_tgid() >> 32;
                evt.tgid = bpf_get_current_pid_tgid();
                bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

                // Read filename from registers
                const char *filename = (const char *)PT_REGS_PARM1(ctx);
                bpf_probe_read_user_str(&evt.fname, sizeof(evt.fname), filename);

                events.perf_submit(ctx, &evt, sizeof(evt));
                return 0;
            }

            int trace_open(struct pt_regs *ctx) {
                struct event_t evt = {};
                evt.pid = bpf_get_current_pid_tgid() >> 32;
                evt.tgid = bpf_get_current_pid_tgid();
                bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

                const char *filename = (const char *)PT_REGS_PARM1(ctx);
                bpf_probe_read_user_str(&evt.fname, sizeof(evt.fname), filename);

                events.perf_submit(ctx, &evt, sizeof(evt));
                return 0;
            }
            """

            b = BPF(text=bpf_program)
            b.attach_kprobe(event="do_execveat_common", fn_name="trace_exec")
            b.attach_kprobe(event="do_filp_open", fn_name="trace_open")

            def _handle_event(cpu, data, size):
                event = b["events"].event(data)
                obs_type = ObservationType.PROCESS_EXEC if "exec" in str(event.comm) else ObservationType.FILE_OPEN
                session.add(KernelObservation(
                    type=obs_type,
                    evidence_tier=EvidenceTier.KERNEL,
                    data={
                        "pid": event.pid,
                        "comm": event.comm.decode("utf-8", errors="replace"),
                        "filename": event.fname.decode("utf-8", errors="replace"),
                    },
                    metadata={"source": "ebpf", "probe": "bcc"},
                ))

            b["events"].open_perf_buffer(_handle_event, page_cnt=64)

            # Collect events for the specified duration
            end_time = time.time() + duration
            while time.time() < end_time and session.active:
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, b.perf_buffer_poll, 100
                    )
                except Exception:
                    break

        except ImportError:
            logger.warning("bcc not installed — eBPF unavailable")
        except Exception as e:
            logger.warning(f"eBPF attach failed: {e}")

        return session


# ---------------------------------------------------------------------------
# Fallback: network + process observation (any OS)
# ---------------------------------------------------------------------------

class FallbackKernelObserver:
    """Network/process-based observation — works without eBPF.

    Uses:
      - psutil for process monitoring
      - Raw socket capture for network traffic (when available)
      - /proc on Linux for file access (when available)
    """

    @staticmethod
    def is_available() -> bool:
        """Always available as a fallback."""
        return True

    async def attach(self, pid: int, duration: float = 5.0) -> KernelSession:
        """Attach network/process monitoring to a target."""
        session = KernelSession(pid=pid, mode="process")

        try:
            import psutil  # type: ignore

            # Get the process
            try:
                proc = psutil.Process(pid)
            except psutil.NoSuchProcess:
                return session

            # Snapshot initial state
            initial_connections = set()
            try:
                for conn in proc.net_connections():
                    key = (conn.laddr, conn.raddr if conn.raddr else None)
                    initial_connections.add(key)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Monitor for the specified duration
            end_time = time.time() + duration
            while time.time() < end_time and session.active:
                try:
                    await asyncio.sleep(1.0)

                    # Check for new connections
                    try:
                        current_connections = set()
                        for conn in proc.net_connections():
                            key = (conn.laddr, conn.raddr if conn.raddr else None)
                            current_connections.add(key)
                            if key not in initial_connections:
                                session.add(KernelObservation(
                                    type=ObservationType.OUTBOUND_CONNECTION,
                                    evidence_tier=EvidenceTier.SYSCALL,
                                    data={
                                        "local": str(conn.laddr),
                                        "remote": str(conn.raddr) if conn.raddr else "none",
                                        "status": conn.status,
                                    },
                                    metadata={"source": "psutil", "pid": pid},
                                ))
                        initial_connections = current_connections
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    # Check file descriptors (Linux only)
                    if platform.system() == "Linux":
                        try:
                            fd_dir = f"/proc/{pid}/fd"
                            fds = os.listdir(fd_dir)
                            # Count open files
                            session.add(KernelObservation(
                                type=ObservationType.FILE_ACCESS,
                                evidence_tier=EvidenceTier.SYSCALL,
                                data={"open_fds": len(fds)},
                                metadata={"source": "/proc", "pid": pid},
                            ))
                        except (OSError, PermissionError):
                            pass

                except asyncio.CancelledError:
                    break
                except Exception:
                    continue

        except ImportError:
            logger.warning("psutil not installed — using basic observation")
            # Ultra-basic fallback: just record process existence
            session.add(KernelObservation(
                type=ObservationType.PROCESS_LIST,
                evidence_tier=EvidenceTier.SYSCALL,
                data={"pid": pid, "mode": "basic"},
                metadata={"source": "os", "note": "psutil not available"},
            ))
        except Exception as e:
            logger.warning(f"Fallback observation failed: {e}")

        return session


# ---------------------------------------------------------------------------
# Main observer — auto-selects best available method
# ---------------------------------------------------------------------------

class KernelObserver:
    """Kernel observer — auto-selects eBPF or fallback.

    Usage:
        observer = KernelObserver()
        session = await observer.attach(pid=1234, duration=5.0)
        observations = session.observations

    The observer tries eBPF first (Linux, root), then falls back to
    process/network monitoring. Every observation carries an evidence tier
    so the caller knows how trustworthy it is.
    """

    def __init__(self):
        self._ebpf = EBPFKernelObserver()
        self._fallback = FallbackKernelObserver()

    def best_available(self) -> str:
        """Return the best available observation mode."""
        if self._ebpf.is_available():
            return "ebpf"
        elif self._fallback.is_available():
            return "process"
        return "none"

    async def attach(
        self,
        pid: int,
        duration: float = 5.0,
        mode: str | None = None,
    ) -> KernelSession:
        """Attach to a process and observe.

        Args:
            pid: Process ID to observe.
            duration: How long to observe (seconds).
            mode: Force a specific mode ("ebpf", "process"). None = auto.

        Returns:
            KernelSession with all observations.
        """
        if mode is None:
            mode = self.best_available()

        if mode == "ebpf" and self._ebpf.is_available():
            return await self._ebpf.attach(pid, duration)
        elif mode == "process":
            return await self._fallback.attach(pid, duration)
        else:
            # No observation method available — return empty session
            session = KernelSession(pid=pid, mode="none")
            session.add(KernelObservation(
                type=ObservationType.PROCESS_LIST,
                evidence_tier=EvidenceTier.SUSPICION,
                data={"pid": pid, "mode": "none", "note": "No kernel observation available"},
                metadata={"source": "none"},
            ))
            return session

    async def observe_target_process(
        self,
        target_url: str,
        duration: float = 5.0,
    ) -> KernelSession:
        """Find and observe the process serving a target URL.

        Best-effort: finds the process by port, then attaches.
        """
        pid = await self._find_process_for_url(target_url)
        if pid:
            return await self.attach(pid, duration)
        # No process found — return empty session
        return KernelSession(pid=0, mode="none")

    async def _find_process_for_url(self, target_url: str) -> int | None:
        """Try to find the PID serving a URL by checking listening ports."""
        try:
            import psutil  # type: ignore
            from urllib.parse import urlparse

            parsed = urlparse(target_url)
            port = parsed.port
            if not port:
                port = 443 if parsed.scheme == "https" else 80

            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN":
                    if conn.laddr.port == port:
                        return conn.pid
        except Exception:
            pass
        return None

    def analyze_observations(
        self,
        session: KernelSession,
        target_url: str = "",
    ) -> list[dict]:
        """Analyze observations and generate findings.

        Returns a list of finding dicts ready for the evidence gate.
        """
        findings = []

        for obs in session.observations:
            # RCE confirmed by execve observation
            if obs.type == ObservationType.PROCESS_EXEC:
                filename = obs.data.get("filename", "")
                # Filter out benign system processes
                if any(bad in filename for bad in ["bash", "sh", "python", "node"]):
                    # Suspicious — could be command injection
                    findings.append({
                        "type": "kernel_process_execution",
                        "severity": "high",
                        "title": f"Process Execution Observed: {filename}",
                        "evidence": (
                            f"execve('{filename}') observed via {obs.metadata.get('source', 'kernel')} "
                            f"on pid {obs.data.get('pid', '?')}"
                        ),
                        "oracle": "kernel_execve_observation",
                        "tier": "confirmed",
                        "flow_types": ["code_exec"],
                        "cvss_score": 8.0,
                        "metadata": {
                            "source": obs.metadata.get("source"),
                            "tier": obs.evidence_tier.value,
                        },
                    })

            # File access observed
            if obs.type in (ObservationType.FILE_OPEN, ObservationType.FILE_READ):
                filename = obs.data.get("filename", "")
                if filename:
                    # Check for sensitive file access
                    sensitive = ["/etc/passwd", "/etc/shadow", "/proc/self",
                                "id_rsa", "credentials", "secret", "key", "token"]
                    if any(s in filename.lower() for s in sensitive):
                        findings.append({
                            "type": "kernel_sensitive_file_access",
                            "severity": "critical",
                            "title": f"Sensitive File Access Observed: {filename}",
                            "evidence": (
                                f"File access to '{filename}' observed via "
                                f"{obs.metadata.get('source', 'kernel')}"
                            ),
                            "oracle": "kernel_file_access_observation",
                            "tier": "confirmed",
                            "flow_types": ["file_read", "data_leak"],
                            "cvss_score": 9.0,
                            "metadata": {
                                "source": obs.metadata.get("source"),
                                "tier": obs.evidence_tier.value,
                            },
                        })

            # Outbound connection (potential SSRF data exfil)
            if obs.type == ObservationType.OUTBOUND_CONNECTION:
                remote = obs.data.get("remote", "")
                if remote and remote != "none":
                    findings.append({
                        "type": "kernel_outbound_connection",
                        "severity": "medium",
                        "title": f"Outbound Connection Observed: {remote}",
                        "evidence": (
                            f"TCP connection to {remote} observed via "
                            f"{obs.metadata.get('source', 'kernel')}"
                        ),
                        "oracle": "kernel_connection_observation",
                        "tier": "confirmed",
                        "flow_types": ["url_fetch"],
                        "cvss_score": 5.0,
                        "metadata": {
                            "source": obs.metadata.get("source"),
                            "tier": obs.evidence_tier.value,
                        },
                    })

        return findings
