"""Network Traffic Observer — Capture and analyze network traffic.

Captures network traffic during scans to provide ground-truth evidence
of SSRF targets, data exfiltration, C2 channels, and other network-level
observations.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class NetworkPacket:
    """A captured network packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes = b""
    length: int = 0


@dataclass
class TrafficCapture:
    """A capture of network traffic."""
    packets: list[NetworkPacket] = field(default_factory=list)
    duration: float = 0.0
    interface: str = ""
    filter: str = ""


@dataclass
class SSRFEvidence:
    """Evidence of SSRF from captured traffic."""
    target_ip: str
    target_port: int
    request_url: str
    response_seen: bool
    internal: bool  # Is this an internal IP?


@dataclass
class ExfiltrationEvidence:
    """Evidence of data exfiltration."""
    destination: str
    data_size: int
    protocol: str
    suspicious: bool


class NetworkObserver:
    """Capture and analyze network traffic for evidence.

    Uses scapy (preferred) or tcpdump for packet capture.
    Analyzes captured traffic for SSRF, exfiltration, and C2 patterns.
    """

    # RFC 1918 private IP ranges
    PRIVATE_RANGES = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("127.0.0.0", "127.255.255.255"),
        ("169.254.0.0", "169.254.255.255"),  # Link-local / IMDS
    ]

    # Cloud metadata IPs
    CLOUD_METADATA_IPS = {
        "169.254.169.254",  # AWS/GCP/Azure IMDS
        "169.254.169.250",  # GCP metadata
        "fd00::2",          # AWS IPv6 IMDS
    }

    async def capture(
        self,
        interface: str = "eth0",
        duration: float = 10.0,
        bpf_filter: str = "",
    ) -> TrafficCapture:
        """Capture network traffic using scapy."""
        capture = TrafficCapture(
            interface=interface,
            duration=duration,
            filter=bpf_filter,
        )

        try:
            from scapy.all import sniff, IP, TCP, UDP

            start = time.time()

            def packet_handler(pkt):
                if IP in pkt:
                    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
                    pkt_info = NetworkPacket(
                        timestamp=time.time(),
                        src_ip=pkt[IP].src,
                        dst_ip=pkt[IP].dst,
                        src_port=pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
                        dst_port=pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
                        protocol=proto,
                        length=len(pkt),
                    )
                    capture.packets.append(pkt_info)

            sniff(
                iface=interface,
                filter=bpf_filter or None,
                prn=packet_handler,
                timeout=duration,
                store=False,
            )

            capture.duration = time.time() - start
            logger.info(f"Captured {len(capture.packets)} packets in {capture.duration:.1f}s")

        except ImportError:
            logger.warning("scapy not installed. Install: pip install scapy")
        except Exception as e:
            logger.warning(f"Packet capture failed: {e}")

        return capture

    def analyze_ssrf(self, capture: TrafficCapture) -> list[SSRFEvidence]:
        """Extract SSRF evidence from captured traffic."""
        evidence = []
        seen = set()

        for pkt in capture.packets:
            key = (pkt.dst_ip, pkt.dst_port)
            if key in seen:
                continue
            seen.add(key)

            is_internal = self._is_private_ip(pkt.dst_ip)
            is_metadata = pkt.dst_ip in self.CLOUD_METADATA_IPS

            if is_internal or is_metadata:
                evidence.append(SSRFEvidence(
                    target_ip=pkt.dst_ip,
                    target_port=pkt.dst_port,
                    request_url=f"{pkt.protocol}://{pkt.dst_ip}:{pkt.dst_port}",
                    response_seen=True,
                    internal=True,
                ))

        return evidence

    def analyze_exfiltration(self, capture: TrafficCapture) -> list[ExfiltrationEvidence]:
        """Detect potential data exfiltration."""
        evidence = []

        # Aggregate by destination
        dest_stats: dict[str, dict] = {}
        for pkt in capture.packets:
            if pkt.dst_port in (80, 443, 8080, 8443):
                dest = f"{pkt.dst_ip}:{pkt.dst_port}"
                if dest not in dest_stats:
                    dest_stats[dest] = {"total_bytes": 0, "packets": 0, "protocols": set()}
                dest_stats[dest]["total_bytes"] += pkt.length
                dest_stats[dest]["packets"] += 1
                dest_stats[dest]["protocols"].add(pkt.protocol)

        # Flag destinations with unusual outbound volume
        for dest, stats in dest_stats.items():
            if stats["total_bytes"] > 100000 and stats["packets"] > 50:  # >100KB, >50 packets
                evidence.append(ExfiltrationEvidence(
                    destination=dest,
                    data_size=stats["total_bytes"],
                    protocol=list(stats["protocols"])[0] if stats["protocols"] else "unknown",
                    suspicious=True,
                ))

        return evidence

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP is in a private range."""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False
