import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Optional, Set, Tuple

from scapy.all import sniff, IP, TCP, UDP, ICMP  # type: ignore

from .utils import get_local_ipv4_addresses
from .logger import json_log

class Sniffer:
    def __init__(
        self,
        iface: str,
        bpf: str,
        logger,
        evaluator: Callable[[str, Dict[str, str]], Optional[Dict[str, str]]],
        auto_block_handler: Optional[Callable[[str, str], None]] = None,
        auto_block_cfg: Optional[Dict[str, object]] = None,
    ):
        self.iface = iface
        self.bpf = bpf
        self.logger = logger
        self.evaluator = evaluator
        self.auto_block_handler = auto_block_handler
        self.auto_block_cfg = auto_block_cfg or {}
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.local_ips: Set[str] = get_local_ipv4_addresses()
        # Auto-block: track source -> deque of (timestamp, dst_port)
        self.window_seconds: int = int(self.auto_block_cfg.get("window_seconds", 5))
        self.distinct_ports_threshold: int = int(self.auto_block_cfg.get("distinct_ports_threshold", 12))
        self.monitor_directions = set([str(x).upper() for x in self.auto_block_cfg.get("directions", ["INCOMING"])])

        self.port_windows: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

    def start(self) -> None:
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="PFW-Sniffer", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)

    def _run(self) -> None:
        # Start sniffing
        sniff(
            iface=self.iface,
            filter=self.bpf,
            prn=self._on_packet,
            store=False,
            stop_filter=lambda x: self.stop_event.is_set(),
        )

    def _on_packet(self, pkt) -> None:
        try:
            if not IP in pkt:
                return
            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst

            direction = "INCOMING" if dst in self.local_ips else ("OUTGOING" if src in self.local_ips else "OTHER")
            proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else ("ICMP" if ICMP in pkt else "OTHER"))

            src_port = None
            dst_port = None
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            meta = {
                "src": src,
                "dst": dst,
                "direction": direction,
                "protocol": proto,
                "src_port": str(src_port) if src_port else "",
                "dst_port": str(dst_port) if dst_port else "",
            }

            # Evaluate against rules for logging
            decision = self.evaluator(direction, meta) or {}
            json_log(self.logger, "packet", {**meta, **decision})

            # Auto-block (port scan detection) for incoming only by default
            if self.auto_block_handler and direction in self.monitor_directions and dst in self.local_ips and dst_port:
                self._track_and_maybe_block(src, int(dst_port))
        except Exception as e:
            self.logger.debug(f"Sniffer error: {e}")

    def _track_and_maybe_block(self, src_ip: str, dst_port: int) -> None:
        now = time.time()
        dq = self.port_windows[src_ip]
        dq.append((now, dst_port))
        # Clean old
        while dq and now - dq[0][0] > self.window_seconds:
            dq.popleft()
        # Count distinct ports in window
        distinct_ports = {p for (_, p) in dq}
        if len(distinct_ports) >= self.distinct_ports_threshold:
            # Trigger block
            if self.auto_block_handler:
                self.auto_block_handler(src_ip, "INCOMING")
            # Reset window to prevent repeated triggers
            dq.clear()
