import threading
import time
from typing import Any, Dict, List, Optional

from .logger import setup_logger, json_log
from .rules import load_config, save_config, Rule, RuleSet
from .iptables import ensure_chains, apply_rules, delete_chains, add_runtime_block, remove_runtime_rule
from .sniffer import Sniffer
from .utils import is_root

class AutoBlockManager:
    def __init__(self, logger, block_minutes: int = 10):
        self.logger = logger
        self.block_minutes = int(block_minutes)
        self.runtime_blocks: Dict[str, List[str]] = {}  # ip -> spec
        self.lock = threading.Lock()

    def block(self, ip: str, direction: str) -> None:
        with self.lock:
            if ip in self.runtime_blocks:
                return
            spec = add_runtime_block(ip, direction)  # returns [chain, "-s", ip, "-j", "DROP"]
            self.runtime_blocks[ip] = spec
            json_log(self.logger, "auto_block", {"ip": ip, "direction": direction, "minutes": self.block_minutes}, "warning")
            timer = threading.Timer(self.block_minutes * 60, self.unblock, args=(ip,))
            timer.daemon = True
            timer.start()

    def unblock(self, ip: str) -> None:
        with self.lock:
            spec = self.runtime_blocks.pop(ip, None)
        if spec:
            remove_runtime_rule(spec)
            json_log(self.logger, "auto_unblock", {"ip": ip}, "info")

    def clear(self) -> None:
        with self.lock:
            keys = list(self.runtime_blocks.keys())
        for ip in keys:
            self.unblock(ip)

class Firewall:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.cfg: Dict[str, Any] = load_config(self.config_path)
        logging_cfg = self.cfg.get("logging", {})
        self.logger = setup_logger(logging_cfg.get("directory", "logs"), logging_cfg.get("level", "INFO"))
        self.active_profile: str = self.cfg.get("active_profile", "home")
        self.ruleset: RuleSet = self.cfg["ruleset"]
        self.sniffer: Optional[Sniffer] = None
        self.auto_block_mgr: Optional[AutoBlockManager] = None
        self.enforcing: bool = False
        self.monitoring: bool = False

    def start(self, enforce: bool = True, monitor: bool = True) -> None:
        if not is_root():
            raise PermissionError("Root privileges are required. Run with sudo.")
        self.active_profile = self.cfg.get("active_profile", "home")

        if enforce:
            ensure_chains()
            dp = self.cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
            apply_rules(self.ruleset, self.active_profile, dp.get("inbound", "ALLOW"), dp.get("outbound", "ALLOW"))
            self.enforcing = True
            json_log(self.logger, "enforcement", {"status": "started"}, "info")

        auto_cfg = self.cfg.get("auto_block", {})
        if monitor:
            self.auto_block_mgr = AutoBlockManager(self.logger, block_minutes=auto_cfg.get("block_minutes", 10)) if auto_cfg.get("enabled", True) else None
            self.sniffer = Sniffer(
                iface=self.cfg.get("sniff", {}).get("iface", "any"),
                bpf=self.cfg.get("sniff", {}).get("bpf", "tcp or udp or icmp"),
                logger=self.logger,
                evaluator=self.evaluate_packet,
                auto_block_handler=(self.auto_block_mgr.block if self.auto_block_mgr else None),
                auto_block_cfg=auto_cfg
            )
            self.sniffer.start()
            self.monitoring = True
            json_log(self.logger, "monitor", {"status": "started"}, "info")

    def stop(self) -> None:
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.monitoring = False
            json_log(self.logger, "monitor", {"status": "stopped"}, "info")

        if self.auto_block_mgr:
            self.auto_block_mgr.clear()
            self.auto_block_mgr = None

        if self.enforcing:
            delete_chains()
            self.enforcing = False
            json_log(self.logger, "enforcement", {"status": "stopped"}, "info")

    def reload(self) -> None:
        self.cfg = load_config(self.config_path)
        self.active_profile = self.cfg.get("active_profile", "home")
        self.ruleset = self.cfg["ruleset"]
        if self.enforcing:
            dp = self.cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
            apply_rules(self.ruleset, self.active_profile, dp.get("inbound", "ALLOW"), dp.get("outbound", "ALLOW"))
        json_log(self.logger, "reload", {"status": "ok"}, "info")

    def evaluate_packet(self, direction: str, meta: Dict[str, str]) -> Optional[Dict[str, str]]:
        # Simulated decision (for logging) according to rule priority
        # Returns {"matched_rule": id, "decision": "ALLOW"/"BLOCK"} if any rule matches
        # Note: Kernel enforcement is via iptables; this is for audit/visibility.
        proto = meta.get("protocol", "OTHER").upper()
        src_ip = meta.get("src", "")
        dst_ip = meta.get("dst", "")
        src_port = meta.get("src_port", "")
        dst_port = meta.get("dst_port", "")
        active_rules = self.ruleset.filter(self.active_profile)

        for r in active_rules:
            if r.direction not in ("ANY", direction):
                continue
            if r.protocol != "ANY" and r.protocol != proto:
                continue
            if r.src_ip and not _cidr_match(src_ip, r.src_ip):
                continue
            if r.dst_ip and not _cidr_match(dst_ip, r.dst_ip):
                continue
            # Ports
            if r.src_port and not _port_match(src_port, r.src_port):
                continue
            if r.dst_port and not _port_match(dst_port, r.dst_port):
                continue
            return {"matched_rule": r.id, "decision": r.action}
        # No match; reflect default policy
        dp = self.cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
        default = dp.get("inbound", "ALLOW") if direction == "INCOMING" else dp.get("outbound", "ALLOW")
        return {"matched_rule": "", "decision": default}

    def list_rules(self) -> List[Rule]:
        return self.ruleset.rules

    def add_rule(self, rule: Rule) -> Rule:
        self.ruleset.add_rule(rule)
        save_config(self.config_path, self.cfg)
        if self.enforcing:
            dp = self.cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
            apply_rules(self.ruleset, self.active_profile, dp.get("inbound", "ALLOW"), dp.get("outbound", "ALLOW"))
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        removed = self.ruleset.remove_rule(rule_id)
        if removed:
            save_config(self.config_path, self.cfg)
            if self.enforcing:
                dp = self.cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
                apply_rules(self.ruleset, self.active_profile, dp.get("inbound", "ALLOW"), dp.get("outbound", "ALLOW"))
        return removed

    def set_policy(self, inbound: Optional[str] = None, outbound: Optional[str] = None) -> None:
        dp = self.cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
        if inbound:
            dp["inbound"] = inbound.upper()
        if outbound:
            dp["outbound"] = outbound.upper()
        self.cfg["default_policy"] = dp
        save_config(self.config_path, self.cfg)
        if self.enforcing:
            apply_rules(self.ruleset, self.active_profile, dp.get("inbound", "ALLOW"), dp.get("outbound", "ALLOW"))

    def switch_profile(self, profile: str) -> None:
        self.cfg["active_profile"] = profile
        self.active_profile = profile
        save_config(self.config_path, self.cfg)
        if self.enforcing:
            dp = self.cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
            apply_rules(self.ruleset, self.active_profile, dp.get("inbound", "ALLOW"), dp.get("outbound", "ALLOW"))

def _cidr_match(ip: str, cidr: str) -> bool:
    # Simple match: if cidr is exact IP or x.x.x.x/y
    # We avoid adding extra deps; for correctness, fallback to string equality if not CIDR
    if "/" not in cidr:
        return ip == cidr
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False

def _port_match(port_str: str, spec: str) -> bool:
    if not port_str:
        return False
    try:
        port = int(port_str)
    except ValueError:
        return False
    # spec like "80,443,1000:2000"
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" in token:
            a, b = token.split(":", 1)
            try:
                low = int(a)
                high = int(b)
                if low <= port <= high:
                    return True
            except Exception:
                continue
        else:
            try:
                if int(token) == port:
                    return True
            except Exception:
                continue
    return False
