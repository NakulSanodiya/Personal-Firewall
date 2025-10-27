from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import uuid
import yaml

Action = str  # "ALLOW" | "BLOCK"
Direction = str  # "INCOMING" | "OUTGOING" | "ANY"
Protocol = str  # "TCP" | "UDP" | "ICMP" | "ANY"

VALID_ACTIONS = {"ALLOW", "BLOCK"}
VALID_DIRECTIONS = {"INCOMING", "OUTGOING", "ANY"}
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "ANY"}

@dataclass
class Rule:
    id: str
    description: str = ""
    action: Action = "BLOCK"
    direction: Direction = "ANY"
    protocol: Protocol = "ANY"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[str] = None  # supports "80", "80,443", "1000:2000"
    dst_port: Optional[str] = None
    interface: Optional[str] = None
    priority: int = 100
    log: bool = False
    enabled: bool = True
    profiles: List[str] = field(default_factory=lambda: ["home", "office", "public"])

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Rule":
        rid = d.get("id") or str(uuid.uuid4())
        rule = Rule(
            id=str(rid),
            description=d.get("description", ""),
            action=d.get("action", "BLOCK").upper(),
            direction=d.get("direction", "ANY").upper(),
            protocol=d.get("protocol", "ANY").upper(),
            src_ip=d.get("src_ip"),
            dst_ip=d.get("dst_ip"),
            src_port=_normalize_ports(d.get("src_port")),
            dst_port=_normalize_ports(d.get("dst_port")),
            interface=d.get("interface"),
            priority=int(d.get("priority", 100)),
            log=bool(d.get("log", False)),
            enabled=bool(d.get("enabled", True)),
            profiles=list(d.get("profiles", ["home", "office", "public"])),
        )
        _validate_rule(rule)
        return rule

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "action": self.action,
            "direction": self.direction,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "interface": self.interface,
            "priority": self.priority,
            "log": self.log,
            "enabled": self.enabled,
            "profiles": self.profiles,
        }

def _normalize_ports(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, int):
        return str(val)
    if isinstance(val, list):
        return ",".join(str(x) for x in val)
    s = str(val).strip()
    return s if s else None

def _validate_rule(rule: Rule) -> None:
    if rule.action not in VALID_ACTIONS:
        raise ValueError(f"Invalid action: {rule.action}")
    if rule.direction not in VALID_DIRECTIONS:
        raise ValueError(f"Invalid direction: {rule.direction}")
    if rule.protocol not in VALID_PROTOCOLS:
        raise ValueError(f"Invalid protocol: {rule.protocol}")
    # Ports only meaningful for TCP/UDP/ANY
    if rule.protocol == "ICMP" and (rule.src_port or rule.dst_port):
        raise ValueError("ICMP does not support ports")
    if rule.interface and not isinstance(rule.interface, str):
        raise ValueError("interface must be a string")

class RuleSet:
    def __init__(self, rules: List[Rule]) -> None:
        self.rules: List[Rule] = sorted(rules, key=lambda r: (r.priority, r.id))

    def filter(self, active_profile: str) -> List[Rule]:
        return [r for r in self.rules if r.enabled and (active_profile in r.profiles or "all" in [p.lower() for p in r.profiles])]

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)
        self.rules.sort(key=lambda r: (r.priority, r.id))

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id]
        return len(self.rules) < before

    def get(self, rule_id: str) -> Optional[Rule]:
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def to_list(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.rules]

def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    rules = [Rule.from_dict(r) for r in data.get("rules", [])]
    rs = RuleSet(rules)
    cfg = {
        "active_profile": data.get("active_profile", "home"),
        "default_policy": data.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"}),
        "sniff": data.get("sniff", {"iface": "any", "bpf": "tcp or udp or icmp"}),
        "auto_block": data.get("auto_block", {"enabled": True, "window_seconds": 5, "distinct_ports_threshold": 12, "block_minutes": 10, "directions": ["INCOMING"]}),
        "logging": data.get("logging", {"directory": "logs", "level": "INFO"}),
        "ruleset": rs,
        "raw": data,
    }
    return cfg

def save_config(path: str, cfg: Dict[str, Any]) -> None:
    data = cfg.get("raw", {})
    # Replace rules with current ruleset
    ruleset: RuleSet = cfg["ruleset"]
    data["rules"] = ruleset.to_list()
    data["active_profile"] = cfg.get("active_profile", "home")
    data["default_policy"] = cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
    data["sniff"] = cfg.get("sniff", {"iface": "any", "bpf": "tcp or udp or icmp"})
    data["auto_block"] = cfg.get("auto_block", {})
    data["logging"] = cfg.get("logging", {})
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)
