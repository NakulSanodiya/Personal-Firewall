import subprocess
from typing import List, Optional, Tuple

from .rules import Rule, RuleSet
from .utils import run_cmd

PFW_INPUT = "PFW_INPUT"
PFW_OUTPUT = "PFW_OUTPUT"

def _iptables_exists() -> bool:
    try:
        run_cmd(["iptables", "-V"], check=True)
        return True
    except Exception:
        return False

def ensure_chains() -> None:
    if not _iptables_exists():
        raise RuntimeError("iptables not found. Install it and ensure it's in PATH.")
    # Create chains if they do not exist
    for chain in (PFW_INPUT, PFW_OUTPUT):
        try:
            run_cmd(["iptables", "-nL", chain], check=True)
        except subprocess.CalledProcessError:
            run_cmd(["iptables", "-N", chain], check=True)
    # Hook into INPUT/OUTPUT
    _ensure_hook("INPUT", PFW_INPUT)
    _ensure_hook("OUTPUT", PFW_OUTPUT)

def _ensure_hook(base_chain: str, hook_chain: str) -> None:
    # If not already hooked, insert at top
    try:
        run_cmd(["iptables", "-C", base_chain, "-j", hook_chain], check=True)
    except subprocess.CalledProcessError:
        run_cmd(["iptables", "-I", base_chain, "1", "-j", hook_chain], check=True)

def flush_chains() -> None:
    for chain in (PFW_INPUT, PFW_OUTPUT):
        run_cmd(["iptables", "-F", chain], check=True)

def delete_chains() -> None:
    # Remove hooks
    for base, hook in (("INPUT", PFW_INPUT), ("OUTPUT", PFW_OUTPUT)):
        # Delete all references
        while True:
            try:
                run_cmd(["iptables", "-D", base, "-j", hook], check=True)
            except subprocess.CalledProcessError:
                break
    # Flush and delete chains
    for chain in (PFW_INPUT, PFW_OUTPUT):
        try:
            run_cmd(["iptables", "-F", chain], check=False)
            run_cmd(["iptables", "-X", chain], check=False)
        except Exception:
            pass

def apply_rules(ruleset: RuleSet, active_profile: str, default_inbound: str, default_outbound: str) -> None:
    ensure_chains()
    flush_chains()

    # Add rules in priority order
    for rule in ruleset.filter(active_profile):
        for chain in _chains_for_direction(rule.direction):
            rule_cmds = _rule_to_iptables_commands(rule, chain)
            for cmd in rule_cmds:
                run_cmd(cmd, check=True)

    # Default policy bottom catch-all
    # For user-defined chains, we can't set a default policy; add a final rule.
    if default_inbound.upper() == "BLOCK":
        run_cmd(["iptables", "-A", PFW_INPUT, "-j", "DROP"], check=True)
    else:
        run_cmd(["iptables", "-A", PFW_INPUT, "-j", "RETURN"], check=True)

    if default_outbound.upper() == "BLOCK":
        run_cmd(["iptables", "-A", PFW_OUTPUT, "-j", "DROP"], check=True)
    else:
        run_cmd(["iptables", "-A", PFW_OUTPUT, "-j", "RETURN"], check=True)

def _chains_for_direction(direction: str) -> List[str]:
    direction = direction.upper()
    if direction == "INCOMING":
        return [PFW_INPUT]
    if direction == "OUTGOING":
        return [PFW_OUTPUT]
    return [PFW_INPUT, PFW_OUTPUT]

def _rule_to_iptables_commands(rule: Rule, chain: str) -> List[List[str]]:
    # Returns one or more iptables commands (list of tokens)
    base: List[str] = ["iptables", "-A", chain]
    cmds: List[List[str]] = []

    # Direction-specific interface flags
    if rule.interface:
        if chain == PFW_INPUT:
            base += ["-i", rule.interface]
        elif chain == PFW_OUTPUT:
            base += ["-o", rule.interface]

    # IPs
    if rule.src_ip:
        base += ["-s", rule.src_ip]
    if rule.dst_ip:
        base += ["-d", rule.dst_ip]

    protos: List[str]
    if rule.protocol == "ANY":
        # If ports specified, apply to TCP and UDP; otherwise add generic rule
        if rule.src_port or rule.dst_port:
            protos = ["tcp", "udp"]
        else:
            protos = ["all"]
    else:
        protos = [rule.protocol.lower()]

    for proto in protos:
        cmd = list(base)
        if proto != "all":
            cmd += ["-p", proto]

        # Ports (only valid for TCP/UDP)
        if proto in ("tcp", "udp"):
            if rule.src_port:
                cmd += ["-m", "multiport", "--sports", rule.src_port]
            if rule.dst_port:
                cmd += ["-m", "multiport", "--dports", rule.dst_port]

        # Logging
        if rule.log:
            log_cmd = list(cmd)
            log_cmd += ["-m", "limit", "--limit", "5/second", "--limit-burst", "10"]
            log_cmd += ["-j", "LOG", "--log-prefix", f"PFW {rule.id} "]
            cmds.append(log_cmd)

        # Action
        action = "ACCEPT" if rule.action == "ALLOW" else "DROP"
        act_cmd = list(cmd) + ["-j", action]
        cmds.append(act_cmd)

    return cmds

def add_runtime_block(ip: str, direction: str) -> List[str]:
    """
    Insert a top-of-chain DROP for a single IP, return the exact spec for later deletion.
    """
    chain = PFW_INPUT if direction.upper() == "INCOMING" else PFW_OUTPUT
    spec = ["-s", ip, "-j", "DROP"]
    cmd = ["iptables", "-I", chain, "1"] + spec
    run_cmd(cmd, check=True)
    return [chain] + spec

def remove_runtime_rule(spec: List[str]) -> None:
    """
    Remove a runtime rule by spec returned from add_runtime_block.
    spec format: [chain, "-s", ip, "-j", "DROP"]
    """
    chain = spec[0]
    rule_spec = spec[1:]
    cmd = ["iptables", "-D", chain] + rule_spec
    try:
        run_cmd(cmd, check=True)
    except subprocess.CalledProcessError:
        # Already removed
        pass
