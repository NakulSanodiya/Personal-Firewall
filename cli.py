import argparse
import sys
from typing import Optional

from tabulate import tabulate

from .core import Firewall
from .rules import Rule

def main() -> None:
    parser = argparse.ArgumentParser(prog="pfw", description="Personal Firewall (Python + iptables + Scapy)")
    parser.set_defaults(func=lambda args: parser.print_help())
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")

    sub = parser.add_subparsers()

    # start
    p_start = sub.add_parser("start", help="Start firewall (enforcement + monitoring)")
    p_start.add_argument("--no-enforce", action="store_true", help="Do not enforce iptables rules")
    p_start.add_argument("--no-monitor", action="store_true", help="Do not start packet monitor")
    p_start.set_defaults(func=cmd_start)

    # stop
    p_stop = sub.add_parser("stop", help="Stop firewall and cleanup iptables hooks")
    p_stop.set_defaults(func=cmd_stop)

    # status
    p_status = sub.add_parser("status", help="Show firewall status")
    p_status.set_defaults(func=cmd_status)

    # reload
    p_reload = sub.add_parser("reload", help="Reload config and reapply rules")
    p_reload.set_defaults(func=cmd_reload)

    # rules list/add/delete
    p_rules = sub.add_parser("rules", help="Manage rules")
    rsub = p_rules.add_subparsers()

    p_rules_list = rsub.add_parser("list", help="List rules")
    p_rules_list.set_defaults(func=cmd_rules_list)

    p_rules_add = rsub.add_parser("add", help="Add rule")
    p_rules_add.add_argument("--id", default="", help="Rule ID (optional)")
    p_rules_add.add_argument("--description", default="", help="Description")
    p_rules_add.add_argument("--action", required=True, choices=["ALLOW", "BLOCK"])
    p_rules_add.add_argument("--direction", required=True, choices=["INCOMING", "OUTGOING", "ANY"])
    p_rules_add.add_argument("--protocol", default="ANY", choices=["TCP", "UDP", "ICMP", "ANY"])
    p_rules_add.add_argument("--src-ip", default=None)
    p_rules_add.add_argument("--dst-ip", default=None)
    p_rules_add.add_argument("--src-port", default=None)
    p_rules_add.add_argument("--dst-port", default=None)
    p_rules_add.add_argument("--interface", default=None)
    p_rules_add.add_argument("--priority", type=int, default=100)
    p_rules_add.add_argument("--log", action="store_true")
    p_rules_add.add_argument("--enabled", action="store_true")
    p_rules_add.add_argument("--profiles", default="home,office,public", help="Comma-separated profiles")
    p_rules_add.set_defaults(func=cmd_rules_add)

    p_rules_del = rsub.add_parser("delete", help="Delete rule by ID")
    p_rules_del.add_argument("--id", required=True)
    p_rules_del.set_defaults(func=cmd_rules_delete)

    # policy
    p_policy = sub.add_parser("policy", help="View or set default policy")
    p_policy.add_argument("--inbound", choices=["ALLOW", "BLOCK"])
    p_policy.add_argument("--outbound", choices=["ALLOW", "BLOCK"])
    p_policy.set_defaults(func=cmd_policy)

    # profile
    p_profile = sub.add_parser("profile", help="Switch or show profile")
    p_profile.add_argument("--switch", help="Profile name to switch to")
    p_profile.set_defaults(func=cmd_profile)

    # gui
    p_gui = sub.add_parser("gui", help="Launch GUI")
    p_gui.set_defaults(func=cmd_gui)

    args = parser.parse_args()
    return args.func(args)

def load_fw(args) -> Firewall:
    return Firewall(args.config)

def cmd_start(args) -> None:
    fw = load_fw(args)
    fw.start(enforce=not args.no_enforce, monitor=not args.no_monitor)

def cmd_stop(args) -> None:
    fw = load_fw(args)
    fw.stop()

def cmd_status(args) -> None:
    fw = load_fw(args)
    rules = fw.list_rules()
    print(f"Active profile: {fw.active_profile}")
    print(f"Rules total: {len(rules)}")
    headers = ["Priority", "ID", "Action", "Dir", "Proto", "Src IP", "Src Port", "Dst IP", "Dst Port", "If", "Log", "Enabled", "Profiles"]
    rows = []
    for r in rules:
        rows.append([r.priority, r.id, r.action, r.direction, r.protocol, r.src_ip or "", r.src_port or "", r.dst_ip or "", r.dst_port or "", r.interface or "", r.log, r.enabled, ",".join(r.profiles)])
    print(tabulate(rows, headers=headers, tablefmt="github"))

def cmd_reload(args) -> None:
    fw = load_fw(args)
    fw.reload()

def cmd_rules_list(args) -> None:
    fw = load_fw(args)
    rules = fw.list_rules()
    headers = ["Priority", "ID", "Action", "Dir", "Proto", "Src IP", "Src Port", "Dst IP", "Dst Port", "If", "Log", "Enabled", "Profiles"]
    rows = []
    for r in rules:
        rows.append([r.priority, r.id, r.action, r.direction, r.protocol, r.src_ip or "", r.src_port or "", r.dst_ip or "", r.dst_port or "", r.interface or "", r.log, r.enabled, ",".join(r.profiles)])
    print(tabulate(rows, headers=headers, tablefmt="github"))

def cmd_rules_add(args) -> None:
    fw = load_fw(args)
    r = Rule.from_dict({
        "id": args.id or None,
        "description": args.description,
        "action": args.action,
        "direction": args.direction,
        "protocol": args.protocol,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "src_port": args.src_port,
        "dst_port": args.dst_port,
        "interface": args.interface,
        "priority": args.priority,
        "log": args.log,
        "enabled": args.enabled or True,
        "profiles": [p.strip() for p in args.profiles.split(",") if p.strip()],
    })
    fw.add_rule(r)
    print(f"Added rule {r.id}")

def cmd_rules_delete(args) -> None:
    fw = load_fw(args)
    if fw.delete_rule(args.id):
        print(f"Deleted rule {args.id}")
    else:
        print(f"No such rule: {args.id}", file=sys.stderr)
        sys.exit(1)

def cmd_policy(args) -> None:
    fw = load_fw(args)
    if args.inbound or args.outbound:
        fw.set_policy(inbound=args.inbound, outbound=args.outbound)
        print("Policy updated.")
    else:
        dp = fw.cfg.get("default_policy", {"inbound": "ALLOW", "outbound": "ALLOW"})
        print(f"Inbound: {dp.get('inbound')} | Outbound: {dp.get('outbound')}")

def cmd_profile(args) -> None:
    fw = load_fw(args)
    if args.switch:
        fw.switch_profile(args.switch)
        print(f"Switched profile to {args.switch}")
    else:
        print(f"Active profile: {fw.active_profile}")

def cmd_gui(args) -> None:
    from .gui import run_gui
    fw = load_fw(args)
    run_gui(fw)
