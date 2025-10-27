import os
import subprocess
from typing import List, Set
from pathlib import Path

def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)

def is_root() -> bool:
    return os.geteuid() == 0

def run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)

def which(binary: str) -> str:
    res = shutil_which(binary)
    if not res:
        raise FileNotFoundError(f"Required binary '{binary}' not found in PATH")
    return res

def get_local_ipv4_addresses() -> Set[str]:
    # Uses `ip -o -4 addr` to get all IPv4 addresses on the system
    try:
        cp = run_cmd(["ip", "-o", "-4", "addr", "show"], check=True)
    except Exception:
        return set()
    addrs = set()
    for line in cp.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ip_cidr = parts[3]
            ip = ip_cidr.split("/")[0]
            addrs.add(ip)
    # Also loopback by default
    addrs.add("127.0.0.1")
    return addrs

# Avoid importing shutil globally to keep lints clean
def shutil_which(name: str) -> str:
    import shutil
    return shutil.which(name) or ""
