import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})")


def detect_subnet() -> str:
    """Best-effort detection of the local IPv4 /24 on Windows."""
    try:
        out = subprocess.check_output(
            ["ipconfig"], text=True, encoding="utf-8", errors="ignore"
        )
        ipv4 = None
        mask = None
        for line in out.splitlines():
            m = re.search(r"IPv4[^:]*:\s*([0-9.]+)", line, re.I)
            if m:
                ipv4 = m.group(1)
            m = re.search(r"Subnet Mask[^:]*:\s*([0-9.]+)", line, re.I)
            if m and ipv4:
                mask = m.group(1)
                break
        if ipv4 and mask:
            net = ipaddress.IPv4Network(f"{ipv4}/{mask}", strict=False)
            # Safety/operational limit: keep the default scan reasonably small.
            if net.num_addresses <= 1024:
                return str(net)
            return str(ipaddress.IPv4Network(f"{ipv4}/24", strict=False))
    except Exception:
        pass
    return ""


def ping(ip: str, timeout_ms: int = 700) -> bool:
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    value = str(timeout_ms if platform.system().lower() == "windows" else max(1, timeout_ms // 1000))
    try:
        p = subprocess.run(
            ["ping", flag, "1", timeout_flag, value, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(2, timeout_ms / 1000 + 1),
        )
        return p.returncode == 0
    except Exception:
        return False


def arp_table() -> dict[str, str]:
    result = {}
    try:
        out = subprocess.check_output(
            ["arp", "-a"], text=True, encoding="utf-8", errors="ignore"
        )
        for line in out.splitlines():
            m = re.search(
                r"^\s*([0-9.]+)\s+([0-9a-f-]{17})\s+\w+",
                line,
                re.I,
            )
            if m:
                result[m.group(1)] = m.group(2).replace("-", ":").upper()
    except Exception:
        pass
    return result


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def scan(subnet: str = "", timeout_ms: int = 700, max_hosts: int = 1024) -> list[dict]:
    subnet = subnet or detect_subnet()
    if not subnet:
        raise RuntimeError("Não foi possível detectar a sub-rede IPv4. Configure network.subnet no config.json.")

    net = ipaddress.ip_network(subnet, strict=False)
    if net.num_addresses > max_hosts:
        raise ValueError(f"Sub-rede {net} excede o limite configurado de {max_hosts} endereços.")

    ips = [str(x) for x in net.hosts()]
    found = []

    with ThreadPoolExecutor(max_workers=min(64, max(4, len(ips)))) as pool:
        futures = {pool.submit(ping, ip, timeout_ms): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                online = future.result()
            except Exception:
                online = False
            if online:
                found.append({"ip": ip, "online": True})

    arp = arp_table()
    for d in found:
        d["mac"] = arp.get(d["ip"])
        d["hostname"] = reverse_dns(d["ip"])

    found.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return found
