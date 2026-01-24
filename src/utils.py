import ipaddress
import socket
import logging

def setup_logger(verbose=False):
    """
    Configure a simple logger for console output.
    """
    logger = logging.getLogger("portscanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()
    fmt = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    logger.handlers = []  # Clear existing handlers
    logger.addHandler(handler)
    return logger


def expand_targets(targets_input):
    """
    Expand targets from comma-separated string or list.
    Supports hostnames, IPs, and CIDR ranges.
    """
    if isinstance(targets_input, str):
        items = [t.strip() for t in targets_input.split(",") if t.strip()]
    elif isinstance(targets_input, list):
        items = targets_input
    else:
        return []

    expanded = []
    for item in items:
        try:
            if "/" in item:
                # CIDR range expansion
                net = ipaddress.ip_network(item, strict=False)
                for ip in net.hosts():
                    expanded.append(str(ip))
            else:
                # Try to resolve hostname to IP, but keep original if fails
                try:
                    socket.gethostbyname(item)
                    expanded.append(item)
                except socket.gaierror:
                    expanded.append(item)
        except ValueError:
            expanded.append(item)

    # Deduplicate while preserving order
    seen = set()
    out = []
    for t in expanded:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def expand_ports(ports_input):
    """
    Expand ports from string like '22,80,443' or '1-1024'.
    Returns a sorted list of integers.
    """
    if not ports_input:
        return []
    ports = set()
    for part in str(ports_input).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                for p in range(min(start, end), max(start, end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)