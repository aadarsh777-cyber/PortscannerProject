import socket
import concurrent.futures
from time import sleep

def scan_tcp_once(host, port, timeout=1.0):
    """
    Try to connect to a TCP port.
    Returns True if open, False if closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_udp_once(host, port, timeout=2.0):
    """
    Best-effort UDP scan.
    Returns (is_open, status) where status can be 'open', 'closed', or 'open|filtered'.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            # Received data implies open
            return True, "open"
        except socket.timeout:
            sock.close()
            return False, "open|filtered"
        except Exception:
            sock.close()
            return False, "closed"
    except Exception:
        return False, "closed"


def run_tcp_scan(targets, ports, timeout=1.0, concurrency=200, logger=None):
    """
    Run a concurrent TCP scan across multiple targets and ports.
    Returns a list of result dictionaries.
    """
    results = []
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        for host in targets:
            for port in ports:
                tasks.append(executor.submit(scan_tcp_once, host, port, timeout))
        i = 0
        for host in targets:
            for port in ports:
                is_open = tasks[i].result()
                i += 1
                results.append({
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                    "status": "open" if is_open else "closed"
                })
    if logger:
        open_count = sum(1 for r in results if r["status"] == "open")
        logger.info(f"TCP scan complete. Open: {open_count}, Total: {len(results)}")
    return results


def run_udp_scan(targets, ports, timeout=2.0, retries=1, concurrency=200, logger=None):
    """
    Run a concurrent UDP scan across multiple targets and ports.
    Returns a list of result dictionaries.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_map = {}
        for host in targets:
            for port in ports:
                future_map[(host, port)] = executor.submit(scan_udp_once, host, port, timeout)
        for (host, port), fut in future_map.items():
            is_open, status = fut.result()
            # Optional retries for UDP timeouts
            if status == "open|filtered" and retries > 0:
                for _ in range(retries):
                    is_open2, status2 = scan_udp_once(host, port, timeout)
                    is_open = is_open or is_open2
                    status = status2 if status2 != "open|filtered" else status
                    if status2 != "open|filtered":
                        break
                    sleep(0.05)
            results.append({
                "host": host,
                "port": port,
                "protocol": "udp",
                "status": "open" if is_open else status
            })
    if logger:
        open_count = sum(1 for r in results if r["status"] == "open")
        logger.info(f"UDP scan complete. Open: {open_count}, Total: {len(results)}")
    return results