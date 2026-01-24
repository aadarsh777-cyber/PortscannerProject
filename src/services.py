import socket
import ssl

def try_grab_banner(host, port, timeout=1.0, logger=None):
    """
    Attempt to grab a banner or service info from an open TCP port.
    Returns a string banner if found, otherwise None.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        banner = None

        # Heuristic probes for common services
        if port in (80, 8080):
            # HTTP probe
            probe = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            sock.sendall(probe)
            try:
                data = sock.recv(1024)
                banner = data.decode(errors="ignore").strip()
            except socket.timeout:
                banner = None

        elif port == 443:
            # HTTPS probe: TLS handshake to get certificate CN
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    subject = cert.get("subject", [])
                    cn = None
                    for tup in subject:
                        for k, v in tup:
                            if k == "commonName":
                                cn = v
                    banner = f"TLS CN={cn}" if cn else "TLS handshake OK"
            except Exception:
                banner = None

        elif port in (21, 25, 110, 143, 22):
            # FTP, SMTP, POP3, IMAP, SSH often send greetings immediately
            try:
                data = sock.recv(1024)
                banner = data.decode(errors="ignore").strip()
            except socket.timeout:
                banner = None

        # Close socket
        sock.close()

        if banner and logger:
            logger.debug(f"Banner {host}:{port} -> {banner[:80]}")

        return banner if banner else None

    except Exception:
        return None