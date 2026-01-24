import argparse

def parse_args():
    """
    Parse command-line arguments for the port scanner.
    """
    parser = argparse.ArgumentParser(description="Procedural Port Scanner (TCP/UDP)")

    # Targets and ports
    parser.add_argument("--targets", required=True,
                        help="Comma-separated hosts or CIDR (e.g., 192.168.1.1,scanme.nmap.org,10.0.0.0/24)")
    parser.add_argument("--ports", required=True,
                        help="Ports list/range (e.g., 22,80,443 or 1-1024)")

    # Scan options
    parser.add_argument("--scan", choices=["tcp", "udp"], default="tcp",
                        help="Scan type (tcp or udp)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Socket timeout in seconds")
    parser.add_argument("--retries", type=int, default=1,
                        help="UDP retries for open|filtered ports")
    parser.add_argument("--concurrency", type=int, default=100,
                        help="Number of threads for concurrent scanning")

    # Banner grabbing
    parser.add_argument("--banner", action="store_true",
                        help="Try to grab banners for open TCP ports")

    # Output options
    parser.add_argument("--table", action="store_true",
                        help="Print human-readable table of results")
    parser.add_argument("--json", help="Save results to JSON file")
    parser.add_argument("--csv", help="Save results to CSV file")

    # Logging
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")

    return parser.parse_args()