from src.cli import parse_args
from src.utils import expand_ports, expand_targets, setup_logger
from src.scanner import run_tcp_scan, run_udp_scan
from src.services import try_grab_banner
from src.output import print_table, save_json, save_csv

def main():
    # Parse CLI arguments
    args = parse_args()
    logger = setup_logger(verbose=args.verbose)

    # Expand targets and ports
    targets = expand_targets(args.targets)
    ports = expand_ports(args.ports)

    if not targets or not ports:
        logger.error("No valid targets or ports specified.")
        return

    logger.info(f"Starting {args.scan.upper()} scan on {len(targets)} target(s) and {len(ports)} port(s)...")

    # Run scan
    if args.scan == "tcp":
        results = run_tcp_scan(
            targets,
            ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            logger=logger
        )
        # Optional banner grabbing
        if args.banner:
            logger.info("Attempting banner grabbing for open TCP ports...")
            for item in results:
                if item["status"] == "open" and item["protocol"] == "tcp":
                    banner = try_grab_banner(item["host"], item["port"], timeout=args.timeout, logger=logger)
                    if banner:
                        item["banner"] = banner
    elif args.scan == "udp":
        results = run_udp_scan(
            targets,
            ports,
            timeout=args.timeout,
            retries=args.retries,
            concurrency=args.concurrency,
            logger=logger
        )
    else:
        logger.error("Invalid scan type. Use 'tcp' or 'udp'.")
        return

    # Output results
    if args.table:
        print_table(results)

    if args.json:
        save_json(results, args.json)
        logger.info(f"Saved JSON results to {args.json}")

    if args.csv:
        save_csv(results, args.csv)
        logger.info(f"Saved CSV results to {args.csv}")


if __name__ == "__main__":
    main()