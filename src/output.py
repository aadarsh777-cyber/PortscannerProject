import json
import csv
from collections import defaultdict

def print_table(results):
    """
    Print scan results in a human-readable table grouped by host.
    """
    by_host = defaultdict(list)
    for r in results:
        by_host[r["host"]].append(r)

    print("\n=== Scan Results ===")
    print(f"{'HOST':<25} {'PORT':<6} {'PROTO':<5} {'STATUS':<14} {'BANNER':<40}")
    print("-" * 92)

    for host, items in by_host.items():
        for r in sorted(items, key=lambda x: (x["port"], x["protocol"])):
            banner = r.get("banner", "")
            banner_short = (banner[:37] + "...") if banner and len(banner) > 40 else banner
            print(f"{host:<25} {r['port']:<6} {r['protocol']:<5} {r['status']:<14} {banner_short:<40}")

    print("-" * 92)
    open_count = sum(1 for r in results if r["status"] == "open")
    print(f"Open ports: {open_count} | Total entries: {len(results)}\n")


def save_json(results, path):
    """
    Save scan results to a JSON file.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def save_csv(results, path):
    """
    Save scan results to a CSV file.
    """
    fields = ["host", "port", "protocol", "status", "banner"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "host": r["host"],
                "port": r["port"],
                "protocol": r["protocol"],
                "status": r["status"],
                "banner": r.get("banner", "")
            })