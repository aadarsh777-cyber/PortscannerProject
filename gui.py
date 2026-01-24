import tkinter as tk
from tkinter import scrolledtext, messagebox
from src.utils import expand_ports, expand_targets
from src.scanner import run_tcp_scan, run_udp_scan
from src.services import try_grab_banner

def run_scan():
    target_input = target_entry.get().strip()
    ports_input = ports_entry.get().strip()
    scan_type = scan_var.get()
    banner_enabled = banner_var.get()

    if not target_input or not ports_input:
        messagebox.showerror("Error", "Please enter target(s) and ports.")
        return

    targets = expand_targets(target_input)
    ports = expand_ports(ports_input)

    if not targets or not ports:
        messagebox.showerror("Error", "Invalid targets or ports.")
        return

    results = []
    if scan_type == "tcp":
        results = run_tcp_scan(targets, ports, timeout=1.0, concurrency=100)
        if banner_enabled:
            for item in results:
                if item["status"] == "open" and item["protocol"] == "tcp":
                    banner = try_grab_banner(item["host"], item["port"], timeout=1.0)
                    if banner:
                        item["banner"] = banner
    else:
        results = run_udp_scan(targets, ports, timeout=2.0, retries=1, concurrency=100)

    # Display results
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"{'HOST':<25} {'PORT':<6} {'PROTO':<5} {'STATUS':<14} {'BANNER':<40}\n")
    output_box.insert(tk.END, "-" * 92 + "\n")
    for r in results:
        banner = r.get("banner", "")
        banner_short = (banner[:37] + "...") if banner and len(banner) > 40 else banner
        output_box.insert(tk.END, f"{r['host']:<25} {r['port']:<6} {r['protocol']:<5} {r['status']:<14} {banner_short:<40}\n")
    output_box.insert(tk.END, "-" * 92 + "\n")
    open_count = sum(1 for r in results if r["status"] == "open")
    output_box.insert(tk.END, f"Open ports: {open_count} | Total entries: {len(results)}\n")

# --- GUI Layout ---
root = tk.Tk()
root.title("Python Port Scanner (Procedural)")

tk.Label(root, text="Targets (comma or CIDR):").grid(row=0, column=0, sticky="w")
target_entry = tk.Entry(root, width=50)
target_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Ports (e.g. 22,80,443 or 1-1024):").grid(row=1, column=0, sticky="w")
ports_entry = tk.Entry(root, width=50)
ports_entry.grid(row=1, column=1, padx=5, pady=5)

scan_var = tk.StringVar(value="tcp")
tk.Label(root, text="Scan Type:").grid(row=2, column=0, sticky="w")
tk.Radiobutton(root, text="TCP", variable=scan_var, value="tcp").grid(row=2, column=1, sticky="w")
tk.Radiobutton(root, text="UDP", variable=scan_var, value="udp").grid(row=2, column=1, sticky="e")

banner_var = tk.BooleanVar()
tk.Checkbutton(root, text="Enable Banner Grabbing (TCP only)", variable=banner_var).grid(row=3, column=1, sticky="w")

tk.Button(root, text="Run Scan", command=run_scan).grid(row=4, column=1, pady=10)

output_box = scrolledtext.ScrolledText(root, width=100, height=20)
output_box.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()