import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from src.utils import expand_ports, expand_targets
from src.scanner import run_tcp_scan, run_udp_scan
from src.services import try_grab_banner
from src.output import save_json, save_csv
import threading
import time
import socket
import random

results = []

def run_scan():
    global results
    target_input = target_entry.get().strip()
    ports_input = ports_entry.get().strip()
    scan_type = scan_var.get()
    banner_enabled = banner_var.get()
    start_time = time.time()

    if not target_input or not ports_input:
        messagebox.showerror("Error", "Please enter target(s) and ports.")
        return

    targets = expand_targets(target_input)
    ports = expand_ports(ports_input)

    # Reset progress bar
    progress_bar["value"] = 0
    progress_bar["maximum"] = len(targets) * len(ports)

    def scan_task():
        nonlocal targets, ports
        global results
        results = []
        count = 0
        status_var.set("Scanning...")
        if scan_type == "tcp":
            for host in targets:
                for port in ports:
                    res = run_tcp_scan([host], [port], timeout=1.0, concurrency=1)
                    results.extend(res)
                    if banner_enabled and res and res[0]["status"] == "open":
                        banner = try_grab_banner(host, port, timeout=1.0)
                        if banner:
                            res[0]["banner"] = banner
                    count += 1
                    progress_bar["value"] = count
        else:
            for host in targets:
                for port in ports:
                    res = run_udp_scan([host], [port], timeout=2.0, retries=1, concurrency=1)
                    results.extend(res)
                    count += 1
                    progress_bar["value"] = count

        # Display results
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, f"{'HOST':<25} {'PORT':<6} {'PROTO':<5} {'STATUS':<14} {'BANNER':<40}\n", "header")
        output_box.insert(tk.END, "-" * 92 + "\n", "divider")
        for r in results:
            banner = r.get("banner", "")
            banner_short = (banner[:37] + "...") if banner and len(banner) > 40 else banner
            try:
                resolved = socket.gethostbyaddr(r['host'])[0]
                host_display = f"{r['host']} ({resolved})"
            except Exception:
                host_display = r['host']
            line = f"{host_display:<25} {r['port']:<6} {r['protocol']:<5} {r['status']:<14} {banner_short:<40}\n"
            tag = "open" if r["status"] == "open" else "closed"
            output_box.insert(tk.END, line, tag)
        output_box.insert(tk.END, "-" * 92 + "\n", "divider")
        open_count = sum(1 for r in results if r["status"] == "open")
        output_box.insert(tk.END, f"Open ports: {open_count} | Total entries: {len(results)}\n", "summary")
        end_time = time.time()
        elapsed = round(end_time - start_time, 2)
        output_box.insert(tk.END, f"Scan completed in {elapsed} seconds\n", "summary")

        progress_bar["value"] = progress_bar["maximum"]  # complete
        status_var.set("Scan complete")

    threading.Thread(target=scan_task).start()
def clear_output():
    output_box.delete(1.0, tk.END)

def save_results_json():
    if not results:
        messagebox.showwarning("Warning", "No results to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")])
    if file:
        save_json(results, file)

def save_results_csv():
    if not results:
        messagebox.showwarning("Warning", "No results to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
    if file:
        save_csv(results, file)

def save_results_txt():
    if not results:
        messagebox.showwarning("Warning", "No results to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
    if file:
        with open(file, "w") as f:
            for r in results:
                f.write(f"{r['host']} {r['port']} {r['protocol']} {r['status']}\n")

def random_ports():
    ports_entry.delete(0, tk.END)
    ports = random.sample(range(1, 1025), 10)
    ports_entry.insert(0, ",".join(map(str, ports)))

# --- GUI Layout ---
root = tk.Tk()
root.title("Python Port Scanner")
root.configure(bg="#1e1e2f")

top_frame = tk.Frame(root, bg="#1e1e2f")
top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

middle_frame = tk.Frame(root, bg="#1e1e2f")
middle_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)

bottom_frame = tk.Frame(root, bg="#1e1e2f")
bottom_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)

tk.Label(top_frame, text="Targets (comma or CIDR):", bg="#1e1e2f", fg="white").grid(row=0, column=0, sticky="w")
target_entry = tk.Entry(top_frame, width=50, bg="#2d2d3a", fg="white", insertbackground="white")
target_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(top_frame, text="Ports (e.g. 22,80,443 or 1-1024):", bg="#1e1e2f", fg="white").grid(row=1, column=0, sticky="w")
ports_entry = tk.Entry(top_frame, width=50, bg="#2d2d3a", fg="white", insertbackground="white")
ports_entry.grid(row=1, column=1, padx=5, pady=5)

preset_var = tk.StringVar(value="Custom")
preset_menu = tk.OptionMenu(top_frame, preset_var, "Custom", "Web (80,443)", "Mail (25,110,143)", "Database (3306,5432)", "All Common")
preset_menu.config(bg="#2d2d3a", fg="white")
preset_menu.grid(row=2, column=1, padx=5, pady=5)

scan_var = tk.StringVar(value="tcp")
tk.Label(top_frame, text="Scan Type:", bg="#1e1e2f", fg="white").grid(row=3, column=0, sticky="w")
tk.Radiobutton(top_frame, text="TCP", variable=scan_var, value="tcp", bg="#1e1e2f", fg="white", selectcolor="#2d2d3a").grid(row=3, column=1, sticky="w")
tk.Radiobutton(top_frame, text="UDP", variable=scan_var, value="udp", bg="#1e1e2f", fg="white", selectcolor="#2d2d3a").grid(row=3, column=1, sticky="e")

banner_var = tk.BooleanVar()
tk.Checkbutton(top_frame, text="Enable Banner Grabbing (TCP only)", variable=banner_var, bg="#1e1e2f", fg="white", selectcolor="#2d2d3a").grid(row=4, column=1, sticky="w")

tk.Button(middle_frame, text="Run Scan", command=run_scan, bg="#00a86b", fg="white").grid(row=0, column=0, pady=10)
tk.Button(middle_frame, text="Clear Output", command=clear_output, bg="#ff4500", fg="white").grid(row=0, column=1, padx=5)
tk.Button(middle_frame, text="Save JSON", command=save_results_json, bg="#1e90ff", fg="white").grid(row=0, column=2, padx=5)
tk.Button(middle_frame, text="Save CSV", command=save_results_csv, bg="#9370db", fg="white").grid(row=1, column=1, pady=5)
tk.Button(middle_frame, text="Save TXT", command=save_results_txt, bg="#008b8b", fg="white").grid(row=0, column=4, padx=5)
tk.Button(middle_frame, text="Random Ports", command=random_ports, bg="#ffa500", fg="black").grid(row=0, column=6, padx=5)

output_box = scrolledtext.ScrolledText(bottom_frame, width=100, height=20, bg="#0d0d0d", fg="white", font=("Consolas", 10))
output_box.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

# Colour tags
output_box.tag_config("header", foreground="cyan", font=("Consolas", 10, "bold"))
output_box.tag_config("divider", foreground="yellow")
output_box.tag_config("open", foreground="lime")
output_box.tag_config("closed", foreground="red")
output_box.tag_config("summary", foreground="orange", font=("Consolas", 10, "bold"))

# Progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.grid(row=4, column=0, pady=10)

status_var = tk.StringVar(value="Ready")
status_bar = tk.Label(root, textvariable=status_var, relief="sunken", anchor="w", bg="#2d2d3a", fg="white")
status_bar.grid(row=3, column=0, sticky="ew")

root.mainloop()
