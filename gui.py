import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk, simpledialog
from src.utils import expand_ports, expand_targets
from src.scanner import run_tcp_scan, run_udp_scan
from src.services import try_grab_banner
from src.output import save_json, save_csv
import threading
import time
import socket
import random

results = []
stop_flag = False

def run_scan():
    global results
    target_input = target_entry.get().strip()
    ports_input = ports_entry.get().strip()
    scan_type = scan_var.get()
    banner_enabled = banner_var.get()
    timeout_val = float(timeout_entry.get())
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
        global stop_flag
        results = []
        stop_flag = False
        count = 0
        status_var.set("Scanning...")
        if scan_type == "tcp":
            for host in targets:
                if stop_flag:
                    break
                for port in ports:
                    if stop_flag:
                        break
                    res = run_tcp_scan([host], [port], timeout=timeout_val, concurrency=1)
                    results.extend(res)
                    if banner_enabled and res and res[0]["status"] == "open":
                        banner = try_grab_banner(host, port, timeout=timeout_val)
                        if banner:
                            res[0]["banner"] = banner
                    count += 1
                    progress_bar["value"] = count
        else:
            for host in targets:
                if stop_flag:
                    break
                for port in ports:
                    if stop_flag:
                        break
                    res = run_udp_scan([host], [port], timeout=timeout_val, retries=1, concurrency=1)
                    results.extend(res)
                    count += 1
                    progress_bar["value"] = count

        # Display results
        display_results = results
        if sort_by_status_var.get():
            display_results = sort_results_by_status(display_results)
        elif sort_by_port_var.get():
            display_results = sort_results_by_port(display_results)
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, f"{'HOST':<25} {'PORT':<6} {'PROTO':<5} {'STATUS':<14} {'BANNER':<40}\n", "header")
        output_box.insert(tk.END, "-" * 92 + "\n", "divider")
        for r in display_results:
            if filter_open_var.get() and r["status"] != "open":
                continue
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
        open_count = sum(1 for r in results if r["status"] == "open")
        total_count = len(results)
        root.after(0, lambda: messagebox.showinfo("Scan Summary", f"Open ports: {open_count}\nTotal scanned: {total_count}"))

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

def copy_results():
    if not results:
        return
    text = "\n".join([f"{r['host']} {r['port']} {r['protocol']} {r['status']}" for r in results])
    root.clipboard_clear()
    root.clipboard_append(text)

def random_ports():
    ports_entry.delete(0, tk.END)
    ports = random.sample(range(1, 1025), 10)
    ports_entry.insert(0, ",".join(map(str, ports)))

def stop_scan():
    global stop_flag
    stop_flag = True

def set_full_range():
    if messagebox.askyesno("Confirm", "Scan full port range 1-65535? This may take a long time. Continue?"):
        ports_entry.delete(0, tk.END)
        ports_entry.insert(0, "1-65535")

def sort_results_by_port(results_list):
    return sorted(results_list, key=lambda x: int(x["port"]))

def sort_results_by_status(results_list):
    return sorted(results_list, key=lambda x: (0 if x["status"] == "open" else 1, int(x["port"])))

def save_results_html():
    if not results:
        messagebox.showwarning("Warning", "No results to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files","*.html")])
    if file:
        with open(file, "w") as f:
            f.write("<html><body><h2>Port Scan Results</h2><table border='1'>")
            f.write("<tr><th>Host</th><th>Port</th><th>Protocol</th><th>Status</th><th>Banner</th></tr>")
            for r in results:
                f.write(f"<tr><td>{r['host']}</td><td>{r['port']}</td><td>{r['protocol']}</td><td>{r['status']}</td><td>{r.get('banner','')}</td></tr>")
            f.write("</table></body></html>")

def auto_save_results():
    with open("autosave_scan.txt", "w") as f:
        for r in results:
            f.write(f"{r['host']} {r['port']} {r['protocol']} {r['status']} {r.get('banner','')}\n")

def save_results():
    if not results:
        messagebox.showwarning("Warning", "No results to save.")
        return

    # Popup to choose format
    format_choice = tk.simpledialog.askstring(
        "Save Results",
        "Enter format (json / csv / txt / html):"
    )

    if not format_choice:
        return

    format_choice = format_choice.lower().strip()

    if format_choice == "json":
        file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")])
        if file:
            save_json(results, file)

    elif format_choice == "csv":
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if file:
            save_csv(results, file)

    elif format_choice == "txt":
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if file:
            with open(file, "w") as f:
                for r in results:
                    f.write(f"{r['host']} {r['port']} {r['protocol']} {r['status']}\n")

    elif format_choice == "html":
        file = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files","*.html")])
        if file:
            with open(file, "w") as f:
                f.write("<html><body><h2>Port Scan Results</h2><table border='1'>")
                f.write("<tr><th>Host</th><th>Port</th><th>Protocol</th><th>Status</th><th>Banner</th></tr>")
                for r in results:
                    f.write(f"<tr><td>{r['host']}</td><td>{r['port']}</td><td>{r['protocol']}</td><td>{r['status']}</td><td>{r.get('banner','')}</td></tr>")
                f.write("</table></body></html>")
    else:
        messagebox.showerror("Error", "Invalid format. Choose json, csv, txt, or html.")

def search_results():
    keyword = search_entry.get().strip().lower()
    if not keyword:
        return
    output_box.tag_remove("highlight", "1.0", tk.END)
    start = "1.0"
    while True:
        pos = output_box.search(keyword, start, stopindex=tk.END)
        if not pos:
            break
        end = f"{pos}+{len(keyword)}c"
        output_box.tag_add("highlight", pos, end)
        start = end
    output_box.tag_config("highlight", background="yellow", foreground="black")



# --- GUI Layout ---
root = tk.Tk()
root.title("Python Port Scanner")
root.configure(bg="#1e1e2f")
root.resizable(True, True)
theme_var = tk.BooleanVar(value=True)  # True = Dark mode

def toggle_theme():
    if theme_var.get():  # Dark mode
        root.configure(bg="#1e1e2f")
        top_frame.configure(bg="#1e1e2f")
        middle_frame.configure(bg="#1e1e2f")
        bottom_frame.configure(bg="#1e1e2f")
        output_box.configure(bg="#0d0d0d", fg="white")
        target_entry.configure(bg="#2d2d3a", fg="white", insertbackground="white")
        ports_entry.configure(bg="#2d2d3a", fg="white", insertbackground="white")
    else:  # Light mode
        root.configure(bg="white")
        top_frame.configure(bg="white")
        middle_frame.configure(bg="white")
        bottom_frame.configure(bg="white")
        output_box.configure(bg="white", fg="black")
        target_entry.configure(bg="white", fg="black", insertbackground="black")
        ports_entry.configure(bg="white", fg="black", insertbackground="black")

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

tk.Label(top_frame, text="Timeout (sec):", bg="#1e1e2f", fg="white").grid(row=5, column=0, sticky="w")
timeout_entry = tk.Entry(top_frame, width=10, bg="#2d2d3a", fg="white")
timeout_entry.insert(0, "1")
timeout_entry.grid(row=5, column=1, padx=5, pady=5)

tk.Label(top_frame, text="Concurrency:", bg="#1e1e2f", fg="white").grid(row=6, column=0, sticky="w")
concurrency_entry = tk.Entry(top_frame, width=10, bg="#2d2d3a", fg="white")
concurrency_entry.insert(0, "100")
concurrency_entry.grid(row=6, column=1, padx=5, pady=5)

filter_open_var = tk.BooleanVar()
tk.Checkbutton(top_frame, text="Show only open", variable=filter_open_var, bg="#1e1e2f", fg="white", selectcolor="#2d2d3a").grid(row=7, column=1, sticky="w")

sort_by_port_var = tk.BooleanVar()
tk.Checkbutton(top_frame, text="Sort by port", variable=sort_by_port_var, bg="#1e1e2f", fg="white", selectcolor="#2d2d3a").grid(row=8, column=1, sticky="w")

sort_by_status_var = tk.BooleanVar()
tk.Checkbutton(top_frame, text="Open first", variable=sort_by_status_var, bg="#1e1e2f", fg="white", selectcolor="#2d2d3a").grid(row=9, column=1, sticky="w")

tk.Button(middle_frame, text="Run Scan", command=run_scan, bg="#00a86b", fg="white").grid(row=0, column=0, pady=10)
tk.Button(middle_frame, text="Clear Output", command=clear_output, bg="#ff4500", fg="white").grid(row=0, column=1, padx=5)
tk.Button(middle_frame, text="Save Results", command=save_results, bg="#1e90ff", fg="white").grid(row=0, column=2, padx=5)
tk.Button(middle_frame, text="Copy Results", command=copy_results, bg="#4682b4", fg="white").grid(row=0, column=3, padx=5)
tk.Button(middle_frame, text="Random Ports", command=random_ports, bg="#ffa500", fg="black").grid(row=0, column=4, padx=5)
tk.Button(middle_frame, text="Stop Scan", command=stop_scan, bg="#dc143c", fg="white").grid(row=0, column=5, padx=5)
tk.Button(middle_frame, text="Auto Save", command=auto_save_results, bg="#32cd32", fg="black").grid(row=0, column=6, padx=5)

search_entry = tk.Entry(middle_frame, width=20, bg="#2d2d3a", fg="white")
search_entry.grid(row=1, column=0, padx=5)

tk.Button(middle_frame, text="Search", command=search_results, bg="#daa520", fg="black").grid(row=1, column=1, padx=5)

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
