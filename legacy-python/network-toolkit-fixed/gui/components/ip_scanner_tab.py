import customtkinter as ctk
import threading
import subprocess
import ipaddress
import time
import socket
import re

class IPScannerTab:
    def __init__(self, master):
        self.master = master
        self.stop_signal = False

        self.entry_start = ctk.CTkEntry(master, placeholder_text="Start IP (e.g., 192.168.1.1)")
        self.entry_start.pack(pady=5)

        self.entry_end = ctk.CTkEntry(master, placeholder_text="End IP (e.g., 192.168.1.254)")
        self.entry_end.pack(pady=5)

        self.button_scan = ctk.CTkButton(master, text="Start Scan", command=self.start_scan)
        self.button_scan.pack(pady=5)

        self.button_stop = ctk.CTkButton(master, text="Stop Scan", command=self.stop_scan)
        self.button_stop.pack(pady=5)

        self.scroll_frame = ctk.CTkScrollableFrame(master, height=400)
        self.scroll_frame.pack(pady=10, fill="both", expand=True)

        self.add_table_header()

    def add_table_header(self):
        headers = ["IP Address", "Ping (ms)", "Estimated Speed", "Hostname", "MAC Address"]
        for col, text in enumerate(headers):
            label = ctk.CTkLabel(self.scroll_frame, text=text, font=("Arial", 12, "bold"))
            label.grid(row=0, column=col, padx=10, pady=5)

    def add_table_row(self, row, ip, ping, speed, hostname, mac):
        ctk.CTkLabel(self.scroll_frame, text=ip).grid(row=row, column=0, padx=5)
        ctk.CTkLabel(self.scroll_frame, text=ping).grid(row=row, column=1, padx=5)
        ctk.CTkLabel(self.scroll_frame, text=speed).grid(row=row, column=2, padx=5)
        ctk.CTkLabel(self.scroll_frame, text=hostname).grid(row=row, column=3, padx=5)
        ctk.CTkLabel(self.scroll_frame, text=mac).grid(row=row, column=4, padx=5)

    def start_scan(self):
        self.stop_signal = False
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        self.add_table_header()
        threading.Thread(target=self.scan_range, daemon=True).start()

    def stop_scan(self):
        self.stop_signal = True
        row = len(self.scroll_frame.winfo_children()) // 5 + 1
        self.add_table_row(row, "Scan stopped", "-", "-", "-", "-")

    def scan_range(self):
        try:
            start_ip = ipaddress.IPv4Address(self.entry_start.get())
            end_ip = ipaddress.IPv4Address(self.entry_end.get())
        except:
            self.add_table_row(1, "Invalid IP range", "-", "-", "-", "-")
            return

        row = 1
        for ip_int in range(int(start_ip), int(end_ip) + 1):
            if self.stop_signal:
                break
            ip_str = str(ipaddress.IPv4Address(ip_int))
            delay = self.ping_ip(ip_str)
            if delay is not None:
                speed = self.estimate_speed(delay)
                hostname = self.get_hostname(ip_str)
                mac = self.get_mac_address(ip_str)
                self.add_table_row(row, ip_str, f"{delay:.2f}", speed, hostname, mac)
            else:
                self.add_table_row(row, ip_str, "No response", "-", "-", "-")
            row += 1

    def ping_ip(self, ip):
        try:
            param = "-n" if subprocess.run("ver", shell=True, capture_output=True).returncode == 0 else "-c"
            start = time.time()
            result = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True, timeout=2)
            end = time.time()
            if result.returncode == 0:
                return (end - start) * 1000
        except:
            return None
        return None

    def estimate_speed(self, delay_ms):
        if delay_ms < 1:
            return "≥ 1 Gbps"
        elif delay_ms < 5:
            return "~1 Gbps"
        elif delay_ms < 15:
            return "Fast Ethernet (100 Mbps)"
        elif delay_ms < 50:
            return "Likely Wi-Fi / 100 Mbps"
        else:
            return "Slow or external"

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "-"

    def get_mac_address(self, ip):
        try:
            arp_output = subprocess.check_output(["arp", "-a"], text=True)
            lines = arp_output.splitlines()
            for line in lines:
                if ip in line:
                    mac_match = re.search(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}", line)
                    if mac_match:
                        return mac_match.group(0)
        except:
            pass
        return "-"
