import customtkinter as ctk
from core.port_scanner import scan_ports
import threading
import ipaddress

class ScannerTab:
    def __init__(self, master):
        self.master = master

        self.entry_ip = ctk.CTkEntry(master, placeholder_text="Target IP")
        self.entry_ip.pack(pady=5)

        self.entry_start_port = ctk.CTkEntry(master, placeholder_text="Start Port")
        self.entry_start_port.pack(pady=5)

        self.entry_end_port = ctk.CTkEntry(master, placeholder_text="End Port")
        self.entry_end_port.pack(pady=5)

        self.progress = ctk.CTkProgressBar(master)
        self.progress.pack(pady=5)
        self.progress.set(0)

        self.button = ctk.CTkButton(master, text="Scan", command=self.start_scan_thread)
        self.button.pack(pady=5)

        self.result = ctk.CTkTextbox(master, height=300)
        self.result.pack(pady=5)

    def start_scan_thread(self):
        thread = threading.Thread(target=self.scan)
        thread.start()

    def scan(self):
        ip = self.entry_ip.get()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.result.delete("1.0", "end")
            self.result.insert("end", "Invalid IP address.\n")
            return

        try:
            start_port = int(self.entry_start_port.get())
            end_port = int(self.entry_end_port.get())
            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
                raise ValueError
        except ValueError:
            self.result.delete("1.0", "end")
            self.result.insert("end", "Invalid port range.\n")
            return

        ports = list(range(start_port, end_port + 1))
        total = len(ports)
        self.result.delete("1.0", "end")
        self.result.insert("end", f"Scanning {ip} ports {start_port}-{end_port}...\n")
        open_ports = []

        for idx, port in enumerate(ports):
            self.progress.set(idx / total)
            try:
                sock = socket.socket()
                sock.settimeout(0.3)
                sock.connect((ip, port))
                open_ports.append(port)
                self.result.insert("end", f"Port {port} is open\n")
                sock.close()
            except:
                pass

        self.progress.set(1)
        if not open_ports:
            self.result.insert("end", "No open ports found.\n")
