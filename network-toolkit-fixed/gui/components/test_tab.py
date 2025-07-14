import customtkinter as ctk
import threading
import subprocess
import socket

class TestTab:
    def __init__(self, master):
        self.master = master

        self.entry = ctk.CTkEntry(master, placeholder_text="Enter host or IP")
        self.entry.pack(pady=10)

        self.button_ping = ctk.CTkButton(master, text="Ping", command=self.start_ping)
        self.button_ping.pack(pady=5)

        self.button_trace = ctk.CTkButton(master, text="Traceroute", command=self.start_traceroute)
        self.button_trace.pack(pady=5)

        self.button_dns = ctk.CTkButton(master, text="DNS Lookup", command=self.start_dns)
        self.button_dns.pack(pady=5)

        self.button_clear = ctk.CTkButton(master, text="Clear Output", command=self.clear_output)
        self.button_clear.pack(pady=5)

        self.output = ctk.CTkTextbox(master, height=400)
        self.output.pack(pady=10)

    def start_ping(self):
        threading.Thread(target=self.ping).start()

    def start_traceroute(self):
        threading.Thread(target=self.traceroute).start()

    def start_dns(self):
        threading.Thread(target=self.dns_lookup).start()

    def clear_output(self):
        self.output.delete("1.0", "end")

    def ping(self):
        host = self.entry.get()
        self.output.insert("end", f"Pinging {host}...\n")
        try:
            param = "-n" if subprocess.run("ver", shell=True, capture_output=True).returncode == 0 else "-c"
            result = subprocess.run(["ping", param, "4", host], capture_output=True, text=True)
            self.output.insert("end", result.stdout + "\n")
        except Exception as e:
            self.output.insert("end", f"Ping error: {e}\n")

    def traceroute(self):
        host = self.entry.get()
        self.output.insert("end", f"Running traceroute to {host}...\n")
        try:
            cmd = ["tracert", host] if subprocess.run("ver", shell=True, capture_output=True).returncode == 0 else ["traceroute", host]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.output.insert("end", result.stdout + "\n")
        except Exception as e:
            self.output.insert("end", f"Traceroute error: {e}\n")

    def dns_lookup(self):
        host = self.entry.get()
        self.output.insert("end", f"Resolving DNS for {host}...\n")
        try:
            ip = socket.gethostbyname(host)
            self.output.insert("end", f"{host} resolves to {ip}\n")
        except Exception as e:
            self.output.insert("end", f"DNS error: {e}\n")
