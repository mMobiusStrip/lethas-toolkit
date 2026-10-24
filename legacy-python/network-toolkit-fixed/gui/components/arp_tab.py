import customtkinter as ctk
from threading import Thread
from core.arp_monitor import monitor_arp
import csv
import os

class ArpTab:
    def __init__(self, master):
        self.master = master
        self.monitoring = False
        self.known_ips = {}

        self.button_start = ctk.CTkButton(master, text="Start Monitoring", command=self.start_monitoring)
        self.button_start.pack(pady=5)

        self.button_stop = ctk.CTkButton(master, text="Stop Monitoring", command=self.stop_monitoring, state="disabled")
        self.button_stop.pack(pady=5)

        self.save_button = ctk.CTkButton(master, text="Save to CSV", command=self.save_to_csv)
        self.save_button.pack(pady=5)

        self.result_box = ctk.CTkTextbox(master, height=400)
        self.result_box.pack(pady=10)

        self.logs = []

    def start_monitoring(self):
        self.monitoring = True
        self.button_start.configure(state="disabled")
        self.button_stop.configure(state="normal")
        self.result_box.insert("end", "Starting ARP monitor...\n")
        thread = Thread(target=monitor_arp, args=(self.display_packet,))
        thread.daemon = True
        thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.button_start.configure(state="normal")
        self.button_stop.configure(state="disabled")
        self.result_box.insert("end", "Stopped ARP monitor.\n")

    def display_packet(self, info):
        if not self.monitoring:
            return

        ip = info['ip']
        mac = info['mac']
        timestamp = info['time']

        log_line = f"[{timestamp}] IP: {ip} -> MAC: {mac}\n"
        spoof_warning = ""

        if ip in self.known_ips:
            if self.known_ips[ip] != mac:
                spoof_warning = f"⚠️ Possible ARP spoofing: {ip} was {self.known_ips[ip]}, now {mac}\n"
        else:
            self.known_ips[ip] = mac

        self.logs.append((timestamp, ip, mac, spoof_warning.strip()))
        self.result_box.insert("end", log_line)
        if spoof_warning:
            self.result_box.insert("end", spoof_warning)
        self.result_box.see("end")

    def save_to_csv(self):
        if not self.logs:
            self.result_box.insert("end", "No data to save.\n")
            return

        filename = "arp_logs.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "IP", "MAC", "Warning"])
            writer.writerows(self.logs)

        self.result_box.insert("end", f"Logs saved to {os.path.abspath(filename)}\n")
