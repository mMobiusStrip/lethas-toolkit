import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import customtkinter as ctk
from gui.components.scanner_tab import ScannerTab
from gui.components.arp_tab import ArpTab
from gui.components.test_tab import TestTab
from gui.components.ip_scanner_tab import IPScannerTab


ctk.set_default_color_theme("dark-blue")
ctk.set_appearance_mode("dark")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Lethas v0.1 Toolkit")
        self.geometry("1280x768")

        tabview = ctk.CTkTabview(self)
        tabview.pack(expand=True, fill="both")

        scanner_frame = tabview.add("Port Scanner")
        arp_frame = tabview.add("ARP Monitor")
        test_frame = tabview.add("Network Tests")
        ipscan_frame = tabview.add("IP Scanner")

        ScannerTab(scanner_frame)
        ArpTab(arp_frame)
        TestTab(test_frame)
        IPScannerTab(ipscan_frame)


if __name__ == "__main__":
    app = App()
    app.mainloop()
