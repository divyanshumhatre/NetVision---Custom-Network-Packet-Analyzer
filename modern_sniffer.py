# NetVision - Custom Network Packet Analyzer
# Project Team: Divyanshu Mhatre (426), Adheesh Nair (537), Deep Malbari (522), Muzamil Ahmad Wani (534), Abhijit Nair (535)
# Pillai College of Engineering - Cryptography and System Security

import os
import threading
from datetime import datetime
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, DNS, Raw

# Feature: Automatically hide the command prompt window on Windows
if os.name == 'nt':
    import ctypes
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

class NetVisionApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NetVision - Network Packet Analyzer")
        self.geometry("1000x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Application State
        self.capturing = False
        self.packet_list = []
        self.packet_count = 0
        self.auto_scroll = ctk.BooleanVar(value=True)

        self.setup_ui()

    def setup_ui(self):
        # Top Control Panel
        control_frame = ctk.CTkFrame(self)
        control_frame.pack(fill="x", padx=10, pady=10)

        self.start_btn = ctk.CTkButton(control_frame, text="▶ Start Capture", fg_color="green", hover_color="darkgreen", command=self.start_capture)
        self.start_btn.pack(side="left", padx=5, pady=5)

        self.stop_btn = ctk.CTkButton(control_frame, text="⏹ Stop Capture", fg_color="red", hover_color="darkred", state="disabled", command=self.stop_capture)
        self.stop_btn.pack(side="left", padx=5, pady=5)

        self.clear_btn = ctk.CTkButton(control_frame, text="🗑️ Clear Data", fg_color="gray30", hover_color="gray20", command=self.clear_data)
        self.clear_btn.pack(side="left", padx=5, pady=5)

        self.export_pcap_btn = ctk.CTkButton(control_frame, text="💾 Save .PCAP", command=self.save_pcap)
        self.export_pcap_btn.pack(side="left", padx=5, pady=5)

        self.export_txt_btn = ctk.CTkButton(control_frame, text="📄 Save .TXT", command=self.save_txt)
        self.export_txt_btn.pack(side="left", padx=5, pady=5)

        # Feature: Auto-scroll toggle and packet counter
        self.scroll_check = ctk.CTkCheckBox(control_frame, text="Auto-Scroll", variable=self.auto_scroll)
        self.scroll_check.pack(side="right", padx=10)
        
        self.count_label = ctk.CTkLabel(control_frame, text="Packets: 0", font=("Arial", 14, "bold"))
        self.count_label.pack(side="right", padx=20)

        # Main Table (Treeview)
        table_frame = ctk.CTkFrame(self)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Styling the Treeview for Dark Mode
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", rowheight=25)
        style.configure("Treeview.Heading", background="#1f538d", foreground="white")
        style.map("Treeview", background=[('selected', '#14375e')])

        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor="center")
        self.tree.column("No.", width=50)
        self.tree.column("Time", width=100)
        self.tree.column("Info", width=250, anchor="w")
        
        # Scrollbar for table
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # Bottom Analysis Box
        self.analysis_box = ctk.CTkTextbox(self, height=200, font=("Consolas", 13), text_color="#2ECC71") # Hacker green text
        self.analysis_box.pack(fill="x", padx=10, pady=(0, 10))
        self.analysis_box.insert("0.0", "Select a packet to view OSI layer breakdown...")
        self.analysis_box.configure(state="disabled")

    def start_capture(self):
        self.capturing = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.capture_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.capturing = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def clear_data(self):
        self.packet_list.clear()
        self.packet_count = 0
        self.count_label.configure(text="Packets: 0")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.analysis_box.configure(state="normal")
        self.analysis_box.delete("0.0", "end")
        self.analysis_box.insert("0.0", "Data cleared. Ready for new capture...")
        self.analysis_box.configure(state="disabled")

    def sniff_packets(self):
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.capturing, store=False)

    def process_packet(self, packet):
        self.packet_list.append(packet)
        self.packet_count += 1
        
        time_str = datetime.now().strftime("%H:%M:%S")
        src = packet[Ether].src if Ether in packet else "Unknown"
        dst = packet[Ether].dst if Ether in packet else "Unknown"
        proto = "Unknown"
        info = ""
        length = len(packet)

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            if TCP in packet:
                proto = "TCP"
                if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                    proto = "HTTP"
                info = f"Src Port: {packet[TCP].sport} -> Dst Port: {packet[TCP].dport}"
            elif UDP in packet:
                proto = "UDP"
                if DNS in packet:
                    proto = "DNS"
                    info = f"Query: {packet[DNS].qd.qname.decode('utf-8', 'ignore') if packet[DNS].qd else 'N/A'}"
                else:
                    info = f"Src Port: {packet[UDP].sport} -> Dst Port: {packet[UDP].dport}"
            elif ICMP in packet:
                proto = "ICMP"
                info = f"Type: {packet[ICMP].type} (Ping)"

        item = self.tree.insert("", "end", values=(self.packet_count, time_str, src, dst, proto, length, info))
        
        # Safe GUI update from background thread
        self.after(0, self.update_counter)
        if self.auto_scroll.get():
            self.after(0, lambda: self.tree.see(item))

    def update_counter(self):
        self.count_label.configure(text=f"Packets: {self.packet_count}")

    def on_packet_select(self, event):
        selected_item = self.tree.focus()
        if not selected_item:
            return
            
        values = self.tree.item(selected_item, "values")
        if not values:
            return
            
        packet_idx = int(values[0]) - 1
        packet = self.packet_list[packet_idx]
        
        self.analysis_box.configure(state="normal")
        self.analysis_box.delete("0.0", "end")
        
        # Build OSI Layer Breakdown
        breakdown = f"--- FRAME {values[0]} ANALYSIS ---\n\n"
        
        if Ether in packet:
            breakdown += "[+] ETHERNET LAYER (Layer 2)\n"
            breakdown += f"    Source MAC:      {packet[Ether].src}\n"
            breakdown += f"    Destination MAC: {packet[Ether].dst}\n"
            breakdown += f"    Type:            {hex(packet[Ether].type)}\n\n"
            
        if IP in packet:
            breakdown += "[+] NETWORK LAYER (Layer 3 - IPv4)\n"
            breakdown += f"    Source IP:       {packet[IP].src}\n"
            breakdown += f"    Destination IP:  {packet[IP].dst}\n"
            breakdown += f"    TTL:             {packet[IP].ttl}\n\n"
            
        if TCP in packet:
            breakdown += "[+] TRANSPORT LAYER (Layer 4 - TCP)\n"
            breakdown += f"    Source Port:     {packet[TCP].sport}\n"
            breakdown += f"    Dest Port:       {packet[TCP].dport}\n"
            breakdown += f"    Sequence No:     {packet[TCP].seq}\n"
            breakdown += f"    Flags:           {packet[TCP].flags}\n\n"
            
        elif UDP in packet:
            breakdown += "[+] TRANSPORT LAYER (Layer 4 - UDP)\n"
            breakdown += f"    Source Port:     {packet[UDP].sport}\n"
            breakdown += f"    Dest Port:       {packet[UDP].dport}\n\n"
            
        if ICMP in packet:
            breakdown += "[+] DIAGNOSTIC LAYER (ICMP)\n"
            breakdown += f"    Type:            {packet[ICMP].type}\n"
            breakdown += f"    Code:            {packet[ICMP].code}\n\n"
            
        if DNS in packet and packet[DNS].qd:
            breakdown += "[+] APPLICATION LAYER (Layer 7 - DNS)\n"
            breakdown += f"    Query Name:      {packet[DNS].qd.qname.decode('utf-8', 'ignore')}\n\n"
            
        if Raw in packet:
            payload = packet[Raw].load[:50] # Show first 50 bytes
            breakdown += "[+] APPLICATION PAYLOAD (Raw Bytes)\n"
            breakdown += f"    Data:            {payload}\n"
            
        self.analysis_box.insert("0.0", breakdown)
        self.analysis_box.configure(state="disabled")

    def save_pcap(self):
        if not self.packet_list:
            messagebox.showwarning("Empty", "No packets to save!")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
        if filepath:
            wrpcap(filepath, self.packet_list)
            messagebox.showinfo("Success", f"Saved {len(self.packet_list)} packets to {filepath}")

    def save_txt(self):
        if not self.packet_list:
            messagebox.showwarning("Empty", "No packets to save!")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if filepath:
            with open(filepath, "w") as f:
                for idx, pkt in enumerate(self.packet_list, 1):
                    f.write(f"Packet {idx} Summary: {pkt.summary()}\n")
            messagebox.showinfo("Success", f"Saved report to {filepath}")

if __name__ == "__main__":
    app = NetVisionApp()
    app.mainloop()
