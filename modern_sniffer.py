import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import threading
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, DNS, wrpcap
import time

# Set modern UI themes
ctk.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class ModernPacketSniffer(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("NetVision - Advanced Packet Analyzer")
        self.geometry("1050x750")
        
        self.sniffing = False
        self.packet_data = [] 
        self.packet_count = 0
        
        self.setup_ui()

    def setup_ui(self):
        # Configure Grid Layout
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ================= TOP CONTROL BAR =================
        self.top_frame = ctk.CTkFrame(self, height=60, corner_radius=10)
        self.top_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        self.title_label = ctk.CTkLabel(self.top_frame, text="Network Traffic Analyzer", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.pack(side="left", padx=20, pady=15)

        self.start_btn = ctk.CTkButton(self.top_frame, text="▶ Start Capture", fg_color="#28a745", hover_color="#218838", 
                                       command=self.start_sniffing, font=ctk.CTkFont(weight="bold"))
        self.start_btn.pack(side="left", padx=10)
        
        self.stop_btn = ctk.CTkButton(self.top_frame, text="⏹ Stop Capture", fg_color="#dc3545", hover_color="#c82333", 
                                      command=self.stop_sniffing, state="disabled", font=ctk.CTkFont(weight="bold"))
        self.stop_btn.pack(side="left", padx=10)

        # Save PCAP Button
        self.save_btn = ctk.CTkButton(self.top_frame, text="💾 Save PCAP", fg_color="#007bff", hover_color="#0056b3", 
                                      command=self.save_pcap, font=ctk.CTkFont(weight="bold"))
        self.save_btn.pack(side="left", padx=10)

        # Save Text Report Button
        self.txt_btn = ctk.CTkButton(self.top_frame, text="📄 Save Text", fg_color="#ffc107", hover_color="#e0a800", text_color="black",
                                     command=self.save_text_report, font=ctk.CTkFont(weight="bold"))
        self.txt_btn.pack(side="left", padx=10)

        self.status_lbl = ctk.CTkLabel(self.top_frame, text="Status: Ready", text_color="gray", font=ctk.CTkFont(size=14))
        self.status_lbl.pack(side="right", padx=20)

        # ================= MIDDLE: PACKET TABLE =================
        self.table_frame = ctk.CTkFrame(self, corner_radius=10)
        self.table_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        self.table_frame.pack_propagate(False)

        # Style the standard Treeview to match Dark Mode
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", 
                        background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b",
                        rowheight=30, borderwidth=0, font=("Segoe UI", 10))
        style.map("Treeview", background=[("selected", "#1f538d")])
        style.configure("Treeview.Heading", 
                        background="#333333", foreground="white", font=("Segoe UI", 11, "bold"), borderwidth=0)

        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        
        self.tree.heading("No", text="#")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source IP")
        self.tree.heading("Destination", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        
        self.tree.column("No", width=50, anchor="center")
        self.tree.column("Time", width=100, anchor="center")
        self.tree.column("Source", width=180, anchor="center")
        self.tree.column("Destination", width=180, anchor="center")
        self.tree.column("Protocol", width=100, anchor="center")
        self.tree.column("Length", width=100, anchor="center")
        
        self.tree.pack(fill="both", expand=True, padx=2, pady=2)
        self.tree.bind("<<TreeviewSelect>>", self.display_packet_details)

        # ================= BOTTOM: LAYER ANALYSIS =================
        self.details_frame = ctk.CTkFrame(self, corner_radius=10)
        self.details_frame.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="nsew")
        
        self.details_label = ctk.CTkLabel(self.details_frame, text="Layer-wise Header Analysis", font=ctk.CTkFont(size=16, weight="bold"))
        self.details_label.pack(anchor="w", padx=15, pady=(10, 0))

        self.details_box = ctk.CTkTextbox(self.details_frame, font=ctk.CTkFont(family="Consolas", size=13), 
                                          fg_color="#1e1e1e", text_color="#4af626") # Hacker green text
        self.details_box.pack(fill="both", expand=True, padx=15, pady=10)
        self.details_box.insert("0.0", "Select a packet from the table to view its layer-wise breakdown here...")

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_lbl.configure(text="Status: Capturing (Live)...", text_color="#28a745")
        
        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_lbl.configure(text="Status: Stopped", text_color="#dc3545")

    def sniff_packets(self):
        try:
            sniff(prn=self.process_packet, stop_filter=lambda p: not self.sniffing)
        except Exception as e:
            messagebox.showerror("Permission Error", f"Failed to start sniffing.\nEnsure you are running as Administrator/root.\n\nError details: {e}")
            self.after(0, self.stop_sniffing)

    def process_packet(self, packet):
        if not self.sniffing:
            return

        self.packet_count += 1
        self.packet_data.append(packet)
        
        timestamp = time.strftime('%H:%M:%S', time.localtime(packet.time))
        length = len(packet)
        
        src_ip, dst_ip, protocol = "Unknown", "Unknown", "Unknown"

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if packet.haslayer(ICMP): protocol = "ICMP"
            elif packet.haslayer(DNS): protocol = "DNS"
            elif packet.haslayer(TCP):
                if packet[TCP].sport in [80, 8080] or packet[TCP].dport in [80, 8080]: protocol = "HTTP"
                elif packet[TCP].sport == 443 or packet[TCP].dport == 443: protocol = "HTTPS"
                else: protocol = "TCP"
            elif packet.haslayer(UDP): protocol = "UDP"
            else: protocol = "IPv4"
        elif packet.haslayer(Ether):
            src_ip = packet[Ether].src
            dst_ip = packet[Ether].dst
            protocol = "ARP/Ethernet"

        self.after(0, self.tree.insert, "", "end", iid=self.packet_count-1, 
                   values=(self.packet_count, timestamp, src_ip, dst_ip, protocol, length))

        # Auto-scroll to bottom of table if active
        self.after(0, self.tree.yview_moveto, 1)

    def display_packet_details(self, event):
        selected_item = self.tree.selection()
        if not selected_item: return
        
        index = int(selected_item[0])
        packet = self.packet_data[index]
        
        self.details_box.delete("0.0", "end")
        analysis = self.generate_analysis_text(packet, index)
        self.details_box.insert("0.0", analysis)

    def generate_analysis_text(self, packet, index):
        """Helper function to generate the text breakdown for both UI and saving"""
        analysis = f"================ FRAME #{index + 1} SUMMARY ================\n\n"
        
        if packet.haslayer(Ether):
            analysis += "[+] ETHERNET LAYER (OSI Layer 2)\n"
            analysis += f"    ├─ Source MAC      : {packet[Ether].src}\n"
            analysis += f"    ├─ Destination MAC : {packet[Ether].dst}\n"
            analysis += f"    └─ Protocol Type   : {hex(packet[Ether].type)}\n\n"
            
        if packet.haslayer(IP):
            analysis += "[+] IP LAYER (OSI Layer 3)\n"
            analysis += f"    ├─ Source IP       : {packet[IP].src}\n"
            analysis += f"    ├─ Destination IP  : {packet[IP].dst}\n"
            analysis += f"    ├─ TTL (Time/Live) : {packet[IP].ttl}\n"
            analysis += f"    └─ Header Length   : {packet[IP].ihl * 4} bytes\n\n"
            
        if packet.haslayer(TCP):
            analysis += "[+] TCP LAYER (OSI Layer 4)\n"
            analysis += f"    ├─ Source Port     : {packet[TCP].sport}\n"
            analysis += f"    ├─ Dest Port       : {packet[TCP].dport}\n"
            analysis += f"    ├─ Sequence No     : {packet[TCP].seq}\n"
            analysis += f"    ├─ Acknowledgment  : {packet[TCP].ack}\n"
            analysis += f"    └─ Flags           : {packet[TCP].flags}\n\n"
            
        elif packet.haslayer(UDP):
            analysis += "[+] UDP LAYER (OSI Layer 4)\n"
            analysis += f"    ├─ Source Port     : {packet[UDP].sport}\n"
            analysis += f"    ├─ Dest Port       : {packet[UDP].dport}\n"
            analysis += f"    └─ Length          : {packet[UDP].len} bytes\n\n"
            
        if packet.haslayer(ICMP):
            analysis += "[+] ICMP LAYER (Network Diagnostic)\n"
            analysis += f"    ├─ Type            : {packet[ICMP].type}\n"
            analysis += f"    └─ Code            : {packet[ICMP].code}\n\n"
            
        if packet.haslayer(DNS):
            analysis += "[+] DNS LAYER (Application Layer)\n"
            analysis += f"    ├─ Transaction ID  : {hex(packet[DNS].id)}\n"
            if packet.haslayer('DNS Question Record'):
                analysis += f"    └─ Query Name      : {packet['DNS Question Record'].qname.decode('utf-8', 'ignore')}\n\n"
                
        return analysis

    def save_pcap(self):
        # Prevent saving if no packets exist
        if not self.packet_data:
            messagebox.showwarning("Warning", "No packets to save. Please capture some traffic first.")
            return
            
        # Open a "Save As" dialog box
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Save Captured Packets"
        )
        
        if file_path:
            try:
                wrpcap(file_path, self.packet_data)
                messagebox.showinfo("Success", f"Successfully saved {len(self.packet_data)} packets to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file:\n{str(e)}")

    def save_text_report(self):
        # Prevent saving if no packets exist
        if not self.packet_data:
            messagebox.showwarning("Warning", "No packets to save. Please capture some traffic first.")
            return
            
        # Open a "Save As" dialog box
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Text Report"
        )
        
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("================ NETVISION PACKET ANALYSIS REPORT ================\n")
                    f.write(f"Total Packets Captured: {len(self.packet_data)}\n")
                    f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("==================================================================\n\n")
                    
                    for index, packet in enumerate(self.packet_data):
                        f.write(self.generate_analysis_text(packet, index) + "\n")
                        
                messagebox.showinfo("Success", f"Text report successfully saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save text file:\n{str(e)}")

if __name__ == "__main__":
    app = ModernPacketSniffer()
    app.mainloop()
