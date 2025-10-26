import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import os
import threading
import time
import re
import math 

# --- Configuration Constants for VM Environment ---
# Assuming the 'volumes' shared folder is auto-mounted here in the Linux VM
VPN_SCRIPT_BASE_PATH = "/volumes" 
# The server's IP address for server connectivity testing
VPN_SERVER_IP = "10.9.0.11" 
# Timeout for analytics commands
ANALYTICS_TIMEOUT = 10

class VPNGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("KYBER Tunnel")
        self.root.geometry("400x650")
        self.root.resizable(False, False)

        # --- Modern Color and Font Scheme ---
        self.COLOR_BG = "#F0F8FF"
        self.COLOR_FRAME = "#FFFFFF"
        self.COLOR_PRIMARY_BLUE = "#4A90E2"
        self.COLOR_DEEP_BLUE = "#00529B"
        self.COLOR_LIGHT_BLUE = "#EAF5FF"
        self.COLOR_TEXT = "#333333"
        self.COLOR_CONNECTED = "#34C759"
        self.FONT_MAIN = ("Segoe UI", 10)
        self.FONT_BOLD = ("Segoe UI", 10, "bold")
        self.FONT_LARGE_BOLD = ("Segoe UI", 12, "bold")
        self.FONT_SMALL_ITALIC = ("Segoe UI", 8, "italic")

        self.root.configure(bg=self.COLOR_BG)

        # --- State variables ---
        self.is_vpn_on = False
        self.client_process = None
        self.status_thread = None
        self.running = False
        self.download_var = tk.StringVar(value="--- Mbps")
        self.upload_var = tk.StringVar(value="--- Mbps")
        self.latency_var = tk.StringVar(value="--- ms")
        self.wave_color = self.COLOR_DEEP_BLUE
        self.wave_speed_multiplier = 4  # Default speed
        self.wave_refresh_ms = 100      # Default refresh rate
        self.wave_update_id = None

        # --- Configure ttk Styles ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background=self.COLOR_BG)
        style.configure("Card.TFrame", background=self.COLOR_FRAME)
        style.configure("TLabel", background=self.COLOR_FRAME, foreground=self.COLOR_TEXT, font=self.FONT_MAIN)
        style.configure("Status.TLabel", background=self.COLOR_BG, font=self.FONT_LARGE_BOLD)
        style.configure("Metric.TLabel", background=self.COLOR_FRAME, font=self.FONT_BOLD, foreground=self.COLOR_DEEP_BLUE)
        style.configure("TButton", font=self.FONT_BOLD, padding=8)
        style.configure("White.TNotebook", background=self.COLOR_FRAME, borderwidth=0)
        style.configure("White.TNotebook.Tab", background="#EAEAEA", foreground=self.COLOR_TEXT, borderwidth=0, padding=[10, 5])
        style.map("White.TNotebook.Tab", background=[("selected", self.COLOR_FRAME)], foreground=[("selected", self.COLOR_PRIMARY_BLUE)])
        
        # --- Main Frame ---
        self.main_frame = ttk.Frame(self.root, padding="15")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Status Display ---
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var, style="Status.TLabel", foreground=self.COLOR_DEEP_BLUE)
        self.status_label.pack(pady=(10, 5))
        
        # --- Main Power Button ---
        self.power_button_canvas = tk.Canvas(self.main_frame, width=130, height=130, bg=self.COLOR_BG, bd=0, highlightthickness=0)
        self.power_button_canvas.pack(pady=20)
        self.power_button_outer = self.power_button_canvas.create_oval(5, 5, 125, 125, fill=self.COLOR_LIGHT_BLUE, outline="#D1D1D1", width=1)
        self.power_button_inner = self.power_button_canvas.create_oval(15, 15, 115, 115, fill=self.COLOR_DEEP_BLUE, outline="")
        self.power_button_text = self.power_button_canvas.create_text(65, 65, text="CONNECT", font=("Segoe UI", 12, "bold"), fill=self.COLOR_FRAME)
        self.power_button_canvas.bind("<Button-1>", lambda event: self.toggle_vpn())
        
        # --- Latency and Performance Metrics Section ---
        graph_frame = ttk.Frame(self.main_frame, style="Card.TFrame")
        graph_frame.pack(fill=tk.X, pady=10)
        
        self.latency_canvas = tk.Canvas(graph_frame, height=60, bg=self.COLOR_FRAME, bd=0, highlightthickness=0)
        self.latency_canvas.pack(fill=tk.X, padx=10, pady=(10, 5))
        self.draw_graph_wave()

        metrics_frame = ttk.Frame(graph_frame, style="Card.TFrame")
        metrics_frame.pack(fill=tk.X, padx=10, pady=(0,10))
        metrics_frame.columnconfigure((0,1,2), weight=1)

        ttk.Label(metrics_frame, text="DOWNLOAD", font=self.FONT_SMALL_ITALIC).grid(row=0, column=0)
        ttk.Label(metrics_frame, textvariable=self.download_var, font=self.FONT_BOLD, style="Metric.TLabel").grid(row=1, column=0)
        
        ttk.Label(metrics_frame, text="UPLOAD", font=self.FONT_SMALL_ITALIC).grid(row=0, column=1)
        ttk.Label(metrics_frame, textvariable=self.upload_var, font=self.FONT_BOLD, style="Metric.TLabel").grid(row=1, column=1)
        
        ttk.Label(metrics_frame, text="LATENCY", font=self.FONT_SMALL_ITALIC).grid(row=0, column=2)
        ttk.Label(metrics_frame, textvariable=self.latency_var, font=self.FONT_BOLD, style="Metric.TLabel").grid(row=1, column=2)

        # --- Configuration & Log Tabs ---
        notebook = ttk.Notebook(self.main_frame, style="White.TNotebook")
        notebook.pack(fill="both", expand="true", pady=(10,0))
        
        config_frame = ttk.Frame(notebook, style="Card.TFrame", padding=15)
        log_frame = ttk.Frame(notebook, style="Card.TFrame", padding=15)
        
        notebook.add(config_frame, text='Settings')
        notebook.add(log_frame, text='Activity Log')
        
        self.create_config_widgets(config_frame)
        self.create_log_widgets(log_frame)

    def create_config_widgets(self, parent):
        parent.columnconfigure(1, weight=1)
        ttk.Label(parent, text="Encryption:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.version_var = tk.StringVar(value="ML-KEM")
        versions = ["ML-KEM", "X25519", "QUIC", "RSA"]
        self.version_dropdown = ttk.Combobox(parent, textvariable=self.version_var, values=versions, state="readonly")
        self.version_dropdown.grid(row=0, column=1, columnspan=2, sticky=tk.EW, pady=5, padx=5)

        ttk.Label(parent, text="Key Directory:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.key_dir_var = tk.StringVar(value=os.path.join("/keys"))
        self.key_entry = ttk.Entry(parent, textvariable=self.key_dir_var)
        self.key_entry.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=5)
        ttk.Button(parent, text="Browse", command=self.browse_key_dir).grid(row=1, column=2, sticky=tk.E, pady=5, padx=5)

    def create_log_widgets(self, parent):
        self.log_text = tk.Text(parent, height=5, state="disabled", bg=self.COLOR_BG, relief="solid", borderwidth=1, font=("Courier New", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def draw_graph_wave(self):
        """Draws a sine wave on the canvas, simulating network activity."""
        self.latency_canvas.delete("wave_line")
        width = 370 
        height = 60 
        
        amplitude = 15
        center_y = height / 2
        frequency = 0.05
        
        t = time.time()
        
        points = []
        for x in range(0, width + 1, 10):
            y = center_y + amplitude * math.sin(x * frequency + t * self.wave_speed_multiplier)
            points.extend([x, y])
            
        self.latency_canvas.create_line(points, fill=self.wave_color, width=2, tags="wave_line")

        self.wave_update_id = self.root.after(100, self.draw_graph_wave)

    def update_visual_state(self, connected):
        if connected:
            self.status_var.set("Connected")
            self.status_label.config(foreground=self.COLOR_CONNECTED)
            self.power_button_canvas.itemconfig(self.power_button_inner, fill=self.COLOR_CONNECTED)
            self.power_button_canvas.itemconfig(self.power_button_text, text="DISCONNECT")
            
            self.wave_color = self.COLOR_CONNECTED  # Turn green
            self.wave_speed_multiplier = 8  # Make it faster (was 4)
            self.wave_refresh_ms = 50       # Make it refresh faster (was 100)
             
        else:
            self.status_var.set("Disconnected")
            self.status_label.config(foreground=self.COLOR_DEEP_BLUE)
            self.power_button_canvas.itemconfig(self.power_button_inner, fill=self.COLOR_DEEP_BLUE)
            self.power_button_canvas.itemconfig(self.power_button_text, text="CONNECT")
            self.reset_analytics_labels()
            
    def reset_analytics_labels(self):
        self.download_var.set("--- Mbps")
        self.upload_var.set("--- Mbps")
        self.latency_var.set("--- ms")

        self.wave_color = self.COLOR_DEEP_BLUE
        self.wave_speed_multiplier = 4
        self.wave_refresh_ms = 100
        self.draw_graph_wave()

    def fetch_and_update_analytics(self):
        # Fetch Latency (using ping)
        try:
            # Command to run ping with sudo in the Linux VM
            ping_cmd = ["sudo", "ping", "-c", "1", VPN_SERVER_IP]
            result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and self.status_var.get() == "Connected":
                match = re.search(r"time=([\d\.]+)\s*ms", result.stdout)
                if match:
                    self.latency_var.set(f"{float(match.group(1)):.1f} ms")
        except subprocess.SubprocessError:
            self.latency_var.set("Error")

        # Fetch Download Speed (Server -> Client, iperf3 -R)
        try:
            # Command to run iperf3 with sudo in the Linux VM
            dl_cmd = ["iperf3", "-c", VPN_SERVER_IP, "-R", "-t", "4", "-f", "m"]
            result = subprocess.run(dl_cmd, capture_output=True, text=True, timeout=ANALYTICS_TIMEOUT)
            if result.returncode == 0 and self.status_var.get() == "Connected":
                match = re.search(r"(\d+\.?\d*)\s+Mbits/sec\s+.*receiver", result.stdout)
                if match:
                    self.download_var.set(f"{float(match.group(1)):.2f} Mbps")
        except subprocess.SubprocessError:
            self.download_var.set("Error")

        # Fetch Upload Speed (Client -> Server, iperf3)
        try:
            # Command to run iperf3 with sudo in the Linux VM
            ul_cmd = ["iperf3", "-c", VPN_SERVER_IP, "-t", "4", "-f", "m"]
            result = subprocess.run(ul_cmd, capture_output=True, text=True, timeout=ANALYTICS_TIMEOUT)
            if result.returncode == 0 and self.status_var.get() == "Connected":
                match = re.search(r"(\d+\.?\d*)\s+Mbits/sec\s+.*sender", result.stdout)
                if match:
                    self.upload_var.set(f"{float(match.group(1)):.2f} Mbps")
        except subprocess.SubprocessError:
            self.upload_var.set("Error")
            
    def browse_key_dir(self):
        directory = filedialog.askdirectory(initialdir=self.key_dir_var.get(), title="Select Key Directory")
        if directory:
            self.key_dir_var.set(directory)

    def log_message(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')}: {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def check_connectivity(self):
        try:
            # Command to check connectivity using ping in the Linux VM
            result = subprocess.run(
                ["ping", "-c", "1", VPN_SERVER_IP],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except subprocess.SubprocessError:
            return False

    def update_status_loop(self):
        """Continuously checks status and fetches analytics if connected."""
        while self.running:
            is_connected = self.check_connectivity()
            
            if self.root.winfo_exists():
                self.update_visual_state(is_connected)
                
                if is_connected:
                    self.fetch_and_update_analytics()
                else:
                    self.reset_analytics_labels()

            time.sleep(2)

    def toggle_vpn(self):
        if not self.is_vpn_on:
            self.start_vpn()
        else:
            self.stop_vpn()

    def start_vpn(self):
        version = self.version_var.get()
        key_dir = self.key_dir_var.get()

        if not os.path.isdir(key_dir):
            messagebox.showerror("Error", "Invalid key directory")
            return

        if version == "RSA":
            key_file_name = "client_private.pem"
        elif version == "ML-KEM":
            # Assuming ML-KEM uses a specific file name like client_private.key
            key_file_name = "mlkem-client_private.pem" 
        elif version == "X25519": # Covers X25519
            key_file_name = "x-client_private.pem"
            # QUIC keys are handled internally by the aioquic library, nothing else required.
            
        if version != "QUIC":
            key_path = os.path.join(key_dir, version, key_file_name)
        
            if not os.path.isfile(key_path):
                # Check for the key file inside the shared folder path as a fallback for mounting issues
                key_path_alt = os.path.join(VPN_SCRIPT_BASE_PATH, "keys", version, key_file_name)
                if not os.path.isfile(key_path_alt):
                     messagebox.showerror("Error", f"Missing key file at both {key_path} and {key_path_alt}")
                     return
                key_path = key_path_alt
        
        self.is_vpn_on = True
        self.status_var.set("Connecting...")
        self.log_message(f"Starting VPN with {version}...")
        
        #if self.wave_update_id:
        #    self.root.after_cancel(self.wave_update_id)
        #self.placeholder_wave_running = False

        try:
            client_cmd = ["sudo", 
                          "env", 
                          f"PYTHONPATH={VPN_SCRIPT_BASE_PATH}", # Sets PYTHONPATH to the volumes share
                          "python3", 
                          f"{VPN_SCRIPT_BASE_PATH}/client/{version}_client.py",
                          "&" # Run in background
                         ]
            subprocess.Popen(client_cmd)
            self.log_message(f"Started {version} client")

            self.running = True
            self.status_thread = threading.Thread(target=self.update_status_loop, daemon=True)
            self.status_thread.start()

        except subprocess.SubprocessError as e:
            self.log_message(f"Failed to start VPN: {str(e)}")
            messagebox.showerror("Error", f"Failed to start VPN: {str(e)}")
            self.is_vpn_on = False
            self.update_visual_state(False)

    def stop_vpn(self):
        self.running = False
        self.is_vpn_on = False
        
        try:
            # Kills the Python client script running in the background
            kill_cmd = ["sudo", "pkill", "-f", "client.py"]
            subprocess.run(kill_cmd, timeout=5)
            self.log_message("VPN client stopped")
        except subprocess.SubprocessError as e:
            self.log_message(f"Sent stop command, but an error occurred: {str(e)}")
        finally:
            self.update_visual_state(False)

    def on_closing(self):
        if self.is_vpn_on:
            self.stop_vpn()
        
        if self.wave_update_id:
            self.root.after_cancel(self.wave_update_id)
            
        self.root.destroy()

# --- Entry Point & Main Loop handling for the VPN GUI ---

if __name__ == "__main__":
    root = tk.Tk()
    app = VPNGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()