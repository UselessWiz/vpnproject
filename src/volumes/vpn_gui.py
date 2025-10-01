import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import os
import threading
import time
 
class VPNGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VPN Client")
        self.root.geometry("400x450")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f0f0")  # Light gray background
 
        # State variables
        self.is_vpn_on = False
        self.client_process = None
        self.status_thread = None
        self.running = False
 
        # Configure styles
        style = ttk.Style()
        style.configure("Main.TFrame", background="#f0f0f0")
        style.configure("Clean.TLabel", background="#f0f0f0", font=("Helvetica", 10))
        style.configure("Analytics.TLabel", background="#f0f0f0", font=("Helvetica", 10, "italic"))
        style.configure("Toggle.TButton", font=("Helvetica", 12, "bold"), padding=10)
 
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="15", style="Main.TFrame")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
 
        # Analytics placeholder
        self.analytics_frame = ttk.Frame(self.main_frame)
        self.analytics_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        self.analytics_label = ttk.Label(self.analytics_frame, text="Analytics: Not available", style="Analytics.TLabel")
        self.analytics_label.grid(row=0, column=0, sticky=tk.W)
 
        # Encryption version selection
        ttk.Label(self.main_frame, text="Encryption Version", style="Clean.TLabel").grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.version_var = tk.StringVar(value="RSA")
        versions = ["RSA", "QUIC", "X25519"]
        self.version_dropdown = ttk.Combobox(self.main_frame, textvariable=self.version_var, values=versions, state="readonly", width=25)
        self.version_dropdown.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
 
        # Key directory input
        ttk.Label(self.main_frame, text="Key Directory", style="Clean.TLabel").grid(row=3, column=0, sticky=tk.W, pady=(0, 5))
        self.key_dir_var = tk.StringVar(value=os.path.join(os.getcwd(), "keys"))
        self.key_entry = ttk.Entry(self.main_frame, textvariable=self.key_dir_var, width=20)
        self.key_entry.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        ttk.Button(self.main_frame, text="Browse", command=self.browse_key_dir).grid(row=4, column=1, sticky=tk.W, pady=(0, 20))
 
        # On/Off toggle button
        self.toggle_button = ttk.Button(self.main_frame, text="On", command=self.toggle_vpn, style="Toggle.TButton")
        self.toggle_button.grid(row=5, column=0, columnspan=2, pady=20)
 
        # Status label
        self.status_var = tk.StringVar(value="Status: Disconnected")
        ttk.Label(self.main_frame, textvariable=self.status_var, style="Clean.TLabel").grid(row=6, column=0, columnspan=2, pady=(0, 10))
 
        # Log window
        self.log_text = tk.Text(self.main_frame, height=8, width=40, state="disabled", bg="#ffffff", relief="flat", borderwidth=1)
        self.log_text.grid(row=7, column=0, columnspan=2, pady=10)
 
    def browse_key_dir(self):
        """Open file dialog to select key directory."""
        directory = filedialog.askdirectory(initialdir=self.key_dir_var.get(), title="Select Key Directory")
        if directory:
            self.key_dir_var.set(directory)
 
    def log_message(self, message):
        """Append a message to the log window."""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')}: {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")
 
    def check_connectivity(self):
        """Check connectivity to 192.168.60.7 using ping."""
        try:
            result = subprocess.run(
                ["docker", "exec", "client-10.9.0.5", "ping", "-c", "1", "192.168.60.7"],
                capture_output=True, text=True, timeout=5
            )
            return "Connected" if result.returncode == 0 else "Disconnected"
        except subprocess.SubprocessError as e:
            self.log_message(f"Connectivity check failed: {str(e)}")
            return "Error"
 
    def update_status(self):
        """Periodically update connection status."""
        while self.running:
            status = self.check_connectivity()
            self.status_var.set(f"Status: {status}")
            self.root.update()
            time.sleep(5)
 
    def toggle_vpn(self):
        """Toggle VPN on or off."""
        if not self.is_vpn_on:
            self.start_vpn()
        else:
            self.stop_vpn()
 
    def start_vpn(self):
        """Start the VPN client."""
        version = self.version_var.get()
        key_dir = self.key_dir_var.get()
 
        # Validate key directory
        if not os.path.isdir(key_dir):
            messagebox.showerror("Error", "Invalid key directory")
            self.log_message("Invalid key directory")
            return
 
        # Check for required key files
        key_path = os.path.join(key_dir, version, "client_private.pem" if version == "RSA" else "x-client_private.pem")
        if not os.path.isfile(key_path):
            messagebox.showerror("Error", f"Missing key file: {key_path}")
            self.log_message(f"Missing key file: {key_path}")
            return
 
        self.toggle_button.config(text="Off")
        self.is_vpn_on = True
        self.log_message(f"Starting VPN with {version}...")
 
        try:
            # Run client script via Docker
            client_cmd = ["docker", "exec", "-d", "client-10.9.0.5",
                "env", f"PYTHONPATH=/volumes",
                "python3", f"/volumes/client/{version}_client.py"
            ]
            self.client_process = subprocess.Popen(client_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.log_message(f"Started {version} client")
 
            # Start status checking thread
            self.running = True
            self.status_thread = threading.Thread(target=self.update_status, daemon=True)
            self.status_thread.start()
 
        except subprocess.SubprocessError as e:
            self.log_message(f"Failed to start VPN: {str(e)}")
            messagebox.showerror("Error", f"Failed to start VPN: {str(e)}")
            self.toggle_button.config(text="On")
            self.is_vpn_on = False
 
    def stop_vpn(self):
        """Stop the VPN client."""
        self.running = False
        self.toggle_button.config(text="On")
        self.is_vpn_on = False
 
        if self.client_process:
            try:
                subprocess.run(["docker", "exec", "-d", "client-10.9.0.5", "pkill", "python3"])
                self.client_process.terminate()
                self.client_process.wait(timeout=5)
                self.log_message("VPN client stopped")
            except subprocess.SubprocessError as e:
                self.log_message(f"Failed to stop VPN: {str(e)}")
                messagebox.showerror("Error", f"Failed to stop VPN: {str(e)}")
            self.client_process = None
 
        self.status_var.set("Status: Disconnected")
 
    def on_closing(self):
        """Handle window close event."""
        if self.is_vpn_on:
            self.stop_vpn()
        self.root.destroy()
 
if __name__ == "__main__":
    root = tk.Tk()
    app = VPNGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()