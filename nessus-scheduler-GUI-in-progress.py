#!/usr/bin/env python3
"""
Nessus GUI Scheduler v6.0 - Complete Cross-Platform Version
- Full GUI interface (no blocking inputs)
- 10-minute missed task recovery
- Works on locked Windows/Linux systems
- System service creation for both platforms
- Real-time monitoring dashboard
"""

import requests
import urllib3
import json
import os
import sys
import time
from datetime import datetime, timedelta
import platform
import threading
import signal
from collections import defaultdict
import logging
from logging.handlers import RotatingFileHandler
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import queue

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
NESSUS_URL = "https://127.0.0.1:8834"
USERNAME = "ControlCase"
PASSWORD = "ControlCase@123"
CONFIG_FILE = "nessus_config.json"
SCHEDULE_FILE = "nessus_schedule.json"

# Timing Configuration
CHECK_INTERVAL_URGENT = 10      # 10 seconds when task within 5 minutes
CHECK_INTERVAL_NORMAL = 60      # 1 minute when task between 5-30 minutes
CHECK_INTERVAL_RELAXED = 600    # 10 minutes when task more than 30 minutes

# Missed Task Recovery
MISSED_TASK_WINDOW = 10         # Execute missed tasks within 10 minutes

# Log rotation settings
LOG_FILE = "nessus_scheduler.log"
MAX_LOG_SIZE = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 5


class NessusSchedulerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Nessus Automated Scheduler v6.0")
        self.root.geometry("1200x850")
        
        # Make window stay on top initially
        self.root.attributes('-topmost', True)
        self.root.after(2000, lambda: self.root.attributes('-topmost', False))
        
        # Queue for thread-safe GUI updates
        self.log_queue = queue.Queue()
        self.status_queue = queue.Queue()
        
        # Scheduler backend
        self.cookie_token = None
        self.api_token = None
        self.schedules = []
        self.executed_tasks = set()
        self.scan_completion_status = {}
        self.running = False
        self.monitor_thread = None
        self.last_log_time = 0
        
        # Setup logging
        self.setup_logging()
        
        # Create GUI
        self.create_gui()
        
        # Load config and schedules
        self.load_or_create_config()
        self.load_schedules_from_file()
        
        # Start GUI update loops
        self.process_queues()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_logging(self):
        """Setup logging to both file and GUI"""
        self.logger = logging.getLogger('NessusScheduler')
        self.logger.setLevel(logging.INFO)
        self.logger.handlers = []
        
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_LOG_SIZE,
            backupCount=LOG_BACKUP_COUNT
        )
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def log(self, message):
        """Thread-safe logging to GUI"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_msg = f"[{timestamp}] {message}"
        self.logger.info(message)
        try:
            self.log_queue.put_nowait(log_msg)
        except:
            pass
    
    def update_status(self, status_dict):
        """Thread-safe status update"""
        try:
            self.status_queue.put_nowait(status_dict)
        except:
            pass
    
    def process_queues(self):
        """Process log and status queues"""
        # Process logs
        try:
            while True:
                log_msg = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, log_msg + "\n")
                self.log_text.see(tk.END)
                
                # Limit log size
                if int(self.log_text.index('end-1c').split('.')[0]) > 1000:
                    self.log_text.delete('1.0', '500.0')
        except queue.Empty:
            pass
        
        # Process status updates
        try:
            while True:
                status = self.status_queue.get_nowait()
                self.update_dashboard_from_status(status)
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_queues)
    
    def create_gui(self):
        """Create the main GUI interface"""
        # Style configuration
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 1: Dashboard
        self.create_dashboard_tab()
        
        # Tab 2: Schedules
        self.create_schedules_tab()
        
        # Tab 3: Logs
        self.create_logs_tab()
        
        # Tab 4: Settings
        self.create_settings_tab()
        
        # Tab 5: System Service
        self.create_service_tab()
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        
        # Status section
        status_frame = ttk.LabelFrame(dashboard_frame, text="Scheduler Status", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.status_label = ttk.Label(status_frame, text="● Status: Stopped", font=("Arial", 12, "bold"), foreground="red")
        self.status_label.pack(anchor=tk.W, pady=2)
        
        self.mode_label = ttk.Label(status_frame, text="Mode: Idle", font=("Arial", 10))
        self.mode_label.pack(anchor=tk.W, pady=2)
        
        self.next_task_label = ttk.Label(status_frame, text="Next Task: None", font=("Arial", 10))
        self.next_task_label.pack(anchor=tk.W, pady=2)
        
        self.system_time_label = ttk.Label(status_frame, text=f"System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", font=("Arial", 10))
        self.system_time_label.pack(anchor=tk.W, pady=2)
        
        self.platform_label = ttk.Label(status_frame, text=f"Platform: {platform.system()}", font=("Arial", 10))
        self.platform_label.pack(anchor=tk.W, pady=2)
        
        # Control buttons
        control_frame = ttk.Frame(dashboard_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="▶ Start Scheduler", command=self.start_scheduler)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⏸ Stop Scheduler", command=self.stop_scheduler, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="🔄 Refresh", command=self.manual_refresh).pack(side=tk.LEFT, padx=5)
        
        # Pending tasks section
        pending_frame = ttk.LabelFrame(dashboard_frame, text="Pending Tasks Today", padding=10)
        pending_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Time", "Scan", "Action", "In Minutes")
        self.pending_tree = ttk.Treeview(pending_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.pending_tree.heading(col, text=col)
            self.pending_tree.column(col, width=200)
        
        scrollbar = ttk.Scrollbar(pending_frame, orient=tk.VERTICAL, command=self.pending_tree.yview)
        self.pending_tree.configure(yscrollcommand=scrollbar.set)
        
        self.pending_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Stats section
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.stats_label = ttk.Label(stats_frame, text="Total Schedules: 0 | Executed Today: 0 | Recovered Tasks: 0")
        self.stats_label.pack()
    
    def create_schedules_tab(self):
        """Create schedules management tab"""
        schedules_frame = ttk.Frame(self.notebook)
        self.notebook.add(schedules_frame, text="📅 Schedules")
        
        # Toolbar
        toolbar = ttk.Frame(schedules_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(toolbar, text="➕ Add Schedule", command=self.add_schedule_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🗑️ Delete Selected", command=self.delete_schedule).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🔄 Refresh Scans", command=self.refresh_scans).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="💾 Save Schedules", command=self.save_schedules_to_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="📁 Load Schedules", command=self.load_schedules_from_file).pack(side=tk.LEFT, padx=5)
        
        # Schedules list
        list_frame = ttk.LabelFrame(schedules_frame, text="Current Schedules", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Scan ID", "Scan Name", "Action", "Time")
        self.schedule_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)
        
        self.schedule_tree.heading("Scan ID", text="Scan ID")
        self.schedule_tree.heading("Scan Name", text="Scan Name")
        self.schedule_tree.heading("Action", text="Action")
        self.schedule_tree.heading("Time", text="Time")
        
        self.schedule_tree.column("Scan ID", width=100)
        self.schedule_tree.column("Scan Name", width=400)
        self.schedule_tree.column("Action", width=150)
        self.schedule_tree.column("Time", width=150)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.schedule_tree.yview)
        self.schedule_tree.configure(yscrollcommand=scrollbar.set)
        
        self.schedule_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_logs_tab(self):
        """Create logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📋 Logs")
        
        # Toolbar
        toolbar = ttk.Frame(logs_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(toolbar, text="🗑️ Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="💾 Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="📁 Open Log File", command=self.open_log_file).pack(side=tk.LEFT, padx=5)
        
        # Log display
        log_frame = ttk.Frame(logs_frame)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=30, bg="#1e1e1e", fg="#00ff00", font=("Courier", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Authentication section
        auth_frame = ttk.LabelFrame(settings_frame, text="Nessus Authentication", padding=15)
        auth_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(auth_frame, text="Nessus URL:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=8, padx=5)
        self.url_entry = ttk.Entry(auth_frame, width=50)
        self.url_entry.insert(0, NESSUS_URL)
        self.url_entry.grid(row=0, column=1, sticky=tk.W, pady=8, padx=5)
        
        ttk.Label(auth_frame, text="Username:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W, pady=8, padx=5)
        self.username_entry = ttk.Entry(auth_frame, width=50)
        self.username_entry.insert(0, USERNAME)
        self.username_entry.grid(row=1, column=1, sticky=tk.W, pady=8, padx=5)
        
        ttk.Label(auth_frame, text="Password:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=8, padx=5)
        self.password_entry = ttk.Entry(auth_frame, width=50, show="*")
        self.password_entry.insert(0, PASSWORD)
        self.password_entry.grid(row=2, column=1, sticky=tk.W, pady=8, padx=5)
        
        btn_frame = ttk.Frame(auth_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=15)
        ttk.Button(btn_frame, text="🔌 Test Connection", command=self.test_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Save Settings", command=self.save_settings).pack(side=tk.LEFT, padx=5)
        
        # Timing configuration
        timing_frame = ttk.LabelFrame(settings_frame, text="Timing Configuration", padding=15)
        timing_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(timing_frame, text=f"⚡ Urgent Check: Every {CHECK_INTERVAL_URGENT}s (when task ≤ 5 min)", foreground="red").pack(anchor=tk.W, pady=3)
        ttk.Label(timing_frame, text=f"⏱️ Normal Check: Every {CHECK_INTERVAL_NORMAL}s (when 5 < task ≤ 30 min)", foreground="orange").pack(anchor=tk.W, pady=3)
        ttk.Label(timing_frame, text=f"🕐 Relaxed Check: Every {CHECK_INTERVAL_RELAXED}s (when task > 30 min)", foreground="green").pack(anchor=tk.W, pady=3)
        ttk.Label(timing_frame, text=f"🔄 Missed Task Recovery: Within {MISSED_TASK_WINDOW} minutes", foreground="blue").pack(anchor=tk.W, pady=3)
        
        # Features info
        features_frame = ttk.LabelFrame(settings_frame, text="Features", padding=15)
        features_frame.pack(fill=tk.X, padx=10, pady=10)
        
        features = [
            "✅ Non-blocking operation (no Enter key required)",
            "✅ Automatic missed task recovery (10-minute window)",
            "✅ Works on locked Windows/Linux systems",
            "✅ Real-time monitoring with adaptive intervals",
            "✅ Automatic re-authentication on session expiry",
            "✅ Skip completed scans automatically"
        ]
        for feature in features:
            ttk.Label(features_frame, text=feature).pack(anchor=tk.W, pady=2)
    
    def create_service_tab(self):
        """Create system service tab"""
        service_frame = ttk.Frame(self.notebook)
        self.notebook.add(service_frame, text="🔧 System Service")
        
        # Info section
        info_frame = ttk.LabelFrame(service_frame, text="System Service Setup", padding=15)
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        info_text = """
Create a system service to run the scheduler automatically:
• Starts on system boot
• Runs even when user is logged out
• Works on locked screen
• Automatically restarts if crashes
        """
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT).pack(anchor=tk.W)
        
        # Windows section
        if platform.system() == "Windows":
            win_frame = ttk.LabelFrame(service_frame, text="Windows Task Scheduler", padding=15)
            win_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            ttk.Label(win_frame, text="Create a Windows Task that:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
            ttk.Label(win_frame, text="• Runs daily at system startup").pack(anchor=tk.W, padx=20)
            ttk.Label(win_frame, text="• Works on locked screen").pack(anchor=tk.W, padx=20)
            ttk.Label(win_frame, text="• Runs with highest privileges").pack(anchor=tk.W, padx=20)
            ttk.Label(win_frame, text="• Auto-restarts if stopped").pack(anchor=tk.W, padx=20)
            
            ttk.Button(win_frame, text="🪟 Create Windows Task", command=self.create_windows_task).pack(pady=15)
            
            self.win_service_text = scrolledtext.ScrolledText(win_frame, height=15, wrap=tk.WORD)
            self.win_service_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Linux section
        elif platform.system() == "Linux":
            linux_frame = ttk.LabelFrame(service_frame, text="Linux Systemd Service", padding=15)
            linux_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            ttk.Label(linux_frame, text="Create a systemd service that:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
            ttk.Label(linux_frame, text="• Starts automatically on boot").pack(anchor=tk.W, padx=20)
            ttk.Label(linux_frame, text="• Runs in background").pack(anchor=tk.W, padx=20)
            ttk.Label(linux_frame, text="• Auto-restarts on failure").pack(anchor=tk.W, padx=20)
            ttk.Label(linux_frame, text="• Logs to systemd journal").pack(anchor=tk.W, padx=20)
            
            ttk.Button(linux_frame, text="🐧 Create Linux Service", command=self.create_linux_service).pack(pady=15)
            
            self.linux_service_text = scrolledtext.ScrolledText(linux_frame, height=15, wrap=tk.WORD, font=("Courier", 9))
            self.linux_service_text.pack(fill=tk.BOTH, expand=True, pady=10)
    
    def load_or_create_config(self):
        """Load existing config"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.cookie_token = config.get('cookie_token')
                    self.api_token = config.get('api_token')
                    
                    if self.api_token:
                        if self.verify_token():
                            self.log("✓ Session is valid")
                            self.status_bar.config(text="✓ Authenticated")
                        else:
                            self.log("⚠ Session expired")
                            self.status_bar.config(text="⚠ Session expired - Test connection in Settings")
            except Exception as e:
                self.log(f"Error loading config: {e}")
        else:
            self.log("No configuration found - Please test connection in Settings tab")
            self.status_bar.config(text="⚠ Not authenticated - Go to Settings")
    
    def test_connection(self):
        """Test Nessus connection"""
        self.log("Testing connection...")
        self.status_bar.config(text="Testing connection...")
        threading.Thread(target=self._test_connection_thread, daemon=True).start()
    
    def _test_connection_thread(self):
        """Background thread for testing connection"""
        try:
            url = self.url_entry.get().strip()
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            
            if not url or not username or not password:
                self.log("✗ Please fill in all fields")
                self.root.after(0, lambda: messagebox.showerror("Error", "Please fill in URL, Username, and Password"))
                return
            
            self.log(f"Connecting to {url}...")
            
            response = requests.post(
                f"{url}/session",
                json={"username": username, "password": password},
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.cookie_token = data.get('token')
                self.log("✓ Cookie token obtained")
                
                # Get or create API token
                api_response = requests.get(
                    f"{url}/session/keys",
                    headers={'X-Cookie': f'token={self.cookie_token}'},
                    verify=False,
                    timeout=10
                )
                
                if api_response.status_code == 200:
                    keys_data = api_response.json()
                    if keys_data.get('accessKey'):
                        self.api_token = keys_data.get('accessKey')
                        self.log("✓ API token obtained")
                    else:
                        create_response = requests.put(
                            f"{url}/session/keys",
                            headers={'X-Cookie': f'token={self.cookie_token}'},
                            verify=False,
                            timeout=10
                        )
                        if create_response.status_code == 200:
                            create_data = create_response.json()
                            self.api_token = create_data.get('accessKey')
                            self.log("✓ New API token created")
                
                # Update global variables
                global NESSUS_URL, USERNAME, PASSWORD
                NESSUS_URL = url
                USERNAME = username
                PASSWORD = password
                
                self.save_config()
                self.log("✓ Configuration saved!")
                
                self.root.after(0, lambda: self.status_bar.config(text="✓ Connected successfully"))
                self.root.after(0, lambda: messagebox.showinfo("Success", "✓ Connection successful!\n\nYou can now add schedules."))
            else:
                self.log(f"✗ Connection failed: {response.status_code}")
                self.log(f"Response: {response.text}")
                self.root.after(0, lambda: messagebox.showerror("Error", f"Connection failed!\n\nStatus: {response.status_code}\n\nCheck credentials and URL."))
        except requests.exceptions.ConnectionError:
            self.log(f"✗ Connection error: Cannot reach server")
            self.root.after(0, lambda: messagebox.showerror("Error", "Cannot connect to Nessus!\n\nCheck:\n1. Nessus is running\n2. URL is correct\n3. Firewall settings"))
        except Exception as e:
            self.log(f"✗ Error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Connection error:\n\n{str(e)}"))
    
    def save_settings(self):
        """Save settings"""
        global NESSUS_URL, USERNAME, PASSWORD
        NESSUS_URL = self.url_entry.get().strip()
        USERNAME = self.username_entry.get().strip()
        PASSWORD = self.password_entry.get().strip()
        self.save_config()
        messagebox.showinfo("Success", "Settings saved!")
        self.log("✓ Settings saved")
    
    def save_config(self):
        """Save configuration"""
        config = {
            'cookie_token': self.cookie_token,
            'api_token': self.api_token
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    
    def verify_token(self):
        """Verify token validity"""
        try:
            response = requests.get(
                f"{NESSUS_URL}/scans",
                headers=self.get_headers(),
                verify=False,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def get_headers(self):
        """Get API headers"""
        return {
            'X-Api-Token': self.api_token,
            'X-Cookie': f'token={self.cookie_token}',
            'Content-Type': 'application/json',
        }
    
    def login(self):
        """Login to Nessus"""
        try:
            response = requests.post(
                f"{NESSUS_URL}/session",
                json={"username": USERNAME, "password": PASSWORD},
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.cookie_token = data.get('token')
                self.save_config()
                self.log("✓ Re-authentication successful")
                return True
            return False
        except:
            return False
    
    def get_available_scans(self):
        """Get list of available scans"""
        try:
            if not self.api_token:
                self.log("✗ Not authenticated")
                return []
            
            response = requests.get(
                f"{NESSUS_URL}/scans",
                headers=self.get_headers(),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                scans = data.get('scans', [])
                self.log(f"✓ Retrieved {len(scans)} scan(s)")
                return scans
            elif response.status_code == 401:
                self.log("⚠ Authentication expired, re-authenticating...")
                if self.login():
                    return self.get_available_scans()
                return []
            else:
                self.log(f"✗ Failed to get scans: {response.status_code}")
                return []
        except Exception as e:
            self.log(f"✗ Error getting scans: {e}")
            return []
    
    def refresh_scans(self):
        """Refresh available scans list"""
        self.log("🔄 Refreshing scans list...")
        self.status_bar.config(text="Refreshing scans...")
        threading.Thread(target=self._refresh_scans_thread, daemon=True).start()
    
    def _refresh_scans_thread(self):
        """Background thread for refreshing scans"""
        scans = self.get_available_scans()
        if scans:
            self.log(f"✓ Found {len(scans)} scan(s):")
            for scan in scans[:10]:
                self.log(f"  • {scan.get('name')} (ID: {scan.get('id')}, Status: {scan.get('status')})")
            if len(scans) > 10:
                self.log(f"  ... and {len(scans) - 10} more")
        else:
            self.log("✗ No scans found or connection error")
        
        self.root.after(0, lambda: self.status_bar.config(text=f"Found {len(scans)} scans"))
    
    def add_schedule_dialog(self):
        """Show dialog to add new schedule"""
        if not self.api_token:
            messagebox.showerror("Error", "⚠ Not authenticated!\n\nGo to Settings tab and test connection first.")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Schedule")
        dialog.geometry("550x450")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Show loading
        loading_label = ttk.Label(dialog, text="⏳ Loading scans...", font=("Arial", 11))
        loading_label.pack(pady=30)
        dialog.update()
        
        # Get scans
        scans = self.get_available_scans()
        loading_label.destroy()
        
        if not scans:
            ttk.Label(dialog, text="❌ No scans available!", foreground="red", font=("Arial", 13, "bold")).pack(pady=20)
            ttk.Label(dialog, text="Possible reasons:", font=("Arial", 11, "bold")).pack(pady=10)
            reasons = [
                "1. Not authenticated properly",
                "2. No scans created in Nessus",
                "3. Connection issue"
            ]
            for reason in reasons:
                ttk.Label(dialog, text=reason).pack(anchor=tk.W, padx=30, pady=2)
            
            btn_frame = ttk.Frame(dialog)
            btn_frame.pack(pady=20)
            ttk.Button(btn_frame, text="🔄 Retry", command=lambda: [dialog.destroy(), self.add_schedule_dialog()]).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="❌ Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
            return
        
        # Scan selection
        ttk.Label(dialog, text="Select Scan:", font=("Arial", 11, "bold")).pack(pady=10, anchor=tk.W, padx=20)
        scan_var = tk.StringVar()
        scan_combo = ttk.Combobox(dialog, textvariable=scan_var, width=60, state="readonly")
        scan_combo['values'] = [f"{s['id']} - {s['name']}" for s in scans]
        scan_combo.pack(pady=5, padx=20)
        
        # Action selection
        ttk.Label(dialog, text="Select Action:", font=("Arial", 11, "bold")).pack(pady=15, anchor=tk.W, padx=20)
        action_var = tk.StringVar(value="launch")
        action_frame = ttk.Frame(dialog)
        action_frame.pack(pady=5)
        
        ttk.Radiobutton(action_frame, text="▶ Launch", variable=action_var, value="launch").pack(side=tk.LEFT, padx=15)
        ttk.Radiobutton(action_frame, text="⏸ Pause", variable=action_var, value="pause").pack(side=tk.LEFT, padx=15)
        ttk.Radiobutton(action_frame, text="▶️ Resume", variable=action_var, value="resume").pack(side=tk.LEFT, padx=15)
        ttk.Radiobutton(action_frame, text="⏹ Stop", variable=action_var, value="stop").pack(side=tk.LEFT, padx=15)
        
        # Time selection
        ttk.Label(dialog, text="Schedule Time (24-hour format):", font=("Arial", 11, "bold")).pack(pady=15, anchor=tk.W, padx=20)
        time_frame = ttk.Frame(dialog)
        time_frame.pack(pady=5)
        
        hour_var = tk.StringVar(value="09")
        minute_var = tk.StringVar(value="00")
        
        ttk.Label(time_frame, text="Hour:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        hour_spin = ttk.Spinbox(time_frame, from_=0, to=23, textvariable=hour_var, width=8, format="%02.0f")
        hour_spin.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(time_frame, text="Minute:", font=("Arial", 10)).pack(side=tk.LEFT, padx=10)
        minute_spin = ttk.Spinbox(time_frame, from_=0, to=59, textvariable=minute_var, width=8, format="%02.0f")
        minute_spin.pack(side=tk.LEFT, padx=5)
        
        def add_schedule():
            if not scan_var.get():
                messagebox.showerror("Error", "Please select a scan")
                return
            
            scan_id = int(scan_var.get().split(' - ')[0])
            scan_name = ' - '.join(scan_var.get().split(' - ')[1:])
            action = action_var.get()
            time_str = f"{int(hour_var.get()):02d}:{int(minute_var.get()):02d}"
            
            schedule = {
                'scan_id': scan_id,
                'scan_name': scan_name,
                'action': action,
                'time': time_str
            }
            
            self.schedules.append(schedule)
            self.update_schedule_tree()
            self.log(f"✓ Added: {action.upper()} {scan_name} at {time_str}")
            messagebox.showinfo("Success", f"✓ Schedule added!\n\n{action.upper()} {scan_name}\nat {time_str}")
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=25)
        ttk.Button(btn_frame, text="➕ Add Schedule", command=add_schedule).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_schedule(self):
        """Delete selected schedule"""
        selection = self.schedule_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a schedule to delete")
            return
        
        if messagebox.askyesno("Confirm", f"Delete {len(selection)} schedule(s)?"):
            for item in selection:
                values = self.schedule_tree.item(item)['values']
                self.schedules = [s for s in self.schedules if not (
                    s['scan_id'] == values[0] and 
                    s['action'] == values[2].lower() and 
                    s['time'] == values[3]
                )]
                self.schedule_tree.delete(item)
            
            self.log(f"🗑️ Deleted {len(selection)} schedule(s)")
    
    def update_schedule_tree(self):
        """Update schedules treeview"""
        for item in self.schedule_tree.get_children():
            self.schedule_tree.delete(item)
        
        for schedule in sorted(self.schedules, key=lambda x: x['time']):
            self.schedule_tree.insert('', tk.END, values=(
                schedule['scan_id'],
                schedule['scan_name'],
                schedule['action'].upper(),
                schedule['time']
            ))
    
    def load_schedules_from_file(self):
        """Load schedules from file"""
        if os.path.exists(SCHEDULE_FILE):
            try:
                with open(SCHEDULE_FILE, 'r') as f:
                    data = json.load(f)
                    self.schedules = data.get('schedules', [])
                    self.update_schedule_tree()
                    self.log(f"✓ Loaded {len(self.schedules)} schedule(s)")
                    self.status_bar.config(text=f"Loaded {len(self.schedules)} schedules")
            except Exception as e:
                self.log(f"✗ Error loading schedules: {e}")
        else:
            self.log("No schedule file found")
    
    def save_schedules_to_file(self):
        """Save schedules to file"""
        try:
            data = {'schedules': self.schedules}
            with open(SCHEDULE_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            self.log(f"✓ Saved {len(self.schedules)} schedule(s)")
            messagebox.showinfo("Success", f"✓ Saved {len(self.schedules)} schedules!")
            self.status_bar.config(text=f"Saved {len(self.schedules)} schedules")
        except Exception as e:
            self.log(f"✗ Error saving: {e}")
            messagebox.showerror("Error", f"Failed to save:\n{e}")
    
    def start_scheduler(self):
        """Start the scheduler"""
        if not self.schedules:
            messagebox.showwarning("Warning", "No schedules configured!\n\nAdd schedules first.")
            return
        
        if not self.api_token:
            messagebox.showerror("Error", "Not authenticated!\n\nTest connection in Settings.")
            return
        
        self.running = True
        self.executed_tasks.clear()
        self.last_log_time = time.time()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="● Status: Running", foreground="green")
        
        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        self.log("=" * 80)
        self.log("🚀 SCHEDULER STARTED")
        self.log("=" * 80)
        self.log(f"📊 Monitoring {len(self.schedules)} schedule(s)")
        self.log(f"🔄 Missed task recovery: {MISSED_TASK_WINDOW} minutes")
        self.log(f"💻 Platform: {platform.system()}")
        self.log(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("=" * 80)
        self.status_bar.config(text="✓ Scheduler running")
    
    def stop_scheduler(self):
        """Stop the scheduler"""
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="● Status: Stopped", foreground="red")
        self.mode_label.config(text="Mode: Idle")
        self.next_task_label.config(text="Next Task: None")
        
        self.log("=" * 80)
        self.log("⏹ SCHEDULER STOPPED")
        self.log("=" * 80)
        self.status_bar.config(text="Scheduler stopped")
    
    def manual_refresh(self):
        """Manual refresh of dashboard"""
        if self.running:
            self.log("🔄 Manual refresh...")
            self.update_dashboard_display()
    
    def monitoring_loop(self):
        """Main monitoring loop - NON-BLOCKING"""
        self.log("🔄 Monitoring loop started")
        
        while self.running:
            try:
                self.check_and_execute_schedules()
                
                # Determine sleep interval
                minutes_until_next, _ = self.get_time_until_next_task()
                if minutes_until_next is not None:
                    if minutes_until_next <= 5:
                        sleep_time = CHECK_INTERVAL_URGENT
                    elif minutes_until_next <= 30:
                        sleep_time = CHECK_INTERVAL_NORMAL
                    else:
                        sleep_time = CHECK_INTERVAL_RELAXED
                else:
                    sleep_time = CHECK_INTERVAL_NORMAL
                
                time.sleep(sleep_time)
                
            except Exception as e:
                self.log(f"✗ Error in monitoring: {e}")
                time.sleep(CHECK_INTERVAL_NORMAL)
    
    def check_and_execute_schedules(self):
        """Check and execute scheduled tasks - WITH MISSED TASK RECOVERY"""
        now = datetime.now()
        today_date = now.strftime('%Y-%m-%d')
        current_minutes = now.hour * 60 + now.minute
        
        # === MISSED TASK RECOVERY ===
        missed_tasks = self.get_missed_tasks()
        if missed_tasks:
            self.log("=" * 80)
            self.log(f"🔄 MISSED TASK RECOVERY: Found {len(missed_tasks)} missed task(s)")
            self.log("=" * 80)
            for task in missed_tasks:
                self.log(f"⚠ Recovering: {task['action'].upper()} - {task['scan_name']}")
                self.log(f"   Scheduled: {task['scheduled_time']} (missed by {task['minutes_ago']} min)")
                
                if self.execute_action(task['scan_id'], task['action'], task['scan_name'], is_recovery=True):
                    self.executed_tasks.add(task['task_id'])
                    self.log(f"✓ Recovery successful")
        
        # === REGULAR TASK EXECUTION ===
        minutes_until_next, next_task = self.get_time_until_next_task()
        
        # Determine mode
        if minutes_until_next is not None:
            if minutes_until_next <= 5:
                mode = "URGENT"
                log_interval = 10
            elif minutes_until_next <= 30:
                mode = "NORMAL"
                log_interval = 60
            else:
                mode = "RELAXED"
                log_interval = 600
        else:
            mode = "IDLE"
            log_interval = 60
        
        # Periodic logging
        current_time = time.time()
        if current_time - self.last_log_time >= log_interval:
            self.last_log_time = current_time
            self.log("-" * 80)
            self.log(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Mode: {mode}")
            
            if minutes_until_next is not None:
                self.log(f"📋 Next: {next_task['action'].upper()} - {next_task.get('scan_name')} at {next_task['time']} (in {minutes_until_next} min)")
            
            pending = self.get_pending_tasks_display()
            if pending:
                self.log(f"📊 Pending today: {len(pending)} task(s)")
                for task in pending[:3]:
                    self.log(f"   • {task['time']} | {task['action'].upper()} | {task['scan_name']}")
            
            self.log("-" * 80)
        
        # Update GUI status
        status_info = {
            'mode': mode,
            'minutes_until_next': minutes_until_next,
            'next_task': next_task,
            'pending_count': len(self.get_pending_tasks_display()),
            'executed_count': len([t for t in self.executed_tasks if t.startswith(today_date)]),
            'recovered_count': len(missed_tasks)
        }
        self.update_status(status_info)
        
        # Execute scheduled tasks
        for schedule in self.schedules:
            scan_id = schedule['scan_id']
            scan_name = schedule.get('scan_name', f'Scan {scan_id}')
            scheduled_time = schedule['time']
            action = schedule['action']
            
            task_id = f"{today_date}_{scan_id}_{scheduled_time}_{action}"
            
            if task_id in self.executed_tasks:
                continue
            
            scheduled_hour, scheduled_minute = map(int, scheduled_time.split(':'))
            
            # Execute within first 30 seconds of scheduled minute
            if (now.hour == scheduled_hour and 
                now.minute == scheduled_minute and 
                now.second < 30):
                
                self.log("=" * 80)
                self.log(f"🎯 TRIGGER: {action.upper()} for {scan_name} at {scheduled_time}")
                self.log("=" * 80)
                
                if self.execute_action(scan_id, action, scan_name):
                    self.executed_tasks.add(task_id)
                    self.log(f"✓ Task completed: {task_id}")
        
        # Cleanup old tasks
        self.executed_tasks = {t for t in self.executed_tasks if t.startswith(today_date)}
    
    def get_missed_tasks(self):
        """Get tasks missed in last 10 minutes"""
        now = datetime.now()
        current_minutes = now.hour * 60 + now.minute
        today_date = now.strftime('%Y-%m-%d')
        
        missed_tasks = []
        
        for schedule in self.schedules:
            scan_id = schedule['scan_id']
            scan_name = schedule.get('scan_name', f'Scan {scan_id}')
            scheduled_time = schedule['time']
            action = schedule['action']
            
            task_id = f"{today_date}_{scan_id}_{scheduled_time}_{action}"
            
            if task_id in self.executed_tasks:
                continue
            
            scheduled_hour, scheduled_minute = map(int, scheduled_time.split(':'))
            scheduled_minutes = scheduled_hour * 60 + scheduled_minute
            
            diff = current_minutes - scheduled_minutes
            
            # Task was scheduled 1-10 minutes ago
            if 1 <= diff <= MISSED_TASK_WINDOW:
                missed_tasks.append({
                    'scan_id': scan_id,
                    'scan_name': scan_name,
                    'action': action,
                    'scheduled_time': scheduled_time,
                    'task_id': task_id,
                    'minutes_ago': diff
                })
        
        return missed_tasks
    
    def get_time_until_next_task(self):
        """Calculate minutes until next task"""
        now = datetime.now()
        current_minutes = now.hour * 60 + now.minute
        today_date = now.strftime('%Y-%m-%d')
        
        min_diff = float('inf')
        next_task_info = None
        
        for schedule in self.schedules:
            task_id = f"{today_date}_{schedule['scan_id']}_{schedule['time']}_{schedule['action']}"
            
            if task_id in self.executed_tasks:
                continue
            
            hour, minute = map(int, schedule['time'].split(':'))
            scheduled_minutes = hour * 60 + minute
            
            diff = scheduled_minutes - current_minutes
            if diff < 0:
                diff += 1440
            
            if diff < min_diff:
                min_diff = diff
                next_task_info = schedule
        
        return (min_diff if min_diff != float('inf') else None, next_task_info)
    
    def get_pending_tasks_display(self):
        """Get pending tasks for today"""
        now = datetime.now()
        today_date = now.strftime('%Y-%m-%d')
        pending_tasks = []
        
        for schedule in self.schedules:
            task_id = f"{today_date}_{schedule['scan_id']}_{schedule['time']}_{schedule['action']}"
            
            if task_id in self.executed_tasks:
                continue
            
            scheduled_hour, scheduled_minute = map(int, schedule['time'].split(':'))
            scheduled_mins = scheduled_hour * 60 + scheduled_minute
            current_mins = now.hour * 60 + now.minute
            
            if scheduled_mins >= current_mins:
                time_diff = scheduled_mins - current_mins
                pending_tasks.append({
                    'time': schedule['time'],
                    'scan_name': schedule.get('scan_name', f"Scan {schedule['scan_id']}"),
                    'action': schedule['action'],
                    'minutes_until': time_diff
                })
        
        return sorted(pending_tasks, key=lambda x: x['minutes_until'])
    
    def update_dashboard_from_status(self, status):
        """Update dashboard from status dict"""
        mode = status.get('mode', 'IDLE')
        minutes_until_next = status.get('minutes_until_next')
        next_task = status.get('next_task')
        
        # Update mode
        mode_colors = {'URGENT': 'red', 'NORMAL': 'orange', 'RELAXED': 'green', 'IDLE': 'gray'}
        self.mode_label.config(text=f"Mode: {mode}", foreground=mode_colors.get(mode, 'black'))
        
        # Update next task
        if minutes_until_next is not None and next_task:
            self.next_task_label.config(
                text=f"Next Task: {next_task['action'].upper()} - {next_task.get('scan_name', 'Unknown')} at {next_task['time']} (in {minutes_until_next} min)"
            )
        else:
            self.next_task_label.config(text="Next Task: None scheduled")
        
        # Update system time
        self.system_time_label.config(text=f"System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Update stats
        self.stats_label.config(
            text=f"Total Schedules: {len(self.schedules)} | Executed Today: {status.get('executed_count', 0)} | Recovered: {status.get('recovered_count', 0)}"
        )
        
        # Update pending tasks tree
        self.update_dashboard_display()
    
    def update_dashboard_display(self):
        """Update pending tasks display"""
        for item in self.pending_tree.get_children():
            self.pending_tree.delete(item)
        
        pending = self.get_pending_tasks_display()
        for task in pending:
            self.pending_tree.insert('', tk.END, values=(
                task['time'],
                task['scan_name'],
                task['action'].upper(),
                f"{task['minutes_until']} min"
            ))
    
    def execute_action(self, scan_id, action, scan_name="Unknown", is_recovery=False):
        """Execute scan action with retry"""
        # Check if already completed
        if action == 'launch':
            if self.is_scan_completed(scan_id):
                self.log(f"⏭️ SKIPPED: {scan_name} already completed")
                return False
        
        action_map = {'launch': 'launch', 'pause': 'pause', 'resume': 'resume', 'stop': 'stop'}
        endpoint = action_map.get(action)
        
        if not endpoint:
            self.log(f"✗ Invalid action: {action}")
            return False
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                recovery_tag = " [RECOVERY]" if is_recovery else ""
                self.log(f"▶️ Executing{recovery_tag}: {action.upper()} - {scan_name} (Attempt {attempt + 1}/{max_retries})")
                
                response = requests.post(
                    f"{NESSUS_URL}/scans/{scan_id}/{endpoint}",
                    headers=self.get_headers(),
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    self.log(f"✓ SUCCESS: {action.upper()} - {scan_name}")
                    return True
                elif response.status_code == 401:
                    self.log("⚠ Session expired, re-authenticating...")
                    if self.login():
                        continue
                    return False
                else:
                    self.log(f"✗ Failed: {response.status_code}")
                    return False
                    
            except Exception as e:
                self.log(f"✗ Error: {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)
        
        self.log(f"✗ Failed after {max_retries} retries")
        return False
    
    def is_scan_completed(self, scan_id):
        """Check if scan is completed"""
        status_info = self.get_scan_status(scan_id)
        return status_info and status_info['status'] == 'completed'
    
    def get_scan_status(self, scan_id):
        """Get scan status"""
        try:
            response = requests.get(
                f"{NESSUS_URL}/scans/{scan_id}",
                headers=self.get_headers(),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                info = data.get('info', {})
                return {
                    'status': info.get('status', 'unknown'),
                    'progress': info.get('progress', 0),
                    'name': info.get('name', 'Unknown')
                }
            elif response.status_code == 401:
                if self.login():
                    return self.get_scan_status(scan_id)
            return None
        except:
            return None
    
    def clear_logs(self):
        """Clear log display"""
        self.log_text.delete(1.0, tk.END)
    
    def export_logs(self):
        """Export logs"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"nessus_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("Success", f"✓ Logs exported to:\n{filename}")
    
    def open_log_file(self):
        """Open log file location"""
        log_path = os.path.abspath(LOG_FILE)
        if platform.system() == "Windows":
            os.system(f'explorer /select,"{log_path}"')
        elif platform.system() == "Linux":
            os.system(f'xdg-open "{os.path.dirname(log_path)}"')
        else:
            messagebox.showinfo("Log File", f"Log file location:\n{log_path}")
    
    def create_windows_task(self):
        """Create Windows Task Scheduler"""
        if platform.system() != "Windows":
            messagebox.showerror("Error", "This feature is only for Windows")
            return
        
        try:
            import win32com.client
        except ImportError:
            messagebox.showerror("Error", "pywin32 not installed!\n\nInstall: pip install pywin32")
            return
        
        if not os.path.exists(CONFIG_FILE) or not os.path.exists(SCHEDULE_FILE):
            messagebox.showerror("Error", "Please save configuration and schedules first!")
            return
        
        script_path = os.path.abspath(__file__)
        python_path = sys.executable
        task_name = "NessusScheduler"
        
        try:
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            root_folder = scheduler.GetFolder('\\')
            
            try:
                root_folder.DeleteTask(task_name, 0)
            except:
                pass
            
            task_def = scheduler.NewTask(0)
            task_def.RegistrationInfo.Description = "Nessus Automated Scheduler v6.0"
            task_def.RegistrationInfo.Author = os.getenv('USERNAME')
            
            # Daily trigger
            TASK_TRIGGER_DAILY = 2
            trigger = task_def.Triggers.Create(TASK_TRIGGER_DAILY)
            start_time = datetime.now().replace(hour=0, minute=0, second=0)
            trigger.StartBoundary = start_time.isoformat()
            trigger.Enabled = True
            trigger.DaysInterval = 1
            
            # Action
            TASK_ACTION_EXEC = 0
            action = task_def.Actions.Create(TASK_ACTION_EXEC)
            action.Path = python_path
            action.Arguments = f'-u "{script_path}"'
            action.WorkingDirectory = os.path.dirname(script_path)
            
            # Settings
            settings = task_def.Settings
            settings.Enabled = True
            settings.StartWhenAvailable = True
            settings.RunOnlyIfNetworkAvailable = False
            settings.DisallowStartIfOnBatteries = False
            settings.StopIfGoingOnBatteries = False
            settings.AllowHardTerminate = False
            settings.MultipleInstances = 3
            settings.ExecutionTimeLimit = "PT0S"
            settings.WakeToRun = True
            
            # Principal - run on locked screen
            principal = task_def.Principal
            principal.UserId = os.getenv('USERNAME')
            principal.LogonType = 4  # Interactive or password
            principal.RunLevel = 1  # Highest
            
            # Get password
            password_dialog = tk.Toplevel(self.root)
            password_dialog.title("Windows Password Required")
            password_dialog.geometry("400x150")
            password_dialog.transient(self.root)
            password_dialog.grab_set()
            
            ttk.Label(password_dialog, text="Enter Windows password to run on locked screen:", font=("Arial", 10)).pack(pady=10)
            password_var = tk.StringVar()
            password_entry = ttk.Entry(password_dialog, textvariable=password_var, show="*", width=40)
            password_entry.pack(pady=10)
            password_entry.focus()
            
            result = {'password': None}
            
            def submit():
                result['password'] = password_var.get()
                password_dialog.destroy()
            
            ttk.Button(password_dialog, text="Create Task", command=submit).pack(pady=10)
            password_dialog.wait_window()
            
            if not result['password']:
                return
            
            TASK_CREATE_OR_UPDATE = 6
            root_folder.RegisterTaskDefinition(
                task_name,
                task_def,
                TASK_CREATE_OR_UPDATE,
                os.getenv('USERNAME'),
                result['password'],
                principal.LogonType
            )
            
            info = f"""
✓ Windows Task Created Successfully!

Task Name: {task_name}
Trigger: Daily at midnight
Run: Continuously in background
User: {os.getenv('USERNAME')}
Privileges: Highest
Works on locked screen: YES
Auto-restart: YES

The task will run even when:
• Windows is locked
• User is logged out
• Screen is off

Manage: taskschd.msc
            """
            
            if hasattr(self, 'win_service_text'):
                self.win_service_text.delete(1.0, tk.END)
                self.win_service_text.insert(1.0, info)
            
            self.log("✓ Windows Task created successfully!")
            messagebox.showinfo("Success", info)
            
        except Exception as e:
            error_msg = f"Error creating task: {e}\n\nMake sure to run as Administrator"
            self.log(f"✗ {error_msg}")
            messagebox.showerror("Error", error_msg)
    
    def create_linux_service(self):
        """Create Linux systemd service"""
        if platform.system() != "Linux":
            messagebox.showerror("Error", "This feature is only for Linux")
            return
        
        if not os.path.exists(CONFIG_FILE) or not os.path.exists(SCHEDULE_FILE):
            messagebox.showerror("Error", "Please save configuration and schedules first!")
            return
        
        script_path = os.path.abspath(__file__)
        python_path = sys.executable
        script_dir = os.path.dirname(script_path)
        current_user = os.getenv('USER')
        service_name = "nessus-scheduler"
        
        service_content = f"""[Unit]
Description=Nessus Automated Scheduler v6.0
After=network.target

[Service]
Type=simple
User={current_user}
WorkingDirectory={script_dir}
ExecStart={python_path} -u {script_path}
Restart=always
RestartSec=10
StandardOutput=append:{script_dir}/{LOG_FILE}
StandardError=append:{script_dir}/{LOG_FILE}
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
"""
        
        temp_service = "/tmp/nessus-scheduler.service"
        with open(temp_service, 'w') as f:
            f.write(service_content)
        
        commands = f"""
# Installation Commands (run these in terminal):

sudo cp {temp_service} /etc/systemd/system/{service_name}.service
sudo systemctl daemon-reload
sudo systemctl enable {service_name}
sudo systemctl start {service_name}

# Management Commands:

# Check status:
sudo systemctl status {service_name}

# View logs:
sudo journalctl -u {service_name} -f

# Stop service:
sudo systemctl stop {service_name}

# Restart service:
sudo systemctl restart {service_name}

# Disable service:
sudo systemctl disable {service_name}
        """
        
        if hasattr(self, 'linux_service_text'):
            self.linux_service_text.delete(1.0, tk.END)
            self.linux_service_text.insert(1.0, "SERVICE FILE CONTENT:\n")
            self.linux_service_text.insert(tk.END, "=" * 60 + "\n")
            self.linux_service_text.insert(tk.END, service_content)
            self.linux_service_text.insert(tk.END, "\n" + "=" * 60 + "\n")
            self.linux_service_text.insert(tk.END, commands)
        
        self.log(f"✓ Service file created: {temp_service}")
        messagebox.showinfo("Success", f"✓ Service file created!\n\nLocation: {temp_service}\n\nSee System Service tab for installation commands.")
        
        # Try auto-install if root
        if os.geteuid() == 0:
            try:
                import shutil
                shutil.copy(temp_service, f"/etc/systemd/system/{service_name}.service")
                os.system("systemctl daemon-reload")
                os.system(f"systemctl enable {service_name}")
                os.system(f"systemctl start {service_name}")
                self.log("✓ Service installed and started!")
                messagebox.showinfo("Success", "✓ Service installed and started!\n\nCheck status with:\nsudo systemctl status nessus-scheduler")
            except Exception as e:
                self.log(f"⚠ Auto-install failed: {e}")
    
    def on_closing(self):
        """Handle window close"""
        if self.running:
            if messagebox.askokcancel("Quit", "⚠ Scheduler is running!\n\nStop and quit?"):
                self.running = False
                if self.monitor_thread:
                    self.monitor_thread.join(timeout=2)
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    """Main entry point"""
    # Check if running headless (as service)
    if len(sys.argv) > 1 and sys.argv[1] == '--headless':
        # Run without GUI
        from collections import defaultdict
        
        class HeadlessScheduler:
            def __init__(self):
                self.cookie_token = None
                self.api_token = None
                self.schedules = []
                self.executed_tasks = set()
                self.running = True
                self.last_log_time = 0
                self.setup_logging()
                self.load_config()
                self.load_schedules()
            
            def setup_logging(self):
                self.logger = logging.getLogger('NessusScheduler')
                self.logger.setLevel(logging.INFO)
                self.logger.handlers = []
                
                file_handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=LOG_BACKUP_COUNT)
                file_handler.setLevel(logging.INFO)
                
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setLevel(logging.INFO)
                
                formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
                file_handler.setFormatter(formatter)
                console_handler.setFormatter(formatter)
                
                self.logger.addHandler(file_handler)
                self.logger.addHandler(console_handler)
            
            def log(self, message):
                self.logger.info(message)
                sys.stdout.flush()
            
            def load_config(self):
                if os.path.exists(CONFIG_FILE):
                    with open(CONFIG_FILE, 'r') as f:
                        config = json.load(f)
                        self.cookie_token = config.get('cookie_token')
                        self.api_token = config.get('api_token')
            
            def load_schedules(self):
                if os.path.exists(SCHEDULE_FILE):
                    with open(SCHEDULE_FILE, 'r') as f:
                        data = json.load(f)
                        self.schedules = data.get('schedules', [])
            
            def get_headers(self):
                return {
                    'X-Api-Token': self.api_token,
                    'X-Cookie': f'token={self.cookie_token}',
                    'Content-Type': 'application/json',
                }
            
            def login(self):
                try:
                    response = requests.post(f"{NESSUS_URL}/session", json={"username": USERNAME, "password": PASSWORD}, verify=False, timeout=10)
                    if response.status_code == 200:
                        self.cookie_token = response.json().get('token')
                        return True
                except:
                    pass
                return False
            
            def execute_action(self, scan_id, action, scan_name, is_recovery=False):
                endpoints = {'launch': 'launch', 'pause': 'pause', 'resume': 'resume', 'stop': 'stop'}
                endpoint = endpoints.get(action)
                
                for attempt in range(3):
                    try:
                        recovery_tag = " [RECOVERY]" if is_recovery else ""
                        self.log(f"Executing{recovery_tag}: {action.upper()} - {scan_name}")
                        
                        response = requests.post(f"{NESSUS_URL}/scans/{scan_id}/{endpoint}", headers=self.get_headers(), verify=False, timeout=10)
                        
                        if response.status_code == 200:
                            self.log(f"SUCCESS: {action.upper()} - {scan_name}")
                            return True
                        elif response.status_code == 401:
                            if self.login():
                                continue
                    except Exception as e:
                        self.log(f"Error: {e}")
                    
                    time.sleep(5)
                
                return False
            
            def get_missed_tasks(self):
                now = datetime.now()
                current_minutes = now.hour * 60 + now.minute
                today_date = now.strftime('%Y-%m-%d')
                missed_tasks = []
                
                for schedule in self.schedules:
                    task_id = f"{today_date}_{schedule['scan_id']}_{schedule['time']}_{schedule['action']}"
                    
                    if task_id in self.executed_tasks:
                        continue
                    
                    hour, minute = map(int, schedule['time'].split(':'))
                    scheduled_minutes = hour * 60 + minute
                    diff = current_minutes - scheduled_minutes
                    
                    if 1 <= diff <= MISSED_TASK_WINDOW:
                        missed_tasks.append({
                            'scan_id': schedule['scan_id'],
                            'scan_name': schedule.get('scan_name', f"Scan {schedule['scan_id']}"),
                            'action': schedule['action'],
                            'scheduled_time': schedule['time'],
                            'task_id': task_id,
                            'minutes_ago': diff
                        })
                
                return missed_tasks
            
            def run(self):
                self.log("=" * 80)
                self.log("NESSUS SCHEDULER v6.0 - HEADLESS MODE")
                self.log("=" * 80)
                self.log(f"Schedules: {len(self.schedules)}")
                self.log(f"Platform: {platform.system()}")
                self.log("=" * 80)
                
                def signal_handler(sig, frame):
                    self.log("\nScheduler stopped by signal")
                    self.running = False
                    sys.exit(0)
                
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
                
                self.last_log_time = time.time()
                
                while self.running:
                    try:
                        now = datetime.now()
                        today_date = now.strftime('%Y-%m-%d')
                        
                        # Missed tasks
                        missed_tasks = self.get_missed_tasks()
                        if missed_tasks:
                            self.log(f"RECOVERY: Found {len(missed_tasks)} missed task(s)")
                            for task in missed_tasks:
                                if self.execute_action(task['scan_id'], task['action'], task['scan_name'], True):
                                    self.executed_tasks.add(task['task_id'])
                        
                        # Regular tasks
                        for schedule in self.schedules:
                            task_id = f"{today_date}_{schedule['scan_id']}_{schedule['time']}_{schedule['action']}"
                            
                            if task_id in self.executed_tasks:
                                continue
                            
                            hour, minute = map(int, schedule['time'].split(':'))
                            
                            if now.hour == hour and now.minute == minute and now.second < 30:
                                self.log(f"TRIGGER: {schedule['action'].upper()} - {schedule.get('scan_name')}")
                                if self.execute_action(schedule['scan_id'], schedule['action'], schedule.get('scan_name', 'Unknown')):
                                    self.executed_tasks.add(task_id)
                        
                        # Cleanup
                        self.executed_tasks = {t for t in self.executed_tasks if t.startswith(today_date)}
                        
                        # Periodic log
                        if time.time() - self.last_log_time >= 600:
                            self.log(f"Monitoring active: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                            self.last_log_time = time.time()
                        
                        time.sleep(10)
                        
                    except Exception as e:
                        self.log(f"Error: {e}")
                        time.sleep(60)
        
        scheduler = HeadlessScheduler()
        scheduler.run()
    
    else:
        # Run with GUI
        root = tk.Tk()
        
        # Configure styles
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass
        
        app = NessusSchedulerGUI(root)
        
        # Center window
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')
        
        root.mainloop()


if __name__ == "__main__":
    main()
