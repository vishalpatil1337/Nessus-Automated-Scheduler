#!/usr/bin/env python3
"""
Nessus Automated Scheduler - Fixed Version v4.0
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

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
NESSUS_URL = "https://127.0.0.1:8834"
USERNAME = "Nessus_Username"    # Enter Nessus Username Here
PASSWORD = "Nessus_Password"    # Enter Nessus Password Here
CONFIG_FILE = "nessus_config.json"
SCHEDULE_FILE = "nessus_schedule.json"

# Timing Configuration
CHECK_INTERVAL_URGENT = 10      # 10 seconds when task within 5 minutes
CHECK_INTERVAL_NORMAL = 60      # 1 minute when task between 5-30 minutes
CHECK_INTERVAL_RELAXED = 1200   # 20 minutes when task more than 30 minutes

# Log rotation settings
LOG_FILE = "nessus_scheduler.log"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 5

class NessusScheduler:
    def __init__(self):
        self.cookie_token = None
        self.api_token = None
        self.schedules = []
        self.executed_tasks = set()
        self.scan_completion_status = {}
        self.running = True
        self.last_log_time = 0
        self.monitor_thread = None
        self.setup_logging()
        self.load_or_create_config()
    
    def setup_logging(self):
        """Setup rotating log file handler"""
        self.logger = logging.getLogger('NessusScheduler')
        self.logger.setLevel(logging.INFO)
        self.logger.handlers = []
        
        # File handler
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_LOG_SIZE,
            backupCount=LOG_BACKUP_COUNT
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log(self, message):
        """Log message to both file and console"""
        self.logger.info(message)
        sys.stdout.flush()
    
    def print_separator(self, char='='):
        """Print separator line"""
        line = char * 80
        self.log(line)
    
    def load_or_create_config(self):
        """Load existing config or create new one"""
        if os.path.exists(CONFIG_FILE):
            print("Found existing configuration")
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.cookie_token = config.get('cookie_token')
                self.api_token = config.get('api_token')
                
                if not self.api_token:
                    print("API token not found, detecting...")
                    self.login_and_detect_api_key()
                elif not self.verify_token():
                    print("Session expired, logging in...")
                    self.login()
                else:
                    print("Session is valid")
        else:
            print("No configuration found, setting up...")
            self.login_and_detect_api_key()
    
    def login_and_detect_api_key(self):
        """Login and auto-detect API key"""
        self.print_separator()
        self.log("AUTHENTICATION")
        self.print_separator()
        print(f"Logging in as: {USERNAME}")
        
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
                print(f"Cookie Token: {self.cookie_token[:30]}...")
                
                api_response = requests.get(
                    f"{NESSUS_URL}/session/keys",
                    headers={'X-Cookie': f'token={self.cookie_token}'},
                    verify=False,
                    timeout=10
                )
                
                if api_response.status_code == 200:
                    keys_data = api_response.json()
                    if keys_data.get('accessKey'):
                        self.api_token = keys_data.get('accessKey')
                        print(f"API Token: {self.api_token[:30]}...")
                    else:
                        create_response = requests.put(
                            f"{NESSUS_URL}/session/keys",
                            headers={'X-Cookie': f'token={self.cookie_token}'},
                            verify=False,
                            timeout=10
                        )
                        if create_response.status_code == 200:
                            create_data = create_response.json()
                            self.api_token = create_data.get('accessKey')
                            print(f"New API Token: {self.api_token[:30]}...")
                        else:
                            print("Could not create API token automatically")
                            self.api_token = input("\nPlease enter your API token manually: ").strip()
                else:
                    print("Could not get API keys automatically")
                    self.api_token = input("\nPlease enter your API token manually: ").strip()
                
                self.save_config()
                print("Configuration saved successfully!")
                
            else:
                print(f"Login failed: {response.status_code}")
                print(f"Response: {response.text}")
                sys.exit(1)
        except Exception as e:
            print(f"Error during login: {e}")
            sys.exit(1)
    
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
                self.log("Re-authentication successful")
                return True
            return False
        except:
            return False
    
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
    
    def get_scan_status(self, scan_id):
        """Get current scan status with details"""
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
        except Exception as e:
            return None
    
    def is_scan_completed(self, scan_id):
        """Check if scan is completed"""
        status_info = self.get_scan_status(scan_id)
        if status_info:
            status = status_info['status']
            return status == 'completed'
        return False
    
    def execute_action(self, scan_id, action, scan_name="Unknown"):
        """Execute scan action with retry and completion check"""
        
        # Check if scan is already completed
        if action == 'launch':
            if self.is_scan_completed(scan_id):
                current_status = self.get_scan_status(scan_id)
                if current_status:
                    self.print_separator()
                    self.log("SKIPPED - Scan Already Completed")
                    self.log(f"Scan: {scan_name} (ID: {scan_id})")
                    self.log(f"Status: {current_status['status'].upper()}")
                    self.log("Reason: Scan status is 'completed', skipping scheduled launch")
                    self.print_separator()
                    return False
        
        max_retries = 3
        retry_count = 0
        
        action_map = {
            'launch': 'launch',
            'pause': 'pause',
            'resume': 'resume',
            'stop': 'stop'
        }
        
        endpoint = action_map.get(action)
        if not endpoint:
            self.log(f"Invalid action: {action}")
            return False
        
        while retry_count < max_retries:
            try:
                self.print_separator()
                self.log(f"EXECUTING: {action.upper()}")
                self.log(f"Scan: {scan_name} (ID: {scan_id})")
                self.log(f"Action: {action.upper()}")
                self.log(f"Attempt: {retry_count + 1}/{max_retries}")
                self.print_separator()
                
                response = requests.post(
                    f"{NESSUS_URL}/scans/{scan_id}/{endpoint}",
                    headers=self.get_headers(),
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    self.log(f"SUCCESS! Scan {scan_id} {action}ed successfully")
                    self.print_separator()
                    return True
                elif response.status_code == 401:
                    self.log("Session expired, re-authenticating...")
                    if self.login():
                        retry_count += 1
                        continue
                    return False
                else:
                    self.log(f"Failed: {response.status_code}")
                    self.log(f"Response: {response.text}")
                    self.print_separator()
                    return False
                    
            except Exception as e:
                self.log(f"Error: {e}")
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(5)
        
        self.log(f"Failed to {action} scan after {max_retries} retries")
        self.print_separator()
        return False
    
    def load_schedules(self):
        """Load schedules from file"""
        if os.path.exists(SCHEDULE_FILE):
            with open(SCHEDULE_FILE, 'r') as f:
                data = json.load(f)
                self.schedules = data.get('schedules', [])
                
                scan_groups = defaultdict(list)
                for sched in self.schedules:
                    scan_groups[sched['scan_id']].append(sched)
                
                print(f"Loaded schedules for {len(scan_groups)} scan(s)")
                
                for scan_id, schedules in scan_groups.items():
                    print(f"  Scan {scan_id}: {len(schedules)} scheduled action(s)")
        else:
            print("No schedule file found")
    
    def save_schedules(self):
        """Save schedules to file"""
        data = {'schedules': self.schedules}
        with open(SCHEDULE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Schedules saved to {SCHEDULE_FILE}")
    
    def get_time_until_next_task(self):
        """Calculate minutes until next scheduled task"""
        now = datetime.now()
        current_minutes = now.hour * 60 + now.minute
        
        min_diff = float('inf')
        next_task_info = None
        
        for schedule in self.schedules:
            scheduled_time = schedule['time']
            hour, minute = map(int, scheduled_time.split(':'))
            scheduled_minutes = hour * 60 + minute
            
            diff = scheduled_minutes - current_minutes
            if diff < 0:
                diff += 1440  # Next day
            
            if diff < min_diff:
                min_diff = diff
                next_task_info = schedule
        
        return (min_diff if min_diff != float('inf') else None, next_task_info)
    
    def get_pending_tasks_display(self):
        """Get display of all pending tasks for today"""
        now = datetime.now()
        current_time_str = now.strftime('%H:%M')
        today_date = now.strftime('%Y-%m-%d')
        
        pending_tasks = []
        
        for schedule in self.schedules:
            scan_id = schedule['scan_id']
            scan_name = schedule.get('scan_name', f'Scan {scan_id}')
            scheduled_time = schedule['time']
            action = schedule['action']
            
            task_id = f"{today_date}_{scan_id}_{scheduled_time}_{action}"
            
            # Skip if already executed
            if task_id in self.executed_tasks:
                continue
            
            # Check if task is in future
            scheduled_hour, scheduled_minute = map(int, scheduled_time.split(':'))
            current_hour = now.hour
            current_minute = now.minute
            
            scheduled_mins = scheduled_hour * 60 + scheduled_minute
            current_mins = current_hour * 60 + current_minute
            
            if scheduled_mins >= current_mins:
                time_diff = scheduled_mins - current_mins
                pending_tasks.append({
                    'time': scheduled_time,
                    'scan_name': scan_name,
                    'action': action,
                    'minutes_until': time_diff
                })
        
        return sorted(pending_tasks, key=lambda x: x['minutes_until'])
    
    def check_and_execute_schedules(self):
        """Monitor and execute schedules - RUNS CONTINUOUSLY"""
        now = datetime.now()
        current_time_str = now.strftime('%H:%M')
        current_second = now.second
        today_date = now.strftime('%Y-%m-%d')
        
        # Calculate time until next task
        minutes_until_next, next_task = self.get_time_until_next_task()
        
        # Determine mode based on time until next task
        if minutes_until_next is not None:
            if minutes_until_next <= 5:
                mode = "URGENT"
                check_interval = CHECK_INTERVAL_URGENT
                log_interval = 10  # Log every 10 seconds
            elif minutes_until_next <= 30:
                mode = "NORMAL"
                check_interval = CHECK_INTERVAL_NORMAL
                log_interval = 60  # Log every 60 seconds
            else:
                mode = "RELAXED"
                check_interval = CHECK_INTERVAL_RELAXED
                log_interval = 1200  # Log every 20 minutes
        else:
            mode = "IDLE"
            check_interval = CHECK_INTERVAL_NORMAL
            log_interval = 60
        
        # FORCE LOG AT SPECIFIED INTERVALS
        current_time = time.time()
        time_since_last_log = current_time - self.last_log_time
        
        should_log = False
        if time_since_last_log >= log_interval:
            should_log = True
            self.last_log_time = current_time
        
        # DISPLAY LOG
        if should_log:
            self.print_separator('-')
            timestamp = now.strftime('%Y-%m-%d %H:%M:%S')
            self.log(f"MONITORING ACTIVE | Windows System Time: {timestamp}")
            self.log(f"Mode: {mode}")
            
            if minutes_until_next is not None:
                if minutes_until_next == 0:
                    self.log("STATUS: EXECUTION WINDOW - Checking for tasks...")
                elif minutes_until_next <= 5:
                    self.log(f"Next Task: {minutes_until_next} min | {next_task['action'].upper()} - {next_task.get('scan_name', 'Unknown')} at {next_task['time']}")
                    self.log(f"Monitoring: Every {CHECK_INTERVAL_URGENT}s | Logging: Every 10s")
                elif minutes_until_next <= 30:
                    self.log(f"Next Task: {minutes_until_next} min | {next_task['action'].upper()} - {next_task.get('scan_name', 'Unknown')} at {next_task['time']}")
                    self.log(f"Monitoring: Every {CHECK_INTERVAL_NORMAL}s (1 min)")
                else:
                    self.log(f"Next Task: {minutes_until_next} min | {next_task['action'].upper()} - {next_task.get('scan_name', 'Unknown')} at {next_task['time']}")
                    self.log(f"Monitoring: Every {CHECK_INTERVAL_RELAXED}s (20 min)")
            
            # Display pending tasks
            pending = self.get_pending_tasks_display()
            if pending:
                self.log(f"\nPending Tasks Today ({len(pending)}):")
                for task in pending[:5]:  # Show max 5
                    self.log(f"  {task['time']} | {task['action'].upper()} | {task['scan_name']} | in {task['minutes_until']} min")
            
            self.print_separator('-')
        
        # Check for task execution
        for schedule in self.schedules:
            scan_id = schedule['scan_id']
            scan_name = schedule.get('scan_name', f'Scan {scan_id}')
            scheduled_time = schedule['time']
            action = schedule['action']
            
            task_id = f"{today_date}_{scan_id}_{scheduled_time}_{action}"
            
            scheduled_hour, scheduled_minute = map(int, scheduled_time.split(':'))
            
            # Execute if in the right minute and first 30 seconds
            if (now.hour == scheduled_hour and 
                now.minute == scheduled_minute and 
                current_second < 30 and
                task_id not in self.executed_tasks):
                
                self.log(f"TRIGGER DETECTED: {action.upper()} for {scan_name} at {scheduled_time}")
                
                if self.execute_action(scan_id, action, scan_name):
                    self.executed_tasks.add(task_id)
                    self.log(f"Task marked as completed: {task_id}")
                    
                    if action in ['stop', 'pause']:
                        self.scan_completion_status[scan_id] = True
        
        # Clean up old executed tasks
        self.executed_tasks = {t for t in self.executed_tasks if t.startswith(today_date)}
        
        return check_interval
    
    def monitoring_loop(self):
        """Background monitoring loop - RUNS CONTINUOUSLY"""
        self.log("Background monitoring thread started")
        
        while self.running:
            try:
                next_interval = self.check_and_execute_schedules()
                time.sleep(next_interval)
            except Exception as e:
                self.log(f"Error in monitoring loop: {e}")
                time.sleep(CHECK_INTERVAL_NORMAL)

def list_available_scans():
    """List all available scans"""
    print("\n" + "="*80)
    print("AVAILABLE SCANS")
    print("="*80)
    
    try:
        response = requests.post(
            f"{NESSUS_URL}/session",
            json={"username": USERNAME, "password": PASSWORD},
            verify=False,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            cookie_token = data.get('token')
            
            headers = {'X-Cookie': f'token={cookie_token}'}
            
            scans_response = requests.get(
                f"{NESSUS_URL}/scans",
                headers=headers,
                verify=False,
                timeout=10
            )
            
            if scans_response.status_code == 200:
                scans_data = scans_response.json()
                scans = scans_data.get('scans', [])
                
                if not scans:
                    print("No scans found")
                    return []
                
                print(f"\nFound {len(scans)} scan(s)\n")
                print(f"{'ID':<10} {'Name':<45} {'Status':<15}")
                print("-"*80)
                
                for scan in scans:
                    scan_id = scan.get('id')
                    name = scan.get('name', 'N/A')[:45]
                    status = scan.get('status', 'N/A')
                    print(f"{scan_id:<10} {name:<45} {status:<15}")
                
                print("="*80)
                return scans
    except Exception as e:
        print(f"Error: {e}")
        return []

def setup_schedules():
    """Interactive schedule setup"""
    scheduler = NessusScheduler()
    
    print("\n" + "="*80)
    print("SCHEDULE SETUP WIZARD")
    print("="*80)
    
    scans = list_available_scans()
    if not scans:
        return
    
    schedules = []
    
    while True:
        print("\n" + "-"*80)
        print("ADD SCHEDULE FOR A SCAN")
        print("-"*80)
        
        try:
            scan_id_input = input("\nEnter Scan ID (or 'done' to finish, 'cancel' to exit): ").strip()
            
            if scan_id_input.lower() == 'done':
                break
            elif scan_id_input.lower() == 'cancel':
                sys.exit(0)
            
            scan_id = int(scan_id_input)
            status_info = scheduler.get_scan_status(scan_id)
            
            if not status_info:
                print("Invalid Scan ID or cannot access scan")
                continue
            
            scan_name = status_info['name']
            print(f"Selected: {scan_name} (Status: {status_info['status']})")
            
            print("\nSelect Action:")
            print("1. Launch scan")
            print("2. Pause scan")
            print("3. Resume scan")
            print("4. Stop scan")
            
            action_choice = input("\nAction: ").strip()
            
            action_map = {'1': 'launch', '2': 'pause', '3': 'resume', '4': 'stop'}
            
            if action_choice not in action_map:
                print("Invalid choice")
                continue
            
            action = action_map[action_choice]
            
            print("\nEnter Time (24-hour format, e.g., 09:30, 18:00):")
            time_str = input("Time: ").strip()
            
            try:
                datetime.strptime(time_str, "%H:%M")
                
                schedules.append({
                    'scan_id': scan_id,
                    'scan_name': scan_name,
                    'action': action,
                    'time': time_str
                })
                
                print(f"Added: {action.capitalize()} '{scan_name}' at {time_str}")
                
            except ValueError:
                print("Invalid time format. Use HH:MM")
        
        except ValueError:
            print("Please enter a valid number")
    
    if not schedules:
        print("\nNo schedules created")
        sys.exit(0)
    
    scheduler.schedules = schedules
    scheduler.save_schedules()
    
    print("\n" + "="*80)
    print("SCHEDULE SUMMARY")
    print("="*80)
    
    scan_groups = defaultdict(list)
    for sched in schedules:
        scan_groups[sched['scan_id']].append(sched)
    
    for scan_id, sched_list in scan_groups.items():
        scan_name = sched_list[0]['scan_name']
        print(f"\nScan: {scan_name} (ID: {scan_id})")
        for sched in sorted(sched_list, key=lambda x: x['time']):
            print(f"  - {sched['time']} : {sched['action'].upper()}")
    
    print("="*80)

def run_scheduler():
    """Run the scheduler with continuous background monitoring"""
    scheduler = NessusScheduler()
    scheduler.load_schedules()
    
    if not scheduler.schedules:
        print("No schedules found. Run setup first.")
        sys.exit(1)
    
    def signal_handler(sig, frame):
        print("\n\n" + "="*80)
        print("SCHEDULER STOPPED BY USER")
        print("="*80)
        scheduler.running = False
        if scheduler.monitor_thread:
            scheduler.monitor_thread.join(timeout=2)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print("\n" + "="*80)
    print("NESSUS SCHEDULER - ACTIVE")
    print("="*80)
    
    scan_groups = defaultdict(list)
    for sched in scheduler.schedules:
        scan_groups[sched['scan_id']].append(sched)
    
    print(f"Scans Monitored: {len(scan_groups)}")
    print(f"Total Schedules: {len(scheduler.schedules)}")
    print(f"Urgent Mode: Check every 10s, Log every 10s (task <= 5 min)")
    print(f"Normal Mode: Check every 1 min, Log every 1 min (5 < task <= 30 min)")
    print(f"Relaxed Mode: Check every 20 min, Log every 20 min (task > 30 min)")
    print(f"Log File: {LOG_FILE}")
    print(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nMONITORING ACTIVE - Running in background")
    print("DO NOT CLOSE THIS WINDOW")
    print("Press Ctrl+C to stop")
    print("="*80 + "\n")
    sys.stdout.flush()
    
    # Initialize last log time
    scheduler.last_log_time = time.time()
    
    # Start background monitoring thread
    scheduler.monitor_thread = threading.Thread(target=scheduler.monitoring_loop, daemon=True)
    scheduler.monitor_thread.start()
    
    # Keep main thread alive
    try:
        while scheduler.running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

def create_windows_task_scheduler():
    """Create Windows Task Scheduler"""
    if platform.system() != "Windows":
        print("This feature is only available on Windows")
        return
    
    try:
        import win32com.client
    except ImportError:
        print("\npywin32 not installed!")
        print("Install: pip install pywin32")
        return
    
    if not os.path.exists(CONFIG_FILE):
        print("Configuration not found. Please run setup first.")
        return
    
    if not os.path.exists(SCHEDULE_FILE):
        print("Schedules not found. Please run schedule setup first.")
        return
    
    print("\n" + "="*80)
    print("WINDOWS TASK SCHEDULER SETUP")
    print("="*80)
    
    script_path = os.path.abspath(__file__)
    python_path = sys.executable
    script_dir = os.path.dirname(script_path)
    
    print(f"\nScript: {script_path}")
    print(f"Python: {python_path}")
    
    task_name = "NessusScheduler"
    
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        
        root_folder = scheduler.GetFolder('\\')
        
        try:
            root_folder.DeleteTask(task_name, 0)
            print(f"\nRemoved existing task: {task_name}")
        except:
            pass
        
        task_def = scheduler.NewTask(0)
        
        reg_info = task_def.RegistrationInfo
        reg_info.Description = "Nessus Scan Scheduler"
        reg_info.Author = os.getenv('USERNAME')
        
        TASK_TRIGGER_TIME = 1
        trigger = task_def.Triggers.Create(TASK_TRIGGER_TIME)
        
        start_time = datetime.now()
        trigger.StartBoundary = start_time.isoformat()
        trigger.Enabled = True
        trigger.Repetition.Interval = "PT1M"
        trigger.Repetition.Duration = ""
        
        TASK_ACTION_EXEC = 0
        action = task_def.Actions.Create(TASK_ACTION_EXEC)
        action.Path = python_path
        action.Arguments = f'"{script_path}" --run'
        action.WorkingDirectory = script_dir
        
        settings = task_def.Settings
        settings.Enabled = True
        settings.StartWhenAvailable = True
        settings.RunOnlyIfNetworkAvailable = True
        settings.DisallowStartIfOnBatteries = False
        settings.StopIfGoingOnBatteries = False
        settings.AllowHardTerminate = True
        settings.MultipleInstances = 3
        settings.ExecutionTimeLimit = "PT1H"
        
        principal = task_def.Principal
        principal.UserId = os.getenv('USERNAME')
        principal.LogonType = 3
        principal.RunLevel = 1
        
        TASK_CREATE_OR_UPDATE = 6
        TASK_LOGON_NONE = 0
        
        root_folder.RegisterTaskDefinition(
            task_name,
            task_def,
            TASK_CREATE_OR_UPDATE,
            '',
            '',
            TASK_LOGON_NONE
        )
        
        print("\n" + "="*80)
        print("SUCCESS!")
        print("="*80)
        print(f"\nTask '{task_name}' created successfully!")
        print("\nTask Details:")
        print("  - Name: NessusScheduler")
        print("  - Runs: Every 1 minute")
        print(f"  - User: {os.getenv('USERNAME')}")
        print("  - Privileges: Highest")
        print("\nTo manage: Open Task Scheduler (taskschd.msc)")
        print("="*80)
        
    except Exception as e:
        print(f"\nError creating task: {e}")
        print("Run this script as Administrator")

def main():
    """Main menu"""
    print("="*80)
    print("NESSUS AUTOMATED SCHEDULER v4.0 - FIXED VERSION")
    print("="*80)
    print(f"Platform: {platform.system()}")
    print(f"Python: {sys.version.split()[0]}")
    print("="*80)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--run':
            run_scheduler()
        elif sys.argv[1] == '--setup':
            setup_schedules()
        elif sys.argv[1] == '--create-task':
            create_windows_task_scheduler()
        else:
            print("Usage:")
            print("  python nessus_scheduler.py --setup         # Setup schedules")
            print("  python nessus_scheduler.py --run           # Run scheduler")
            print("  python nessus_scheduler.py --create-task   # Setup Task Scheduler")
    else:
        while True:
            print("\n" + "="*80)
            print("MAIN MENU")
            print("="*80)
            print("1. Setup/Edit schedules")
            print("2. Run scheduler manually")
            print("3. Create Windows Task Scheduler")
            print("4. View current schedules")
            print("5. Exit")
            print("="*80)
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                setup_schedules()
            elif choice == '2':
                run_scheduler()
            elif choice == '3':
                create_windows_task_scheduler()
            elif choice == '4':
                if os.path.exists(SCHEDULE_FILE):
                    with open(SCHEDULE_FILE, 'r') as f:
                        data = json.load(f)
                        schedules = data.get('schedules', [])
                        
                        if schedules:
                            scan_groups = defaultdict(list)
                            for sched in schedules:
                                scan_groups[sched['scan_id']].append(sched)
                            
                            print("\nCURRENT SCHEDULES:")
                            for scan_id, sched_list in scan_groups.items():
                                scan_name = sched_list[0]['scan_name']
                                print(f"\nScan: {scan_name} (ID: {scan_id})")
                                for sched in sorted(sched_list, key=lambda x: x['time']):
                                    print(f"  - {sched['time']} : {sched['action'].upper()}")
                        else:
                            print("\nNo schedules found")
                else:
                    print("\nNo schedules found")
            elif choice == '5':
                print("\nGoodbye!")
                break
            else:
                print("Invalid option")

if __name__ == "__main__":
    main()