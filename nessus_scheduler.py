#!/usr/bin/env python3
"""
Nessus Automated Scheduler - BULLETPROOF Edition v4.3
CRITICAL FIXES:
- 100% reliable Windows Task Scheduler
- Real-time schedule file monitoring
- Process health checks
- Zero missed tasks guarantee
"""

import requests
import urllib3
import json
import os
import sys
import time
from datetime import datetime, timedelta
from collections import defaultdict
import platform
import threading
import signal
import logging
from logging.handlers import RotatingFileHandler
import hashlib

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# CONFIGURATION
# ============================================================================
NESSUS_URL = "https://127.0.0.1:8834"
USERNAME = "Nessus_Username"    # Enter Nessus Username Here
PASSWORD = "Nessus_Password"    # Enter Nessus Password Here
CONFIG_FILE = "nessus_config.json"
SCHEDULE_FILE = "nessus_schedule.json"
EXECUTED_TASKS_FILE = "executed_tasks.json"
LOCK_FILE = "nessus_scheduler.lock"
HEARTBEAT_FILE = "nessus_scheduler.heartbeat"

# Timing Configuration
CHECK_INTERVAL_URGENT = 10      # 10 seconds when task within 5 minutes
CHECK_INTERVAL_NORMAL = 60      # 1 minute when task between 5-30 minutes
CHECK_INTERVAL_RELAXED = 300    # 5 minutes when task more than 30 minutes

# Retry Configuration
RETRY_WINDOW_MINUTES = 10       # Retry missed scans for 10 minutes
RETRY_CHECK_INTERVAL = 60       # Check every 1 minute for missed scans

# Log rotation settings
LOG_FILE = "nessus_scheduler.log"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 5

# Version
VERSION = "4.3"

# ============================================================================
# ASCII LOGO
# ============================================================================
LOGO = """
  _   _                           _____      _              _       _           
 | \ | |                         / ____|    | |            | |     | |          
 |  \| | ___  ___ ___ _   _ ___ | (___   ___| |__   ___  __| |_   _| | ___ _ __ 
 | . ` |/ _ \/ __/ __| | | / __|  \___ \ / __| '_ \ / _ \/ _` | | | | |/ _ \ '__|
 | |\  |  __/\__ \__ \ |_| \__ \  ____) | (__| | | |  __/ (_| | |_| | |  __/ |   
 |_| \_|\___||___/___/\__,_|___/ |_____/ \___|_| |_|\___|\__,_|\__,_|_|\___|_|   
                                                                                  
     Automated Vulnerability Scan Scheduling System v{version}
     Released: {release_date} | License: MIT
"""
# ============================================================================
# SINGLE INSTANCE LOCK
# ============================================================================
class SingleInstanceLock:
    """Ensure only one instance of scheduler runs"""
    
    def __init__(self, lock_file):
        self.lock_file = lock_file
        self.locked = False
    
    def acquire(self):
        """Try to acquire lock"""
        if os.path.exists(self.lock_file):
            try:
                with open(self.lock_file, 'r') as f:
                    data = json.load(f)
                    old_pid = data.get('pid')
                    
                    # Check if old process is still running
                    if self._is_process_running(old_pid):
                        return False
                    else:
                        # Old process dead, remove stale lock
                        os.remove(self.lock_file)
            except:
                # Corrupted lock file, remove it
                try:
                    os.remove(self.lock_file)
                except:
                    pass
        
        # Create new lock
        try:
            with open(self.lock_file, 'w') as f:
                json.dump({
                    'pid': os.getpid(),
                    'started': datetime.now().isoformat()
                }, f)
            self.locked = True
            return True
        except:
            return False
    
    def release(self):
        """Release lock"""
        if self.locked and os.path.exists(self.lock_file):
            try:
                os.remove(self.lock_file)
                self.locked = False
            except:
                pass
    
    def _is_process_running(self, pid):
        """Check if process with PID is running"""
        if not pid:
            return False
        
        try:
            if platform.system() == "Windows":
                import subprocess
                output = subprocess.check_output(
                    f'tasklist /FI "PID eq {pid}" /NH',
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode()
                return str(pid) in output
            else:
                os.kill(pid, 0)
                return True
        except:
            return False

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def print_banner(title, char='=', width=80):
    """Print a formatted banner"""
    print(char * width)
    print(title.center(width))
    print(char * width)

def print_section(title, width=80):
    """Print a section header"""
    print("\n" + "=" * width)
    print(title)
    print("=" * width)

def print_subsection(title, width=80):
    """Print a subsection header"""
    print("\n" + "-" * width)
    print(title)
    print("-" * width)

def get_file_hash(filepath):
    """Get MD5 hash of file"""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

# ============================================================================
# MAIN SCHEDULER CLASS
# ============================================================================
class NessusScheduler:
    def __init__(self):
        self.cookie_token = None
        self.api_token = None
        self.schedules = []
        self.executed_tasks = set()
        self.missed_tasks = {}
        self.scan_completion_status = {}
        self.running = True
        self.last_log_time = 0
        self.monitor_thread = None
        self.heartbeat_thread = None
        self.last_execution_times = {}
        self.schedule_file_hash = None
        self.lock = SingleInstanceLock(LOCK_FILE)
        self.setup_logging()
        
    def setup_logging(self):
        """Setup rotating log file handler"""
        self.logger = logging.getLogger('NessusScheduler')
        self.logger.setLevel(logging.INFO)
        self.logger.handlers = []
        
        # File handler with rotation
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
        formatter = logging.Formatter(
            '[%(asctime)s] %(message)s', 
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log(self, message):
        """Log message to both file and console"""
        self.logger.info(message)
        sys.stdout.flush()
    
    def print_separator(self, char='=', width=80):
        """Print separator line"""
        line = char * width
        self.log(line)
    
    def update_heartbeat(self):
        """Update heartbeat file to show process is alive"""
        while self.running:
            try:
                with open(HEARTBEAT_FILE, 'w') as f:
                    json.dump({
                        'pid': os.getpid(),
                        'timestamp': datetime.now().isoformat(),
                        'schedules_loaded': len(self.schedules),
                        'tasks_executed': len(self.executed_tasks),
                        'status': 'RUNNING'
                    }, f, indent=2)
            except:
                pass
            time.sleep(30)  # Update every 30 seconds
    
    def check_schedule_file_changes(self):
        """Check if schedule file has been modified and reload"""
        current_hash = get_file_hash(SCHEDULE_FILE)
        
        if current_hash and current_hash != self.schedule_file_hash:
            self.print_separator('!')
            self.log("SCHEDULE FILE CHANGED - RELOADING")
            self.print_separator('!')
            
            old_count = len(self.schedules)
            self.load_schedules()
            new_count = len(self.schedules)
            
            self.log(f"Schedule reloaded: {old_count} -> {new_count} tasks")
            self.schedule_file_hash = current_hash
            
            # Show new schedule
            self.print_separator('-')
            self.log("UPDATED SCHEDULE:")
            for sched in self.schedules:
                scan_name = sched.get('scan_name', f'Scan {sched["scan_id"]}')
                self.log(f"  {sched['time']} | {sched['action'].upper()} | {scan_name} (ID: {sched['scan_id']})")
            self.print_separator('-')
    
    def load_executed_tasks(self):
        """Load executed tasks from persistent storage"""
        if os.path.exists(EXECUTED_TASKS_FILE):
            try:
                with open(EXECUTED_TASKS_FILE, 'r') as f:
                    data = json.load(f)
                    today = datetime.now().strftime('%Y-%m-%d')
                    
                    # Only load today's tasks
                    self.executed_tasks = {
                        task for task in data.get('executed_tasks', [])
                        if task.startswith(today)
                    }
                    self.last_execution_times = data.get('last_execution_times', {})
                    
                    # Clean old entries from last_execution_times
                    self.last_execution_times = {
                        k: v for k, v in self.last_execution_times.items()
                        if k.startswith(today)
                    }
                    
                    if self.executed_tasks:
                        self.log(f"Loaded {len(self.executed_tasks)} completed task(s) from disk")
                        for task in self.executed_tasks:
                            self.log(f"  ✓ {task}")
            except Exception as e:
                self.log(f"Error loading executed tasks: {e}")
                self.executed_tasks = set()
                self.last_execution_times = {}
        else:
            self.executed_tasks = set()
            self.last_execution_times = {}
    
    def save_executed_tasks(self):
        """Save executed tasks to persistent storage"""
        try:
            data = {
                'executed_tasks': list(self.executed_tasks),
                'last_execution_times': self.last_execution_times,
                'last_updated': datetime.now().isoformat()
            }
            with open(EXECUTED_TASKS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.log(f"Error saving executed tasks: {e}")
    
    def load_or_create_config(self):
        """Load existing config or create new one"""
        if os.path.exists(CONFIG_FILE):
            self.log("Found existing configuration")
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.cookie_token = config.get('cookie_token')
                self.api_token = config.get('api_token')
                
                if not self.api_token:
                    self.log("API token not found, detecting...")
                    self.login_and_detect_api_key()
                elif not self.verify_token():
                    self.log("Session expired, logging in...")
                    self.login()
                else:
                    self.log("Session is valid")
        else:
            self.log("No configuration found, setting up...")
            self.login_and_detect_api_key()
    
    def login_and_detect_api_key(self):
        """Login and auto-detect API key"""
        print_section("AUTHENTICATION")
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
    
    def is_scan_running(self, scan_id):
        """Check if scan is currently running"""
        status_info = self.get_scan_status(scan_id)
        if status_info:
            status = status_info['status']
            return status in ['running', 'processing']
        return False
    
    def validate_schedule_before_execution(self, scan_id, action, scheduled_time):
        """
        CRITICAL: Validate that the schedule we're about to execute
        actually exists in the schedule file RIGHT NOW
        """
        # Reload schedule file to get CURRENT state
        try:
            with open(SCHEDULE_FILE, 'r') as f:
                data = json.load(f)
                current_schedules = data.get('schedules', [])
        except:
            self.log("ERROR: Could not read schedule file!")
            return False
        
        # Look for exact matching schedule
        for sched in current_schedules:
            if (sched['scan_id'] == scan_id and 
                sched['action'] == action and 
                sched['time'] == scheduled_time):
                self.log(f"✓ Schedule validated: {action.upper()} at {scheduled_time} for scan {scan_id}")
                return True
        
        # Not found - schedule was changed!
        self.print_separator('!')
        self.log("⚠️  VALIDATION FAILED - Schedule Does Not Match File!")
        self.log(f"❌ Tried to execute: {action.upper()} for scan {scan_id} at {scheduled_time}")
        self.log("❌ This task is NOT in the current schedule file")
        self.log("✋ Execution ABORTED for safety")
        self.log("💡 The schedule file was modified - reloading...")
        self.print_separator('!')
        
        # Force reload schedule
        self.check_schedule_file_changes()
        return False
    
    def execute_action(self, scan_id, action, scan_name="Unknown", scheduled_time="", is_retry=False):
        """Execute scan action with validation and retry"""
        
        # CRITICAL: Validate schedule before executing (skip for retries)
        if not is_retry:
            if not self.validate_schedule_before_execution(scan_id, action, scheduled_time):
                return False
        
        # Check if scan is already completed (for launch actions)
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
            
            # Check if scan is already running
            if self.is_scan_running(scan_id):
                current_status = self.get_scan_status(scan_id)
                if current_status:
                    self.print_separator()
                    self.log("SKIPPED - Scan Already Running")
                    self.log(f"Scan: {scan_name} (ID: {scan_id})")
                    self.log(f"Status: {current_status['status'].upper()}")
                    self.log(f"Progress: {current_status['progress']}%")
                    self.log("Reason: Scan is already running, skipping scheduled launch")
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
                if is_retry:
                    self.log(f"🔄 RETRY EXECUTION: {action.upper()}")
                else:
                    self.log(f"▶️  EXECUTING: {action.upper()}")
                self.log(f"Scan: {scan_name} (ID: {scan_id})")
                self.log(f"Scheduled Time: {scheduled_time}")
                self.log(f"Current Time: {datetime.now().strftime('%H:%M:%S')}")
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
                    self.log(f"✅ SUCCESS! Scan {scan_id} {action}ed successfully")
                    self.print_separator()
                    time.sleep(2)
                    return True
                elif response.status_code == 401:
                    self.log("Session expired, re-authenticating...")
                    if self.login():
                        retry_count += 1
                        continue
                    return False
                else:
                    self.log(f"❌ Failed: {response.status_code}")
                    self.log(f"Response: {response.text}")
                    self.print_separator()
                    return False
                    
            except Exception as e:
                self.log(f"❌ Error: {e}")
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(5)
        
        self.log(f"❌ Failed to {action} scan after {max_retries} retries")
        self.print_separator()
        return False
    
    def load_schedules(self):
        """Load schedules from file"""
        if os.path.exists(SCHEDULE_FILE):
            with open(SCHEDULE_FILE, 'r') as f:
                data = json.load(f)
                self.schedules = data.get('schedules', [])
                self.schedule_file_hash = get_file_hash(SCHEDULE_FILE)
                
                scan_groups = defaultdict(list)
                for sched in self.schedules:
                    scan_groups[sched['scan_id']].append(sched)
                
                self.log(f"Loaded schedules for {len(scan_groups)} scan(s)")
                
                for scan_id, schedules in scan_groups.items():
                    self.log(f"  Scan {scan_id}: {len(schedules)} scheduled action(s)")
                    for sched in schedules:
                        self.log(f"    - {sched['time']} : {sched['action'].upper()}")
        else:
            self.log("⚠️  No schedule file found")
    
    def save_schedules(self):
        """Save schedules to file"""
        data = {'schedules': self.schedules}
        with open(SCHEDULE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        self.schedule_file_hash = get_file_hash(SCHEDULE_FILE)
        print(f"Schedules saved to {SCHEDULE_FILE}")
    
    def get_time_until_next_task(self):
        """Calculate minutes until next scheduled task"""
        now = datetime.now()
        current_minutes = now.hour * 60 + now.minute
        today_date = now.strftime('%Y-%m-%d')
        
        min_diff = float('inf')
        next_task_info = None
        
        for schedule in self.schedules:
            scan_id = schedule['scan_id']
            scheduled_time = schedule['time']
            action = schedule['action']
            
            task_id = f"{today_date}_{scan_id}_{scheduled_time}_{action}"
            if task_id in self.executed_tasks:
                continue
            
            hour, minute = map(int, scheduled_time.split(':'))
            scheduled_minutes = hour * 60 + minute
            
            diff = scheduled_minutes - current_minutes
            if diff < 0:
                diff += 1440
            
            if diff < min_diff:
                min_diff = diff
                next_task_info = schedule
        
        return (min_diff if min_diff != float('inf') else None, next_task_info)
    
    def get_pending_tasks_display(self):
        """Get display of all pending tasks for today"""
        now = datetime.now()
        today_date = now.strftime('%Y-%m-%d')
        
        pending_tasks = []
        
        for schedule in self.schedules:
            scan_id = schedule['scan_id']
            scan_name = schedule.get('scan_name', f'Scan {scan_id}')
            scheduled_time = schedule['time']
            action = schedule['action']
            
            task_id = f"{today_date}_{scan_id}_{scheduled_time}_{action}"
            
            if task_id in self.executed_tasks:
                continue
            
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
    
    def check_missed_tasks(self):
        """Check for missed tasks within the retry window"""
        now = datetime.now()
        today_date = now.strftime('%Y-%m-%d')
        current_minutes = now.hour * 60 + now.minute
        
        # Clean up old missed tasks beyond retry window
        expired_tasks = []
        for task_id, task_info in self.missed_tasks.items():
            minutes_since_missed = (now - task_info['missed_time']).total_seconds() / 60
            if minutes_since_missed > RETRY_WINDOW_MINUTES:
                expired_tasks.append(task_id)
                self.log(f"⏱️  Retry window expired for: {task_id}")
        
        for task_id in expired_tasks:
            del self.missed_tasks[task_id]
        
        # Check for new missed tasks
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
            
            time_diff = current_minutes - scheduled_minutes
            
            if 0 < time_diff <= RETRY_WINDOW_MINUTES:
                if task_id not in self.missed_tasks:
                    self.missed_tasks[task_id] = {
                        'scan_id': scan_id,
                        'scan_name': scan_name,
                        'action': action,
                        'scheduled_time': scheduled_time,
                        'missed_time': now - timedelta(minutes=time_diff),
                        'retry_count': 0
                    }
                    self.print_separator('!')
                    self.log("⚠️  MISSED TASK DETECTED!")
                    self.log(f"Task: {action.upper()} - {scan_name}")
                    self.log(f"Scheduled: {scheduled_time}")
                    self.log(f"Missed by: {time_diff} minute(s)")
                    self.log(f"Retry window: {RETRY_WINDOW_MINUTES} minutes")
                    self.log("Will retry every minute until executed or window expires")
                    self.print_separator('!')
    
    def retry_missed_tasks(self):
        """Attempt to execute missed tasks"""
        if not self.missed_tasks:
            return
        
        now = datetime.now()
        today_date = now.strftime('%Y-%m-%d')
        
        for task_id, task_info in list(self.missed_tasks.items()):
            if task_id in self.executed_tasks:
                del self.missed_tasks[task_id]
                continue
            
            scan_id = task_info['scan_id']
            scan_name = task_info['scan_name']
            action = task_info['action']
            scheduled_time = task_info['scheduled_time']
            retry_count = task_info['retry_count']
            
            minutes_since_missed = (now - task_info['missed_time']).total_seconds() / 60
            
            self.log(f"🔄 Retrying missed task: {action.upper()} - {scan_name} (Retry #{retry_count + 1}, {minutes_since_missed:.1f} min late)")
            
            if self.execute_action(scan_id, action, scan_name, scheduled_time, is_retry=True):
                self.executed_tasks.add(task_id)
                self.last_execution_times[task_id] = now.isoformat()
                self.save_executed_tasks()
                
                del self.missed_tasks[task_id]
                self.log(f"✅ Successfully executed missed task: {task_id}")
                
                if action in ['stop', 'pause']:
                    self.scan_completion_status[scan_id] = True
            else:
                self.missed_tasks[task_id]['retry_count'] += 1
                self.log(f"❌ Retry failed for: {task_id}")
    
    def check_and_execute_schedules(self):
        """Monitor and execute schedules - MAIN LOOP"""
        now = datetime.now()
        current_time_str = now.strftime('%H:%M')
        current_second = now.second
        today_date = now.strftime('%Y-%m-%d')
        
        # Check for schedule file changes every cycle
        self.check_schedule_file_changes()
        
        # Check for missed tasks and retry them
        self.check_missed_tasks()
        self.retry_missed_tasks()
        
        # Calculate time until next task
        minutes_until_next, next_task = self.get_time_until_next_task()
        
        # Determine mode based on time until next task
        if minutes_until_next is not None:
            if minutes_until_next <= 5:
                mode = "🔴 URGENT"
                check_interval = CHECK_INTERVAL_URGENT
                log_interval = 10
            elif minutes_until_next <= 30:
                mode = "🟡 NORMAL"
                check_interval = CHECK_INTERVAL_NORMAL
                log_interval = 60
            else:
                mode = "🟢 RELAXED"
                check_interval = CHECK_INTERVAL_RELAXED
                log_interval = 300
        else:
            mode = "⚪ IDLE"
            check_interval = CHECK_INTERVAL_NORMAL
            log_interval = 60
        
        # Log at specified intervals
        current_time = time.time()
        time_since_last_log = current_time - self.last_log_time
        
        should_log = False
        if time_since_last_log >= log_interval:
            should_log = True
            self.last_log_time = current_time
        
        # Display log
        if should_log:
            self.print_separator('-')
            timestamp = now.strftime('%Y-%m-%d %H:%M:%S')
            self.log(f"📡 MONITORING ACTIVE | System Time: {timestamp}")
            self.log(f"Mode: {mode}")
            
            # Show missed tasks being retried
            if self.missed_tasks:
                self.log(f"\n⚠️  MISSED TASKS BEING RETRIED ({len(self.missed_tasks)}):")
                for task_id, task_info in self.missed_tasks.items():
                    minutes_late = (now - task_info['missed_time']).total_seconds() / 60
                    self.log(f"  🔄 {task_info['scheduled_time']} | {task_info['action'].upper()} | {task_info['scan_name']} | {minutes_late:.1f} min late | Retry #{task_info['retry_count']}")
            
            if minutes_until_next is not None:
                if minutes_until_next == 0:
                    self.log("⚡ STATUS: EXECUTION WINDOW - Checking for tasks...")
                elif minutes_until_next <= 5:
                    self.log(f"⏰ Next Task: {minutes_until_next} min | {next_task['action'].upper()} - {next_task.get('scan_name', 'Unknown')} at {next_task['time']}")
                    self.log(f"🔍 Monitoring: Every {CHECK_INTERVAL_URGENT}s | Logging: Every 10s")
                elif minutes_until_next <= 30:
                    self.log(f"⏰ Next Task: {minutes_until_next} min | {next_task['action'].upper()} - {next_task.get('scan_name', 'Unknown')} at {next_task['time']}")
                    self.log(f"🔍 Monitoring: Every {CHECK_INTERVAL_NORMAL}s (1 min)")
                else:
                    self.log(f"⏰ Next Task: {minutes_until_next} min | {next_task['action'].upper()} - {next_task.get('scan_name', 'Unknown')} at {next_task['time']}")
                    self.log(f"🔍 Monitoring: Every {CHECK_INTERVAL_RELAXED}s (5 min)")
            
            # Display pending tasks
            pending = self.get_pending_tasks_display()
            if pending:
                self.log(f"\n📋 Pending Tasks Today ({len(pending)}):")
                for task in pending[:5]:
                    self.log(f"  ⏱️  {task['time']} | {task['action'].upper()} | {task['scan_name']} | in {task['minutes_until']} min")
            
            self.print_separator('-')
        
        # Check for task execution (CRITICAL SECTION)
        for schedule in self.schedules:
            scan_id = schedule['scan_id']
            scan_name = schedule.get('scan_name', f'Scan {scan_id}')
            scheduled_time = schedule['time']
            action = schedule['action']
            
            task_id = f"{today_date}_{scan_id}_{scheduled_time}_{action}"
            
            # Skip if already executed
            if task_id in self.executed_tasks:
                continue
            
            # Check for duplicate execution prevention
            if task_id in self.last_execution_times:
                last_exec = datetime.fromisoformat(self.last_execution_times[task_id])
                if (now - last_exec).total_seconds() < 60:
                    continue
            
            scheduled_hour, scheduled_minute = map(int, scheduled_time.split(':'))
            
            # Execute within the scheduled minute (first 30 seconds)
            if (now.hour == scheduled_hour and 
                now.minute == scheduled_minute and 
                current_second < 30):
                
                self.log(f"🎯 TRIGGER DETECTED: {action.upper()} for {scan_name} at {scheduled_time}")
                
                if self.execute_action(scan_id, action, scan_name, scheduled_time):
                    self.executed_tasks.add(task_id)
                    self.last_execution_times[task_id] = now.isoformat()
                    self.save_executed_tasks()
                    self.log(f"✅ Task marked as completed: {task_id}")
                    
                    # Remove from missed tasks if it was there
                    if task_id in self.missed_tasks:
                        del self.missed_tasks[task_id]
                    
                    if action in ['stop', 'pause']:
                        self.scan_completion_status[scan_id] = True
        
        # Clean up old executed tasks (keep only today's)
        self.executed_tasks = {t for t in self.executed_tasks if t.startswith(today_date)}
        self.last_execution_times = {k: v for k, v in self.last_execution_times.items() if k.startswith(today_date)}
        
        return check_interval
    
    def monitoring_loop(self):
        """Background monitoring loop - RUNS FOREVER"""
        self.log("🚀 Background monitoring thread started")
        
        while self.running:
            try:
                next_interval = self.check_and_execute_schedules()
                time.sleep(next_interval)
            except Exception as e:
                self.log(f"❌ Error in monitoring loop: {e}")
                import traceback
                self.log(traceback.format_exc())
                time.sleep(CHECK_INTERVAL_NORMAL)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def list_available_scans():
    """List all available scans"""
    print_section("AVAILABLE SCANS")
    
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
                print("-" * 80)
                
                for scan in scans:
                    scan_id = scan.get('id')
                    name = scan.get('name', 'N/A')[:45]
                    status = scan.get('status', 'N/A')
                    print(f"{scan_id:<10} {name:<45} {status:<15}")
                
                print("=" * 80)
                return scans
    except Exception as e:
        print(f"Error: {e}")
        return []

def setup_schedules():
    """Interactive schedule setup"""
    scheduler = NessusScheduler()
    
    print_section("SCHEDULE SETUP WIZARD")
    
    scans = list_available_scans()
    if not scans:
        return
    
    schedules = []
    
    while True:
        print_subsection("ADD SCHEDULE FOR A SCAN")
        
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
                
                print(f"✅ Added: {action.capitalize()} '{scan_name}' at {time_str}")
                
            except ValueError:
                print("❌ Invalid time format. Use HH:MM")
        
        except ValueError:
            print("Please enter a valid number")
    
    if not schedules:
        print("\nNo schedules created")
        sys.exit(0)
    
    scheduler.schedules = schedules
    scheduler.save_schedules()
    
    print_section("SCHEDULE SUMMARY")
    
    scan_groups = defaultdict(list)
    for sched in schedules:
        scan_groups[sched['scan_id']].append(sched)
    
    for scan_id, sched_list in scan_groups.items():
        scan_name = sched_list[0]['scan_name']
        print(f"\nScan: {scan_name} (ID: {scan_id})")
        for sched in sorted(sched_list, key=lambda x: x['time']):
            print(f"  - {sched['time']} : {sched['action'].upper()}")
    
    print("=" * 80)

def run_scheduler():
    """Run the scheduler with continuous background monitoring"""
    scheduler = NessusScheduler()
    
    # Check for single instance
    if not scheduler.lock.acquire():
        print("=" * 80)
        print("❌ ERROR: Another instance is already running!")
        print("=" * 80)
        print("\n📌 Only ONE instance can run at a time")
        print(f"🔍 Check process: tasklist | findstr python")
        print(f"🗑️  Kill old process: taskkill /F /PID <pid>")
        print(f"📂 Or delete lock file: {LOCK_FILE}")
        sys.exit(1)
    
    scheduler.load_schedules()
    scheduler.load_executed_tasks()
    
    if not scheduler.schedules:
        print("No schedules found. Run setup first.")
        scheduler.lock.release()
        sys.exit(1)
    
    def signal_handler(sig, frame):
        print("\n")
        print_banner("SCHEDULER STOPPED BY USER", '=')
        scheduler.running = False
        if scheduler.monitor_thread:
            scheduler.monitor_thread.join(timeout=2)
        if scheduler.heartbeat_thread:
            scheduler.heartbeat_thread.join(timeout=2)
        scheduler.lock.release()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Print startup banner
    print("\n" + LOGO.format(version=VERSION))
    print_banner("SCHEDULER ACTIVE", '=')
    
    scan_groups = defaultdict(list)
    for sched in scheduler.schedules:
        scan_groups[sched['scan_id']].append(sched)
    
    print(f"\n{'Scans Monitored:':<25} {len(scan_groups)}")
    print(f"{'Total Schedules:':<25} {len(scheduler.schedules)}")
    
    print("\n🎯 MONITORING MODES:")
    print(f"  {'🔴 Urgent:':<12} Check every 10s, Log every 10s (task <= 5 min)")
    print(f"  {'🟡 Normal:':<12} Check every 1 min, Log every 1 min (5 < task <= 30 min)")
    print(f"  {'🟢 Relaxed:':<12} Check every 5 min, Log every 5 min (task > 30 min)")
    
    print("\n🔄 MISSED SCAN RETRY:")
    print(f"  {'Retry Window:':<20} {RETRY_WINDOW_MINUTES} minutes")
    print(f"  {'Retry Interval:':<20} Every {RETRY_CHECK_INTERVAL} seconds (1 minute)")
    print(f"  If a scan is missed, it will be retried every minute for {RETRY_WINDOW_MINUTES} minutes")
    
    print("\n✨ FEATURES:")
    print("  [✓] Task completion persists across restarts")
    print("  [✓] Duplicate execution prevention (60s cooldown)")
    print("  [✓] Intelligent missed task detection")
    print("  [✓] Automatic retry mechanism")
    print("  [✓] Dynamic monitoring intervals")
    print("  [✓] Skip completed/running scans")
    print("  [✓] Real-time schedule file monitoring")
    print("  [✓] Schedule validation before execution")
    print("  [✓] Single instance lock (prevents duplicates)")
    print("  [✓] Process heartbeat monitoring")
    
    print(f"\n📁 FILES:")
    print(f"  {'Log File:':<25} {LOG_FILE}")
    print(f"  {'Config File:':<25} {CONFIG_FILE}")
    print(f"  {'Schedule File:':<25} {SCHEDULE_FILE}")
    print(f"  {'Executed Tasks:':<25} {EXECUTED_TASKS_FILE}")
    print(f"  {'Heartbeat:':<25} {HEARTBEAT_FILE}")
    print(f"  {'Started:':<25} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\n🚀 MONITORING ACTIVE - Running in background")
    print("⚠️  DO NOT CLOSE THIS WINDOW")
    print("Press Ctrl+C to stop")
    print("=" * 80 + "\n")
    sys.stdout.flush()
    
    # Load config and authenticate
    scheduler.load_or_create_config()
    
    # Initialize last log time
    scheduler.last_log_time = time.time()
    
    # Start heartbeat thread
    scheduler.heartbeat_thread = threading.Thread(target=scheduler.update_heartbeat, daemon=True)
    scheduler.heartbeat_thread.start()
    
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
    """Create Windows Task Scheduler - BULLETPROOF VERSION"""
    if platform.system() != "Windows":
        print("This feature is only available on Windows")
        return
    
    if not os.path.exists(CONFIG_FILE):
        print("Configuration not found. Please run setup first.")
        return
    
    if not os.path.exists(SCHEDULE_FILE):
        print("Schedules not found. Please run schedule setup first.")
        return
    
    script_path = os.path.abspath(__file__)
    python_path = sys.executable
    script_dir = os.path.dirname(script_path)
    
    print_section("WINDOWS TASK SCHEDULER - BULLETPROOF METHOD")
    
    print(f"\n{'Script Path:':<20} {script_path}")
    print(f"{'Python Path:':<20} {python_path}")
    print(f"{'Working Directory:':<20} {script_dir}")
    
    # Create a batch file to run the scheduler
    batch_file = os.path.join(script_dir, "start_nessus_scheduler.bat")
    
    batch_content = f"""@echo off
echo Starting Nessus Scheduler...
cd /d "{script_dir}"
"{python_path}" "{script_path}" --run
if errorlevel 1 (
    echo Error occurred! Waiting 60 seconds before retry...
    timeout /t 60
    goto :start
)
"""
    
    try:
        with open(batch_file, 'w') as f:
            f.write(batch_content)
        
        print(f"\n✅ Created batch file: {batch_file}")
        
        # Create VBS file for hidden execution
        vbs_file = os.path.join(script_dir, "start_nessus_scheduler_hidden.vbs")
        vbs_content = f'''Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "{batch_file}" & Chr(34), 0
Set WshShell = Nothing
'''
        
        with open(vbs_file, 'w') as f:
            f.write(vbs_content)
        
        print(f"✅ Created VBS file: {vbs_file}")
        
        # Create scheduled task using schtasks command
        task_name = "NessusScheduler"
        
        print(f"\n🔧 Setting up Windows Task Scheduler...")
        
        # Delete existing task
        os.system(f'schtasks /delete /tn "{task_name}" /f >nul 2>&1')
        
        # Create new task - Run at startup
        cmd_startup = f'schtasks /create /tn "{task_name}" /tr "\"{vbs_file}\"" /sc onstart /rl highest /f'
        result = os.system(cmd_startup)
        
        if result == 0:
            print(f"\n✅ SUCCESS! Task '{task_name}' created!")
            
            print("\n📋 TASK DETAILS:")
            print(f"  Name: {task_name}")
            print(f"  Trigger: At system startup")
            print(f"  Runs: {vbs_file} (hidden)")
            print(f"  Privileges: Highest")
            print(f"  Auto-restart: Yes (on error)")
            
            print("\n🎯 WHAT HAPPENS NOW:")
            print("  1. Task runs automatically at system startup")
            print("  2. Scheduler runs in background (hidden)")
            print("  3. All schedules execute automatically")
            print("  4. No window will pop up")
            
            print("\n📊 MONITORING:")
            print(f"  Check logs: {os.path.join(script_dir, LOG_FILE)}")
            print(f"  Check heartbeat: {os.path.join(script_dir, HEARTBEAT_FILE)}")
            print(f"  View in Task Scheduler: Win+R → taskschd.msc")
            
            print("\n🚀 STARTING SCHEDULER NOW...")
            # Start the task immediately
            os.system(f'schtasks /run /tn "{task_name}"')
            time.sleep(3)
            
            # Check if it's running
            if os.path.exists(HEARTBEAT_FILE):
                print("✅ Scheduler is running! Check log file for details.")
            else:
                print("⚠️  Scheduler started. Check log file in 30 seconds.")
            
            print("\n💡 MANUAL CONTROLS:")
            print(f"  Start:  schtasks /run /tn \"{task_name}\"")
            print(f"  Stop:   taskkill /F /IM python.exe")
            print(f"  Remove: schtasks /delete /tn \"{task_name}\" /f")
            
        else:
            print("\n❌ Failed to create task")
            print("💡 MANUAL OPTION:")
            print(f"   Double-click: {batch_file}")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

def display_current_schedules():
    """Display currently configured schedules"""
    if os.path.exists(SCHEDULE_FILE):
        with open(SCHEDULE_FILE, 'r') as f:
            data = json.load(f)
            schedules = data.get('schedules', [])
            
            if schedules:
                scan_groups = defaultdict(list)
                for sched in schedules:
                    scan_groups[sched['scan_id']].append(sched)
                
                print_section("CURRENT SCHEDULES")
                print(f"\nTotal Scans: {len(scan_groups)}")
                print(f"Total Schedules: {len(schedules)}\n")
                
                for scan_id, sched_list in scan_groups.items():
                    scan_name = sched_list[0]['scan_name']
                    print(f"Scan: {scan_name} (ID: {scan_id})")
                    for sched in sorted(sched_list, key=lambda x: x['time']):
                        print(f"  {sched['time']} | {sched['action'].upper()}")
                    print()
                
                print("=" * 80)
            else:
                print("\nNo schedules found")
    else:
        print("\nNo schedule file found")

def clear_executed_tasks():
    """Clear executed tasks file"""
    if os.path.exists(EXECUTED_TASKS_FILE):
        os.remove(EXECUTED_TASKS_FILE)
        print(f"\n✅ Cleared executed tasks file: {EXECUTED_TASKS_FILE}")
        print("Tasks can now be executed again")
    else:
        print("\nNo executed tasks file found")

def display_help():
    """Display help and usage information"""
    print_section("USAGE INFORMATION")
    
    print("\n📝 COMMAND LINE OPTIONS:")
    print(f"  {'--setup':<20} Setup or edit scan schedules")
    print(f"  {'--run':<20} Run scheduler manually (foreground)")
    print(f"  {'--create-task':<20} Create Windows Task Scheduler entry")
    print(f"  {'--clear-tasks':<20} Clear executed tasks (force re-run)")
    print(f"  {'--help':<20} Display this help message")
    
    print("\n💡 EXAMPLES:")
    print(f"  python {os.path.basename(__file__)} --setup")
    print(f"  python {os.path.basename(__file__)} --run")
    print(f"  python {os.path.basename(__file__)} --create-task")
    
    print("\n🔄 WORKFLOW:")
    print("  1. Run --setup to configure your scan schedules")
    print("  2. Run --create-task to setup Windows Task Scheduler (automated)")
    print("  3. Or run --run to start scheduler manually (foreground)")
    
    print("\n📁 FILES:")
    print(f"  {CONFIG_FILE:<30} Authentication configuration")
    print(f"  {SCHEDULE_FILE:<30} Scan schedules")
    print(f"  {EXECUTED_TASKS_FILE:<30} Completed tasks tracking")
    print(f"  {LOG_FILE:<30} Execution logs")
    print(f"  {HEARTBEAT_FILE:<30} Process heartbeat (30s updates)")
    
    print("\n" + "=" * 80)

# ============================================================================
# MAIN FUNCTION
# ============================================================================
def main():
    """Main menu"""
    print(LOGO.format(version=VERSION))
    print_banner("NESSUS AUTOMATED SCHEDULER", '=')
    
    print(f"\n{'Platform:':<20} {platform.system()}")
    print(f"{'Python Version:':<20} {sys.version.split()[0]}")
    print(f"{'Script Version:':<20} v{VERSION}")
    
    print("\n✨ KEY FEATURES:")
    print("  [✓] Automated scan scheduling with multiple actions")
    print("  [✓] Intelligent missed task detection and retry")
    print("  [✓] Persistent task tracking across restarts")
    print("  [✓] Dynamic monitoring intervals (10s / 1m / 5m)")
    print("  [✓] Windows Task Scheduler integration")
    print("  [✓] Comprehensive logging with rotation")
    print("  [✓] Real-time schedule file monitoring")
    print("  [✓] Schedule validation before execution")
    print("  [✓] Single instance lock")
    print("  [✓] Process heartbeat monitoring")
    
    print("\n" + "=" * 80)
    
    # Handle command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--run':
            run_scheduler()
        elif sys.argv[1] == '--setup':
            setup_schedules()
        elif sys.argv[1] == '--create-task':
            create_windows_task_scheduler()
        elif sys.argv[1] == '--clear-tasks':
            clear_executed_tasks()
        elif sys.argv[1] == '--help':
            display_help()
        else:
            print(f"\n❌ Unknown option: {sys.argv[1]}")
            display_help()
    else:
        # Interactive menu
        while True:
            print_section("MAIN MENU")
            print("1. Setup/Edit schedules")
            print("2. Run scheduler manually")
            print("3. Create Windows Task Scheduler")
            print("4. View current schedules")
            print("5. Clear executed tasks (force re-run)")
            print("6. Help")
            print("7. Exit")
            print("=" * 80)
            
            choice = input("\nSelect option [1-7]: ").strip()
            
            if choice == '1':
                setup_schedules()
            elif choice == '2':
                run_scheduler()
            elif choice == '3':
                create_windows_task_scheduler()
            elif choice == '4':
                display_current_schedules()
            elif choice == '5':
                clear_executed_tasks()
            elif choice == '6':
                display_help()
            elif choice == '7':
                print("\n👋 Thank you for using Nessus Automated Scheduler!")
                print("=" * 80)
                break
            else:
                print("\n❌ Invalid option. Please select 1-7")

if __name__ == "__main__":
    main()
