#!/usr/bin/env python3
"""
Nessus Automated Scheduler - Professional Edition v4.2
Author: Security Automation Team
Description: Automated scheduling system for Nessus vulnerability scans with 
             intelligent retry logic and persistent task tracking.
License: MIT
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

# Timing Configuration
CHECK_INTERVAL_URGENT = 10      # 10 seconds when task within 5 minutes
CHECK_INTERVAL_NORMAL = 60      # 1 minute when task between 5-30 minutes
CHECK_INTERVAL_RELAXED = 1200   # 20 minutes when task more than 30 minutes

# Retry Configuration
RETRY_WINDOW_MINUTES = 10       # Retry missed scans for 10 minutes
RETRY_CHECK_INTERVAL = 60       # Check every 1 minute for missed scans

# Log rotation settings
LOG_FILE = "nessus_scheduler.log"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 5

# Version
VERSION = "4.2"

# ============================================================================
# ASCII LOGO
# ============================================================================
LOGO = r"""
  _   _                           _____      _              _       _           
 | \ | |                         / ____|    | |            | |     | |          
 |  \| | ___  ___ ___ _   _ ___ | (___   ___| |__   ___  __| |_   _| | ___ _ __ 
 | . ` |/ _ \/ __/ __| | | / __|  \___ \ / __| '_ \ / _ \/ _` | | | | |/ _ \ '__|
 | |\  |  __/\__ \__ \ |_| \__ \  ____) | (__| | | |  __/ (_| | |_| | |  __/ |   
 |_| \_|\___||___/___/\__,_|___/ |_____/ \___|_| |_|\___|\__,_|\__,_|_|\___|_|   
                                                                                  
          Automated Vulnerability Scan Scheduling System v{version}
"""

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
        self.last_execution_times = {}
        self.setup_logging()
        self.load_or_create_config()
        self.load_executed_tasks()
    
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
            except Exception as e:
                self.log(f"Error loading executed tasks: {e}")
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
    
    def execute_action(self, scan_id, action, scan_name="Unknown", is_retry=False):
        """Execute scan action with retry and completion check"""
        
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
                    self.log(f"RETRY EXECUTION: {action.upper()}")
                else:
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
                    time.sleep(2)
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
                self.log(f"Retry window expired for: {task_id}")
        
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
                    self.log("MISSED TASK DETECTED!")
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
            
            self.log(f"Retrying missed task: {action.upper()} - {scan_name} (Retry #{retry_count + 1}, {minutes_since_missed:.1f} min late)")
            
            if self.execute_action(scan_id, action, scan_name, is_retry=True):
                self.executed_tasks.add(task_id)
                self.last_execution_times[task_id] = now.isoformat()
                self.save_executed_tasks()
                
                del self.missed_tasks[task_id]
                self.log(f"Successfully executed missed task: {task_id}")
                
                if action in ['stop', 'pause']:
                    self.scan_completion_status[scan_id] = True
            else:
                self.missed_tasks[task_id]['retry_count'] += 1
                self.log(f"Retry failed for: {task_id}")
    
    def check_and_execute_schedules(self):
        """Monitor and execute schedules"""
        now = datetime.now()
        current_time_str = now.strftime('%H:%M')
        current_second = now.second
        today_date = now.strftime('%Y-%m-%d')
        
        # Check for missed tasks and retry them
        self.check_missed_tasks()
        self.retry_missed_tasks()
        
        # Calculate time until next task
        minutes_until_next, next_task = self.get_time_until_next_task()
        
        # Determine mode based on time until next task
        if minutes_until_next is not None:
            if minutes_until_next <= 5:
                mode = "URGENT"
                check_interval = CHECK_INTERVAL_URGENT
                log_interval = 10
            elif minutes_until_next <= 30:
                mode = "NORMAL"
                check_interval = CHECK_INTERVAL_NORMAL
                log_interval = 60
            else:
                mode = "RELAXED"
                check_interval = CHECK_INTERVAL_RELAXED
                log_interval = 1200
        else:
            mode = "IDLE"
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
            self.log(f"MONITORING ACTIVE | System Time: {timestamp}")
            self.log(f"Mode: {mode}")
            
            # Show missed tasks being retried
            if self.missed_tasks:
                self.log(f"\nMISSED TASKS BEING RETRIED ({len(self.missed_tasks)}):")
                for task_id, task_info in self.missed_tasks.items():
                    minutes_late = (now - task_info['missed_time']).total_seconds() / 60
                    self.log(f"  {task_info['scheduled_time']} | {task_info['action'].upper()} | {task_info['scan_name']} | {minutes_late:.1f} min late | Retry #{task_info['retry_count']}")
            
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
                for task in pending[:5]:
                    self.log(f"  {task['time']} | {task['action'].upper()} | {task['scan_name']} | in {task['minutes_until']} min")
            
            self.print_separator('-')
        
        # Check for task execution
        for schedule in self.schedules:
            scan_id = schedule['scan_id']
            scan_name = schedule.get('scan_name', f'Scan {scan_id}')
            scheduled_time = schedule['time']
            action = schedule['action']
            
            task_id = f"{today_date}_{scan_id}_{scheduled_time}_{action}"
            
            if task_id in self.executed_tasks:
                continue
            
            if task_id in self.last_execution_times:
                last_exec = datetime.fromisoformat(self.last_execution_times[task_id])
                if (now - last_exec).total_seconds() < 60:
                    continue
            
            scheduled_hour, scheduled_minute = map(int, scheduled_time.split(':'))
            
            if (now.hour == scheduled_hour and 
                now.minute == scheduled_minute and 
                current_second < 30):
                
                self.log(f"TRIGGER DETECTED: {action.upper()} for {scan_name} at {scheduled_time}")
                
                if self.execute_action(scan_id, action, scan_name):
                    self.executed_tasks.add(task_id)
                    self.last_execution_times[task_id] = now.isoformat()
                    self.save_executed_tasks()
                    self.log(f"Task marked as completed: {task_id}")
                    
                    if task_id in self.missed_tasks:
                        del self.missed_tasks[task_id]
                    
                    if action in ['stop', 'pause']:
                        self.scan_completion_status[scan_id] = True
        
        # Clean up old executed tasks (keep only today's)
        self.executed_tasks = {t for t in self.executed_tasks if t.startswith(today_date)}
        self.last_execution_times = {k: v for k, v in self.last_execution_times.items() if k.startswith(today_date)}
        
        return check_interval
    
    def monitoring_loop(self):
        """Background monitoring loop"""
        self.log("Background monitoring thread started")
        
        while self.running:
            try:
                next_interval = self.check_and_execute_schedules()
                time.sleep(next_interval)
            except Exception as e:
                self.log(f"Error in monitoring loop: {e}")
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
    scheduler.load_schedules()
    
    if not scheduler.schedules:
        print("No schedules found. Run setup first.")
        sys.exit(1)
    
    def signal_handler(sig, frame):
        print("\n")
        print_banner("SCHEDULER STOPPED BY USER", '=')
        scheduler.running = False
        if scheduler.monitor_thread:
            scheduler.monitor_thread.join(timeout=2)
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
    
    print("\nMONITORING MODES:")
    print(f"  {'Urgent:':<12} Check every 10s, Log every 10s (task <= 5 min)")
    print(f"  {'Normal:':<12} Check every 1 min, Log every 1 min (5 < task <= 30 min)")
    print(f"  {'Relaxed:':<12} Check every 20 min, Log every 20 min (task > 30 min)")
    
    print("\nMISSED SCAN RETRY:")
    print(f"  {'Retry Window:':<20} {RETRY_WINDOW_MINUTES} minutes")
    print(f"  {'Retry Interval:':<20} Every {RETRY_CHECK_INTERVAL} seconds (1 minute)")
    print(f"  If a scan is missed, it will be retried every minute for {RETRY_WINDOW_MINUTES} minutes")
    
    print("\nFEATURES:")
    print("  [✓] Task completion persists across restarts")
    print("  [✓] Duplicate execution prevention (60s cooldown)")
    print("  [✓] Intelligent missed task detection")
    print("  [✓] Automatic retry mechanism")
    print("  [✓] Dynamic monitoring intervals")
    print("  [✓] Skip completed/running scans")
    
    print(f"\n{'Log File:':<25} {LOG_FILE}")
    print(f"{'Config File:':<25} {CONFIG_FILE}")
    print(f"{'Schedule File:':<25} {SCHEDULE_FILE}")
    print(f"{'Executed Tasks File:':<25} {EXECUTED_TASKS_FILE}")
    print(f"{'Started:':<25} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\nMONITORING ACTIVE - Running in background")
    print("DO NOT CLOSE THIS WINDOW")
    print("Press Ctrl+C to stop")
    print("=" * 80 + "\n")
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
        print("Install with: pip install pywin32")
        return
    
    if not os.path.exists(CONFIG_FILE):
        print("Configuration not found. Please run setup first.")
        return
    
    if not os.path.exists(SCHEDULE_FILE):
        print("Schedules not found. Please run schedule setup first.")
        return
    
    print_section("WINDOWS TASK SCHEDULER SETUP")
    
    script_path = os.path.abspath(__file__)
    python_path = sys.executable
    script_dir = os.path.dirname(script_path)
    
    print(f"\n{'Script Path:':<20} {script_path}")
    print(f"{'Python Path:':<20} {python_path}")
    print(f"{'Working Directory:':<20} {script_dir}")
    
    task_name = "NessusScheduler"
    
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        
        root_folder = scheduler.GetFolder('\\')
        
        # Remove existing task if present
        try:
            root_folder.DeleteTask(task_name, 0)
            print(f"\n[✓] Removed existing task: {task_name}")
        except:
            pass
        
        task_def = scheduler.NewTask(0)
        
        # Registration info
        reg_info = task_def.RegistrationInfo
        reg_info.Description = f"Nessus Automated Scheduler v{VERSION} - Professional Edition"
        reg_info.Author = os.getenv('USERNAME')
        
        # Trigger: Time-based, repeating every 1 minute
        TASK_TRIGGER_TIME = 1
        trigger = task_def.Triggers.Create(TASK_TRIGGER_TIME)
        
        start_time = datetime.now()
        trigger.StartBoundary = start_time.isoformat()
        trigger.Enabled = True
        trigger.Repetition.Interval = "PT1M"
        trigger.Repetition.Duration = ""
        
        # Action: Execute Python script
        TASK_ACTION_EXEC = 0
        action = task_def.Actions.Create(TASK_ACTION_EXEC)
        action.Path = python_path
        action.Arguments = f'"{script_path}" --run'
        action.WorkingDirectory = script_dir
        
        # Settings
        settings = task_def.Settings
        settings.Enabled = True
        settings.StartWhenAvailable = True
        settings.RunOnlyIfNetworkAvailable = True
        settings.DisallowStartIfOnBatteries = False
        settings.StopIfGoingOnBatteries = False
        settings.AllowHardTerminate = True
        settings.MultipleInstances = 3
        settings.ExecutionTimeLimit = "PT1H"
        
        # Principal: Run with highest privileges
        principal = task_def.Principal
        principal.UserId = os.getenv('USERNAME')
        principal.LogonType = 3
        principal.RunLevel = 1
        
        # Register task
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
        
        print_section("SUCCESS!", '=')
        print(f"\nTask '{task_name}' created successfully!")
        
        print("\nTASK DETAILS:")
        print(f"  {'Name:':<20} {task_name}")
        print(f"  {'Version:':<20} v{VERSION} (Professional)")
        print(f"  {'Runs:':<20} Every 1 minute")
        print(f"  {'User:':<20} {os.getenv('USERNAME')}")
        print(f"  {'Privileges:':<20} Highest")
        print(f"  {'Missed Scan Retry:':<20} Enabled ({RETRY_WINDOW_MINUTES} min window)")
        print(f"  {'Task Tracking:':<20} Persistent")
        
        print("\nMANAGEMENT:")
        print("  Open Task Scheduler: Press Win+R, type 'taskschd.msc'")
        print("  Task Location: Task Scheduler Library > NessusScheduler")
        
        print("\n" + "=" * 80)
        
    except Exception as e:
        print(f"\nError creating task: {e}")
        print("\nNOTE: Run this script as Administrator to create scheduled tasks")

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
        confirm = input("\nThis will allow tasks to run again today. Continue? (yes/no): ").strip().lower()
        if confirm == 'yes':
            os.remove(EXECUTED_TASKS_FILE)
            print(f"\n[✓] Cleared executed tasks file: {EXECUTED_TASKS_FILE}")
            print("Tasks can now be executed again")
        else:
            print("Cancelled")
    else:
        print("\nNo executed tasks file found")

def display_help():
    """Display help and usage information"""
    print_section("USAGE INFORMATION")
    
    print("\nCOMMAND LINE OPTIONS:")
    print(f"  {'--setup':<20} Setup or edit scan schedules")
    print(f"  {'--run':<20} Run scheduler manually (foreground)")
    print(f"  {'--create-task':<20} Create Windows Task Scheduler entry")
    print(f"  {'--clear-tasks':<20} Clear executed tasks (force re-run)")
    print(f"  {'--help':<20} Display this help message")
    
    print("\nEXAMPLES:")
    print(f"  python {os.path.basename(__file__)} --setup")
    print(f"  python {os.path.basename(__file__)} --run")
    print(f"  python {os.path.basename(__file__)} --create-task")
    
    print("\nWORKFLOW:")
    print("  1. Run --setup to configure your scan schedules")
    print("  2. Run --create-task to setup Windows Task Scheduler (automated)")
    print("  3. Or run --run to start scheduler manually (foreground)")
    
    print("\nFILES:")
    print(f"  {CONFIG_FILE:<30} Authentication configuration")
    print(f"  {SCHEDULE_FILE:<30} Scan schedules")
    print(f"  {EXECUTED_TASKS_FILE:<30} Completed tasks tracking")
    print(f"  {LOG_FILE:<30} Execution logs")
    
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
    
    print("\nKEY FEATURES:")
    print("  [✓] Automated scan scheduling with multiple actions")
    print("  [✓] Intelligent missed task detection and retry")
    print("  [✓] Persistent task tracking across restarts")
    print("  [✓] Dynamic monitoring intervals (10s / 1m / 20m)")
    print("  [✓] Windows Task Scheduler integration")
    print("  [✓] Comprehensive logging with rotation")
    
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
            print(f"\nUnknown option: {sys.argv[1]}")
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
                print("\nThank you for using Nessus Automated Scheduler!")
                print("=" * 80)
                break
            else:
                print("\n[!] Invalid option. Please select 1-7")

if __name__ == "__main__":
    main()
