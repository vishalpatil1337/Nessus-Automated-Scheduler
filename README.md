# Nessus Automated Scheduler v4.0

A Python-based automated scheduler for Tenable Nessus vulnerability scans with intelligent monitoring, adaptive logging, and Windows Task Scheduler integration.

## Features

- ✅ **Automated Scan Management** - Schedule launch, pause, resume, and stop actions
- 🔄 **Continuous Background Monitoring** - Runs in background thread without blocking
- 🧠 **Adaptive Monitoring Modes**
  - **Urgent Mode**: Check every 10s (task within 5 minutes)
  - **Normal Mode**: Check every 1 min (task between 5-30 minutes)
  - **Relaxed Mode**: Check every 20 min (task > 30 minutes)
- 📝 **Auto-Rotating Logs** - 5MB max per file, keeps 5 backups (30MB total)
- 🔐 **Auto-Authentication** - Detects and manages API tokens automatically
- 🪟 **Windows Task Scheduler Integration** - Set and forget automation
- 📊 **Real-Time Status Display** - Shows pending tasks and system time
- 🎯 **Multiple Scan Support** - Independent scheduling for multiple scans
- 🛡️ **Smart Execution** - Skips already completed scans automatically

## Requirements

### System Requirements
- **OS**: Windows (Task Scheduler feature), Linux/macOS (manual mode)
- **Python**: 3.6 or higher
- **Nessus**: Running instance (default: https://127.0.0.1:8834)

### Python Dependencies
```bash
pip install requests urllib3
```

### Optional (for Windows Task Scheduler)
```bash
pip install pywin32
```

## Installation

1. **Clone or download** the script
```bash
git clone 
cd nessus-scheduler
```


2. **Configure credentials** (edit script)
```python
NESSUS_URL = "https://127.0.0.1:8834"
USERNAME = "your_username"
PASSWORD = "your_password"
```

## Quick Start

### Interactive Setup

Run the script without arguments for the menu:
```bash
python nessus_scheduler.py
```

**Menu Options:**
1. Setup/Edit schedules
2. Run scheduler manually
3. Create Windows Task Scheduler
4. View current schedules
5. Exit

### Command Line Usage

**Setup Schedules:**
```bash
python nessus_scheduler.py --setup
```

**Run Scheduler Manually:**
```bash
python nessus_scheduler.py --run
```

**Create Windows Task:**
```bash
python nessus_scheduler.py --create-task
```

## Configuration

### Files Created
- `nessus_config.json` - Authentication tokens (auto-generated)
- `nessus_schedule.json` - Scheduled tasks
- `nessus_scheduler.log` - Primary log file
- `nessus_scheduler.log.1` to `.5` - Rotated backups

### Timing Configuration
```python
CHECK_INTERVAL_URGENT = 10      # 10 seconds (task <= 5 min)
CHECK_INTERVAL_NORMAL = 60      # 1 minute (5 < task <= 30 min)
CHECK_INTERVAL_RELAXED = 1200   # 20 minutes (task > 30 min)
```

### Log Rotation Settings
```python
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 5            # Keep 5 backups
```

## Usage Examples

### Example 1: Schedule Single Scan

1. Run setup:
```bash
python nessus_scheduler.py --setup
```

2. Select scan from list:
```
Enter Scan ID: 12
```

3. Choose action:
```
1. Launch scan
Action: 1
```

4. Set time:
```
Time: 09:30
```

### Example 2: Schedule Multiple Actions for One Scan
```
Scan ID: 12
Action: 1 (Launch)
Time: 09:00

Scan ID: 12
Action: 4 (Stop)
Time: 17:00

Type 'done' to finish
```

### Example 3: Schedule Multiple Scans
```
Scan ID: 12
Action: 1 (Launch)
Time: 09:00

Scan ID: 15
Action: 1 (Launch)
Time: 10:00

Scan ID: 18
Action: 1 (Launch)
Time: 11:00

Type 'done' to finish
```

## Windows Task Scheduler Setup

### Automatic Setup (Recommended)

1. Run as Administrator:
```bash
python nessus_scheduler.py --create-task
```

2. Verify task created:
- Open Task Scheduler (`taskschd.msc`)
- Look for task: **NessusScheduler**

### Manual Setup

1. **Open Task Scheduler** (`Win + R` → `taskschd.msc`)

2. **Create Basic Task**
   - Name: `NessusScheduler`
   - Description: `Nessus Scan Scheduler`

3. **Trigger**
   - Daily
   - Start: Today at system startup
   - Repeat: Every 5 minutes
   - Duration: Indefinitely

4. **Action**
   - Program: `C:\Path\To\Python\python.exe`
   - Arguments: `"C:\Path\To\nessus_scheduler.py" --run`
   - Start in: `C:\Path\To\Script\Directory`

5. **Settings**
   - ✅ Run whether user is logged on or not
   - ✅ Run with highest privileges
   - ✅ If task fails, restart every 1 minute
   - ⚠️ **Important**: Stop existing instance before starting new

## Monitoring Modes Explained

### Urgent Mode (Task ≤ 5 minutes)
```
Monitoring: Every 10 seconds
Logging: Every 10 seconds
Purpose: Ensure immediate execution
```

### Normal Mode (5 < Task ≤ 30 minutes)
```
Monitoring: Every 1 minute
Logging: Every 1 minute
Purpose: Balanced monitoring
```

### Relaxed Mode (Task > 30 minutes)
```
Monitoring: Every 20 minutes
Logging: Every 20 minutes
Purpose: Minimal resource usage
```

## Log Output Examples

### Urgent Mode Log
```
--------------------------------------------------------------------------------
MONITORING ACTIVE | Windows System Time: 2025-10-22 09:25:30
Mode: URGENT
Next Task: 4 min | LAUNCH - Weekly Vulnerability Scan at 09:30
Monitoring: Every 10s | Logging: Every 10s

Pending Tasks Today (3):
  09:30 | LAUNCH | Weekly Vulnerability Scan | in 4 min
  12:00 | STOP | Weekly Vulnerability Scan | in 154 min
  18:00 | LAUNCH | Network Scan | in 514 min
--------------------------------------------------------------------------------
```

### Execution Log
```
================================================================================
EXECUTING: LAUNCH
Scan: Weekly Vulnerability Scan (ID: 12)
Action: LAUNCH
Attempt: 1/3
================================================================================
SUCCESS! Scan 12 launched successfully
================================================================================
```

### Skip Log (Already Completed)
```
================================================================================
SKIPPED - Scan Already Completed
Scan: Weekly Vulnerability Scan (ID: 12)
Status: COMPLETED
Reason: Scan status is 'completed', skipping scheduled launch
================================================================================
```

## Troubleshooting

### Issue: Multiple Python Processes Running

**Cause**: Task Scheduler creating duplicate instances

**Solution**: Edit Task Scheduler settings:
```python
settings.MultipleInstances = 2  # TASK_INSTANCES_STOP_EXISTING
```

Or add process lock in code (see manual for details).

### Issue: Authentication Failed

**Cause**: Invalid credentials or expired session

**Solution**:
1. Delete `nessus_config.json`
2. Re-run setup
3. Verify Nessus credentials

### Issue: Scans Not Executing

**Cause**: Time mismatch or already completed

**Check**:
1. Verify Windows system time is correct
2. Check log file for execution attempts
3. Verify scan status in Nessus console
4. Check if scan was already completed

### Issue: Log File Growing Too Large

**Current Protection**: Auto-rotation at 5MB (max 30MB total)

**Manual Cleanup**:
```bash
# Delete old logs
rm nessus_scheduler.log.*

# Or adjust settings in script
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
```

### Issue: Task Scheduler Not Running

**Check**:
1. Task Scheduler service is running
2. Task has correct permissions (Run with highest privileges)
3. Python path is correct in task settings
4. User account has necessary permissions

## Best Practices

### For 2-Day Continuous Operation

1. **Fix Task Scheduler Settings**
```python
   settings.MultipleInstances = 2  # Stop existing before new
```

2. **Monitor Resource Usage**
   - Check Task Manager for multiple `python.exe`
   - Review logs every 12 hours
   - Verify scan execution in Nessus

3. **Set Reasonable Intervals**
   - Task Scheduler: Every 5-10 minutes (not 1 minute)
   - Let script handle frequent checks internally

### For Production Use

1. **Use Dedicated Service Account**
2. **Enable Task History** in Task Scheduler
3. **Set Up Alerting** for failed scans
4. **Regular Log Review** (weekly)
5. **Test Schedule** before production deployment
6. **Backup Configuration Files** regularly

## Security Considerations

- ⚠️ **Credentials in Script**: Store securely, restrict file permissions
- 🔒 **SSL Verification Disabled**: Uses `verify=False` for self-signed certs
- 🛡️ **API Token Storage**: Stored in plain text in `nessus_config.json`
- 👤 **Run with Least Privilege**: Use dedicated Nessus service account

**Recommended**:
```bash
# Linux/macOS: Restrict config file permissions
chmod 600 nessus_config.json

# Windows: Use NTFS permissions to restrict access
```

## File Structure
```
nessus-scheduler/
├── nessus_scheduler.py          # Main script
├── nessus_config.json           # Authentication (auto-generated)
├── nessus_schedule.json         # Schedules (user-defined)
├── nessus_scheduler.log         # Current log
├── nessus_scheduler.log.1       # Backup log 1
├── nessus_scheduler.log.2       # Backup log 2
├── nessus_scheduler.log.3       # Backup log 3
├── nessus_scheduler.log.4       # Backup log 4
├── nessus_scheduler.log.5       # Backup log 5
├── requirements.txt             # Dependencies
└── README.md                    # This file
```

## Schedule File Format

`nessus_schedule.json`:
```json
{
  "schedules": [
    {
      "scan_id": 12,
      "scan_name": "Weekly Vulnerability Scan",
      "action": "launch",
      "time": "09:30"
    },
    {
      "scan_id": 12,
      "scan_name": "Weekly Vulnerability Scan",
      "action": "stop",
      "time": "17:00"
    }
  ]
}
```

## API Endpoints Used

- `POST /session` - Authentication
- `GET /session/keys` - Retrieve API keys
- `PUT /session/keys` - Create API keys
- `GET /scans` - List all scans
- `GET /scans/{id}` - Get scan details
- `POST /scans/{id}/launch` - Launch scan
- `POST /scans/{id}/pause` - Pause scan
- `POST /scans/{id}/resume` - Resume scan
- `POST /scans/{id}/stop` - Stop scan

## Version History

### v4.0 (Current)
- ✅ Fixed continuous monitoring without Enter key requirement
- ✅ Added adaptive logging intervals
- ✅ Background thread execution
- ✅ Smart skip logic for completed scans
- ✅ Improved status display
- ✅ Log rotation implementation

### v3.x
- Multiple scan support
- Windows Task Scheduler integration
- Auto-token detection

### v2.x
- Basic scheduling
- Manual execution

### v1.x
- Initial release

## Support & Contribution

For issues, questions, or contributions:
- Review logs first: `nessus_scheduler.log`
- Check Nessus API documentation
- Verify network connectivity to Nessus server

## License

This script is provided as-is for educational and automation purposes. Use at your own risk.

## Disclaimer

- Test thoroughly in non-production environment first
- Always maintain backup access to Nessus console
- Monitor first few executions manually
- Not officially supported by Tenable

---
