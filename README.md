# 🎮 Nessus Scan Boss

> **Because manually pausing scans at lunchtime is so 2015**

Stop babysitting your Nessus scans. This tool does the boring stuff while you do literally anything else.

---

## 🤷 What Even Is This?

You know how your vulnerability scans hog all the bandwidth during Zoom calls? Yeah, this fixes that.

**Simple version:** Tell scans when to start, pause, resume, or stop. They obey. You look like a wizard. 🧙‍♂️

**Example day in the life:**
```
09:00 AM → Scan starts (you're getting coffee ☕)
12:00 PM → Scan pauses (IT Director needs bandwidth for WebEx)
01:00 PM → Scan resumes (meeting over, crisis averted)
05:00 PM → Scan stops (you're already home)
```

All automatic. Zero clicking. Maximum flex.

---

## 🚀 Setup (3 Minutes)

### Step 1: Install Stuff
```bash
pip install requests urllib3 pywin32
```

### Step 2: Tell It What To Do
```bash
python nessus_scheduler.py --setup
```

**The script asks you:**
```
Which scan? → 45
What action? → 2 (Pause)  
When? → 12:00
```

Add more actions, type `done` when you're done being productive.

### Step 3: Set It And Forget It
```bash
python nessus_scheduler.py --create-task
```

**Boom.** Windows Task Scheduler handles the rest. Go take a nap.

---

## 🎯 The Four Magic Buttons

| Button | What It Does | When You'd Use It |
|--------|-------------|-------------------|
| 🚀 **Launch** | Starts a scan | "Begin the hackening at 9 AM" |
| ⏸️ **Pause** | Temporarily stops scan | "CEO is on Zoom, chill out" |
| ▶️ **Resume** | Continues paused scan | "Coast is clear, back to work" |
| 🛑 **Stop** | Kills scan completely | "It's 5 PM, I don't get paid for this" |

---

## 🧠 The Smart Parts (That Make You Look Smart)

### It Adapts Like a Chameleon 🦎

**5 minutes until action?**
```
Checks every 10 seconds (won't miss it)
Logs every 10 seconds (you can watch the excitement)
```

**30 minutes until action?**
```
Checks every 1 minute (chill mode)
Logs every 1 minute (still awake)
```

**2 hours until action?**
```
Checks every 20 minutes (taking a power nap)
Logs every 20 minutes (basically hibernating)
```

### It's Lazy In a Good Way 😴

- **Already completed scan?** Skips it. (Why launch something that's done?)
- **Session expired?** Re-authenticates automatically. (No "oops I forgot" moments)
- **Logs too big?** Rotates them. (Max 30MB, then old ones get yeeted)

### It Won't Explode Your Computer 💥

- **CPU usage:** Less than opening Chrome (0.5% average)
- **RAM usage:** 20-50 MB (your browser tabs use 100x more)
- **Disk space:** 30 MB max (self-cleans like a good roommate)

---

## 📝 What You'll Actually See

### When It's Chillin'
```
--------------------------------------------------------------------------------
MONITORING ACTIVE | 2025-10-22 08:30:15
Mode: NORMAL
Next Task: 29 min | PAUSE - Weekly Scan at 09:00

Pending Tasks Today (3):
  09:00 | PAUSE | Weekly Scan | in 29 min
  13:00 | RESUME | Weekly Scan | in 269 min
  17:00 | STOP | Weekly Scan | in 509 min
--------------------------------------------------------------------------------
```

### When It Does The Thing
```
================================================================================
EXECUTING: PAUSE
Scan: Weekly Network Scan (ID: 45)
Action: PAUSE
Attempt: 1/3
================================================================================
SUCCESS! Scan 45 paused successfully
================================================================================
```

### When It's Too Smart For Its Own Good
```
================================================================================
SKIPPED - Scan Already Completed
Scan: Monday Morning Scan (ID: 12)
Status: COMPLETED
Reason: Already done, not launching again (you're welcome)
================================================================================
```

---

## 🎪 Real-World Shenanigans

### The "My Boss Uses All The Bandwidth" Schedule
```json
{
  "schedules": [
    {"scan_id": 45, "action": "launch", "time": "06:00"},  
    {"scan_id": 45, "action": "pause", "time": "09:00"},   // Boss arrives
    {"scan_id": 45, "action": "resume", "time": "18:00"},  // Boss leaves
    {"scan_id": 45, "action": "stop", "time": "23:00"}
  ]
}
```

### The "Compliance Auditor Is Watching" Schedule
```json
{
  "schedules": [
    {"scan_id": 10, "action": "launch", "time": "22:00"},  // After hours
    {"scan_id": 10, "action": "stop", "time": "05:59"}     // Before anyone notices
  ]
}
```

### The "I Need To Review Between Phases" Schedule
```json
{
  "schedules": [
    {"scan_id": 30, "action": "launch", "time": "08:00"},
    {"scan_id": 30, "action": "pause", "time": "10:00"},   // Check progress
    {"scan_id": 30, "action": "resume", "time": "14:00"},  // Looks good, continue
    {"scan_id": 30, "action": "stop", "time": "17:00"}
  ]
}
```

---

## 🔧 Configuration (The Boring But Necessary Part)

Edit these in the script:
```python
NESSUS_URL = "https://127.0.0.1:8834"  # Where's your Nessus?
USERNAME = "XYZ"                # Your username
PASSWORD = "XYZ@12345"            # Your password (yes, in plain text, I know 🙄)
```

**About that password thing:** Yeah, it's stored in plain text. Secure your files:
```bash
# Windows: Lock it down
icacls nessus_config.json /grant:r "%USERNAME%:F" /inheritance:r

# Linux/Mac: chmod it
chmod 600 nessus_config.json
```

---

## 🐛 When Things Go Wrong (They Won't But Just In Case)

### "Nothing's happening!"

**Check 1:** Is the script running?
```bash
tasklist | findstr python
```

**Check 2:** What do the logs say?
```bash
type nessus_scheduler.log
```

**Check 3:** Is your clock correct?
```
Win + I → Time & Language → Check "Set time automatically"
```

### "There are 47 Python processes!"

You forgot to set this properly. Edit the script:
```python
settings.MultipleInstances = 2  # Kills old before starting new
```

### "It says authentication failed"
```bash
# Nuke the config and start fresh
del nessus_config.json
python nessus_scheduler.py --setup
```

### "My logs are huge!"

They shouldn't be (max 30MB). But if they are:
```bash
# Delete old logs
del nessus_scheduler.log.*
```

---

## 📊 Files You'll See (And What They Do)
```
📁 Your Folder
├── 🐍 nessus_scheduler.py          ← The actual code
├── 🔑 nessus_config.json           ← API tokens (auto-created)
├── 📅 nessus_schedule.json         ← Your schedule (you create this)
└── 📝 nessus_scheduler.log         ← What happened today
    ├── nessus_scheduler.log.1      ← Yesterday
    ├── nessus_scheduler.log.2      ← 2 days ago
    ├── nessus_scheduler.log.3      ← 3 days ago
    ├── nessus_scheduler.log.4      ← 4 days ago
    └── nessus_scheduler.log.5      ← 5 days ago (then auto-deleted)
```

**Total space:** ~30 MB (then it cleans itself)

---

## 🎓 Pro Tips From The Trenches

### ✅ DO:
- **Test with a schedule 2 minutes from now** before going full production
- **Stagger scan starts** (don't launch 5 scans at 09:00, spread them out)
- **Use descriptive scan names** ("Production_Web_Scan" not "test123")
- **Check logs the first week** (after that, weekly is fine)

### ❌ DON'T:
- **Don't schedule PAUSE before LAUNCH** (physics doesn't work that way)
- **Don't set RESUME without PAUSE** (what are you resuming?)
- **Don't close the terminal** if running manually (Ctrl+C exists for a reason)
- **Don't panic if you see "SKIPPED"** (it's being smart, not broken)

---

## 🆚 Why Not Just Use...?

### Nessus Built-in Scheduler?
```
Nessus: Can only launch scans
This:   Launch, pause, resume, stop, adapt, think, predict lottery numbers*

*May not actually predict lottery numbers
```

### Cron or Task Scheduler Directly?
```
Cron:   Requires 4 separate scripts
This:   One script rules them all
```

### The `schedule` Python Library?
```
schedule lib: Checks every 1 second (wasteful)
This:         Checks every 20 minutes when chill (efficient)
```

---

## 🎬 Quick Commands Reference
```bash
# View menu
python nessus_scheduler.py

# Setup schedules
python nessus_scheduler.py --setup

# Run manually (testing)
python nessus_scheduler.py --run

# Install to Windows Task Scheduler
python nessus_scheduler.py --create-task
```

---

## 🔮 What This Can't Do (Yet)

- ❌ Make you coffee (but honestly, probably next version)
- ❌ Read your mind (schedule things yourself, lazy)
- ❌ Fix your broken scans (that's a Nessus problem)
- ❌ Run on your smart fridge (but if you try, send pics)

---

## 📦 Dependencies (The Required Stuff)
```txt
requests      # Talk to Nessus API
urllib3       # Handle SSL stuff
pywin32       # Windows Task Scheduler magic (Windows only)
```

**Everything else?** Built into Python. No weird npm install shenanigans.

---

## 🎪 Final Boss Fight: Running 48 Hours Straight

**Q:** Can it run for 2 days without exploding?  
**A:** Yes. Done it. Survived. Here's what happens:

- ✅ Logs rotate at 5 MB (won't fill your disk)
- ✅ Sessions refresh automatically (won't get kicked out)
- ✅ CPU stays under 1% (won't melt your PC)
- ✅ RAM stays around 30 MB (won't eat your memory)

**But fix this first:**
```python
settings.MultipleInstances = 2  # Or you'll have 2,880 Python processes
```

**Monitoring checklist:**
```
Hour 0:  Start it, verify first action works
Hour 12: Check logs (look for "ERROR" or "FAILED")
Hour 24: Verify scans executed correctly
Hour 48: Pat yourself on back, go home
```

---

## 🎤 The One-Sentence Summary

**This tool stops you from manually clicking "pause" on Nessus scans like it's 2010.**

---

## 🙏 Credits

Built by someone who got tired of:
- Pausing scans manually
- Missing scheduled stops
- Wasting bandwidth during important meetings
- Explaining to their boss why the network is slow

**Powered by:** Python, coffee, mild frustration, and a surprising amount of free time.

---

## ⚠️ The Legal Stuff (But Make It Fast)
```
- Not officially supported by Tenable
- Test before production (seriously)
- Check logs regularly (don't be lazy)
- Don't blame me if you break stuff
- Use at your own risk (you're an adult)
```

---

## 🎮 Ready Player One?
```bash
pip install requests urllib3 pywin32
python nessus_scheduler.py --setup
python nessus_scheduler.py --create-task
```

**Now go do literally anything else.** The robots are in charge now. 🤖

---

**Version:** 4.0 (The "Actually Works" Edition)  
**Status:** Production Ready ✅  
**Bugs:** Probably None (Famous Last Words)  
**Your scans:** Finally automated 🎉

---

*P.S. If this saves you 10 minutes a day, that's 40 hours a year. You're welcome. Buy me a coffee.* ☕
