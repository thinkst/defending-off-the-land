# Scheduled Task monitor

This script creates a new scheduled task that alerts if any other scheduled tasks are created that:
- Run a suspicious command: `powershell.exe`, `cmd.exe`, `*.bat`, `mshta.exe`, `rundll.exe`, `regsvr32.exe`
- Run a program that is writable by the user (to filter out legitimate tasks)
- Operate on user-writable paths

## Installer script

Run `schedtask.ps1` as administrator with a web bug Canarytoken URL as an argument. This will enable Object Audit Logging and create a task that is triggered by new scheduled tasks that alerts to that web URL. It sets the User-Agent to the discovered task name for easier analysis.
