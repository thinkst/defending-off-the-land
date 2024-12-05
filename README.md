# Windows tokens for defending off the land

This repository contains a number of scripts for creating and deploying extent Windows OS features in non-traditional ways.
With these scripts your Windows systems that you may not be allowed to install or deploy agents to can provide additional 
visibility for suspicious behavior.

The capabilities include:
- RDP Canarytoken (`rdp_winrm`) - This script configures the RDP service to listen for logins and serve a certificate that triggers an alert from the would-be attacker's machine
- WinRM Canarytoken (`rdp_winrm`) - This script configures the WinRM service to listen on HTTPS (port 5986) certificate that triggers an alert from the would-be attacker's machine
- Scheduled Task alerter (`task_token`) - This script installs a scheduled task that monitors for other scheduled tasks that are suspicious, and alerts on their creation
- Windows Registry Monitor (`registry_monitor`) - This script (which can be installed as a periodic task) monitors ~80 sensitive Registry keys and alerts on their change
- Windows Service Canarytoken (`service_token`) - This script registers itself as a Windows Service that appears to be a defensive application (e.g., MalwareBytes). If the Service is ever stopped, it alerts.
- Windows Projected File System (`file_access_token`) - These scripts show examples of Windows ProjFS, SMB Share, TarPit extended examples.
