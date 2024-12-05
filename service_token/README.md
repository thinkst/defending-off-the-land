# Windows Service Canarytoken

## Quick-start

From an administrator PowerShell console, setup and start the Service:
`.\CanaryService.ps1 -Setup -TokenUrl <webbug token URL> && .\CanaryService.ps1 -Start`

Optionally, the details of the Service can be configured in the `-Setup` step with the following options:
- `-serviceName <Short name of service>`
- `-serviceDisplayName <Longer display name of service`
- `-serviceDescription <String of service description>`

To remove simply run:
`.\CanaryService.ps1 -Remove`

## Why

As noted in the [MITRE ATT&CK T1489](https://attack.mitre.org/techniques/T1489/) write-up, a number of attackers and malware disable certain
discovered defensive services, including anti-malware engines and backup tools. As a post-exploitation technique, it makes sense to disable
those services before bringing other payloads onto the compromised host. This Canarytoken service appears to be a defensive service, but alerts
when stopped.
