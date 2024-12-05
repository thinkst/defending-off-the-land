# Windows Service Canarytoken

From an administrator PowerShell console, setup and start the Service:
`.\CanaryService.ps1 -Setup -TokenUrl <webbug token URL> && .\CanaryService.ps1 -Start`

Optionally, the details of the Service can be configured in the `-Setup` step with the following options:
- `-serviceName <Short name of service>`
- `-serviceDisplayName <Longer display name of service`
- `-serviceDescription <String of service description>`