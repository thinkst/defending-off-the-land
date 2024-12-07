$taskName = "ADLoginMonitor1"
$canarytoken = "" # Generate a Web Bug Canarytoken and copy the unique value here
$domain = "canarytokens.com"
$tokenedUsernames = "JacobT,MarcoS,RobertoA" # Edit this list to match the fake credentials you've drop in your environment
$tokenCheckPeriodSeconds = "60"
$LOG_CREDENTIAL_VALIDATION = 4776
$LOG_KERBEROS_AUTHENTICATION_SERVICE = 4768
$REGEX_FOR_USER_PRINCIPAL_NAME = "^(.*?)(?:@|\\)"
$REGEX_FOR_DOWNLEVEL_LOGON_NAME = "^(?:.*\\)?(.+)$"
$UNKNOWN_VALUE = ""
$serviceScriptPath = "C:\svc.ps1"
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrEmpty($canarytoken)) {
    Write-Error "Please generate a Canarytoken and copy the unique value into `$canarytoken"
}

if ([string]::IsNullOrEmpty($domain)) {
    Write-Error "You must specify a Canarytokens server domain."
}

if ([string]::IsNullOrEmpty($tokenedUsernames)) {
    Write-Error "List decoy usernames separated by commas, e.g.: JacobT,MarcoS,RobertoA"
}

# Enable the Audit Event Log policies on the domain for 4776, 4768 events
Write-Host "Setting Credential Validation and Kerberos Authentication Service to audit failed events..."
auditpol /set /subcategory:"Credential Validation" /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /failure:enable
# And do a Group Policy update
gpupdate /force

# Run checks to make sure auditing is on as expected
function CheckAuditPolicy {
  param (
      [string]$subcategories
  )

  $auditSetting = auditpol /get /subcategory:"$subcategories" | Select-String "Failure"

  if (-not $auditSetting) {
      Write-Host "Error: Audit policy for '$subcategories' is not set to report on 'Failure', is there a conflicting Group Policy Object rule?"
      exit
  }
}

CheckAuditPolicy -subcategories "Credential Validation"
CheckAuditPolicy -subcategories "Kerberos Authentication Service"

$actionsScript = @"
function Trip-Canarytoken {
    param (
        [Hashtable]`$httpArgs
    )
    `$encodedParams = @()
    foreach (`$key in `$httpArgs.Keys) {
        # URL-encode the key and value
        `$encodedKey = [System.Net.WebUtility]::UrlEncode(`$key)
        `$encodedValue = [System.Net.WebUtility]::UrlEncode(`$httpArgs[`$key])
        `$encodedParams += "`$encodedKey=`$encodedValue"
        Write-Host `$encodedParams
        Write-Host `$encodedKey
    }
 
    `$queryString = [String]::Join("&amp;", `$encodedParams)
    `$url = 'http://$domain/stuff/terms/$canarytoken/post.jsp?' + `$queryString
    try {
        `$response = Invoke-RestMethod -Uri `$url -Method Get
        Write-Host 'Request was successfull to '+ `$url
    }
    catch {
        Write-Host 'Error occurred: `$_'
    }
}
`$timeLimit = (Get-Date).AddSeconds(-2 * $tokenCheckPeriodSeconds);
`$credential_validation_events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $LOG_CREDENTIAL_VALIDATION; StartTime = `$timeLimit} | Where-Object { `$_.Properties[3].Value -eq 0xC0000064 })
`$kerberos_authentication_events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $LOG_KERBEROS_AUTHENTICATION_SERVICE; StartTime = `$timeLimit} | Where-Object { `$_.Properties[6].Value -eq 0x6 })
`$kerberos_authentication_bad_events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $LOG_KERBEROS_AUTHENTICATION_SERVICE; StartTime = `$timeLimit} | Where-Object { `$_.Properties.Count -eq 0 })
`$log_entries = `$credential_validation_events + `$kerberos_authentication_events
`$users = '$tokenedUsernames' -split ',';

foreach (`$log_entry in `$kerberos_authentication_bad_events) {
  `$log_xml = [xml]`$log_entry.ToXml();
  if (!(Get-Member -inputobject `$log_xml.Event -name 'ProcessingErrorData' -MemberType Properties)) {
      continue
  }
  `$error_data = `$log_xml.Event.ProcessingErrorData.EventPayload;
  `$error_data_array = `$error_data -split '0000';
  `$parsed_error_array = @();
  foreach (`$item in `$error_data_array) {
    `$item = `$item -replace '00', '';
    if (`$item.Length -eq 0) {
        continue
    }
    `$curr_data = `$(-join (`$item -split '(..)' | ? { `$_ } | % { [char][convert]::ToUInt32(`$_,16) }));
    if (`$curr_data -match '::ffff:') {
        `$ip = [System.Net.IPAddress]::Parse(`$(`$curr_data -split 'ffff:')[1]);
    }
    `$parsed_error_array += `$curr_data;
  }

  `$attemptedUsername = `$parsed_error_array[0];

  if (`$attemptedUsername -match '$REGEX_FOR_USER_PRINCIPAL_NAME') {
    `$attemptedUsername = `$matches[1];
  }
  if (`$attemptedUsername -match '$REGEX_FOR_DOWNLEVEL_LOGON_NAME') {
    `$attemptedUsername = `$matches[1]
  }

  if (`$attemptedUsername -notin `$users) {
    continue;
  }

  `$workstationName = Invoke-Expression 'ping -a `$ip' | Where-Object { `$_ -match 'Pinging (.+?) \[' } | ForEach-Object { `$matches[1] } | Select-Object -Last 1;

  if ([string]::IsNullOrEmpty(`$workstationName)) {
  `$workstationName = '$UNKNOWN_VALUE';
  }
  if ([string]::IsNullOrEmpty(`$ip)) {
    `$dnsIP = '$UNKNOWN_VALUE';
  } else {
    `$dnsIP = [System.BitConverter]::ToString(`$ip.GetAddressBytes()) -replace '-'
  }

   Trip-Canarytoken @{record_id = `$(`$log_entry.recordId); machine_name = `$(`$log_entry.MachineName); workstation_name = `$(`$workstationName); workstation_ip = `$(`$dnsIP); username = `$(`$attemptedUsername)}
}

foreach (`$log_entry in `$log_entries) {
  if (`$log_entry.Id -eq $LOG_CREDENTIAL_VALIDATION) {
    `$attemptedUsername = `$log_entry.Properties[1].Value;
  } elseif (`$log_entry.Id -eq $LOG_KERBEROS_AUTHENTICATION_SERVICE) {
    `$attemptedUsername = `$log_entry.Properties[0].Value;
  }

  if (`$attemptedUsername -match '$REGEX_FOR_USER_PRINCIPAL_NAME') {
    `$attemptedUsername = `$matches[1];
  }
  if (`$attemptedUsername -match '$REGEX_FOR_DOWNLEVEL_LOGON_NAME') {
    `$attemptedUsername = `$matches[1]
  }

  if (`$attemptedUsername -notin `$users) {
    continue;
  }

  if (`$log_entry.Id -eq $LOG_CREDENTIAL_VALIDATION) {
    `$workstationName = `$log_entry.Properties[2].Value;
    `$hostnameResult = Invoke-Expression 'ping `$workstationName -4' | Select-String -Pattern '\d+\.\d+\.\d+\.\d+' | ForEach-Object { `$_.Matches.Value } | Select-Object -Last 1;
    if (`$hostnameResult) {
      `$ip = [System.Net.IPAddress]::Parse(`$hostnameResult);
    }
  }

  if (`$log_entry.Id -eq $LOG_KERBEROS_AUTHENTICATION_SERVICE) {
    `$ip = [System.Net.IPAddress]::Parse(`$log_entry.Properties[9].Value);
    `$workstationName = Invoke-Expression 'ping -a `$ip' | Where-Object { `$_ -match 'Pinging (.+?) \[' } | ForEach-Object { `$matches[1] } | Select-Object -Last 1;
  }

  if ([string]::IsNullOrEmpty(`$workstationName)) {
    `$workstationName = '$UNKNOWN_VALUE';
  }
  if ([string]::IsNullOrEmpty(`$ip)) {
    `$dnsIP = '$UNKNOWN_VALUE';
  } else {
    `$dnsIP = [System.BitConverter]::ToString(`$ip.GetAddressBytes()) -replace '-'
  }
  Trip-Canarytoken @{record_id = `$(`$log_entry.recordId); machine_name = `$(`$log_entry.MachineName); workstation_name = `$(`$workstationName); workstation_ip = `$(`$dnsIP); username = `$(`$attemptedUsername)}
}
"@

Write-Output $actionsScript | Out-File -FilePath $serviceScriptPath

# Get the current time and format for the time trigger start boundary
$currentTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"

$xmlContent = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT${tokenCheckPeriodSeconds}S</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>${currentTime}</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-executionpolicy bypass $serviceScriptPath</Arguments>
    </Exec>
  </Actions>
</Task>
"@

Set-Content -Path "File.txt" -Value $xmlContent
# Register the task from the XML string
Write-Host "Creating scheduled task '$taskName' from XML..."
$taskResult = Register-ScheduledTask -Xml $xmlContent -TaskName $taskName -Force

# Was it successful?
if ($null -eq $taskResult) {
  Write-Host "Failed to create scheduled task '$taskName'."
  exit
}
else {
  Write-Host "Scheduled task '$taskName' created successfully."
}

# All done, delete the script file
$scriptPath = $MyInvocation.MyCommand.Path
Remove-Item $scriptPath -Force
Write-Host "Setup script has ended and will be deleted." 
