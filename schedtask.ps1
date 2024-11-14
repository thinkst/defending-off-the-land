# Powershell script to configure a scheduled task alerter
# (C) 2024 Thinkst Applied Research
# Author: Jacob Torrey

function Get-SID {
    ((whoami /user) -match "S-" -split " ")[1]
}

function Get-CurrentUser {
    whoami
}

function Enable-SchedTaskEvents {
    auditpol.exe /set /subcategory:"Other Object Access Events" /success:enable
}

function Test-Dir {
    param ([string]$dir)
    (Get-Acl $dir | Select-Object -ExpandProperty Access | Where-Object {($_.identityreference -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -or ($_.identityreference -eq "BUILTIN\Users")} | Select-Object FileSystemRights | Where-Object {($_.FileSystemRights -eq "FullControl") -or ($_.FileSystemRights -contains "Write")}) -ne $null
}

function Extract-Dir {
    param ([string] $str)
    if ($str -match '((?:[a-zA-Z]:\\)(?:[-\u4e00-\u9fa5\w\s.()~!@#$%^&()\[\]{}+=]+\\)*)') {
        return $Matches[0]
    }
    return ''
}

function Get-TaskXML {
    param ([string] $taskname)
    [xml](get-scheduledtask -TaskName $taskname | export-scheduledtask)
}

function Get-Actions {
    param ([xml]$xmls)

    $cmds = $xmls.Task.Actions.Exec.Command
    $wdirs = $xmls.Task.Actions.Exec.WorkingDir
    $args = $xmls.Task.Actions.Exec.Arguments
    $alert = $false
    $foundBad = $suspiciousCommands | ?{$cmds -match $_}
    if ($foundBad.Count -ge 1) {
        Write-Host 'Found bad command(s):' $foundBad
        $alert = $true
    }
    foreach ($c in $cmds) {
        $d = Extract-Dir($c)
        if ($d -ne '') {
            if (Test-Dir($d)) {
                Write-Host $c 'is a writable command'
                $alert = $true
            }
        }
    }
    foreach ($a in $args) {
        $d = Extract-Dir($c)
        if ($d -ne '') {
            if (Test-Dir($d)) {
                Write-Host $c 'is a writable directory in an argument'
                $alert = $true
            }
        }
    }
    return $alert
}

function Install-Task {
    param (
        [string]$tokenUrl,
        [string]$taskName = "Microsoft Auto-Updater"
    )
    $as = $actionScript.Replace("[TOKENURI]", $tokenUrl).Replace('[TASKNAME]', $taskName)
    $xmls = $xmltemplate.Replace("[USERNAME]", (Get-CurrentUser)).Replace("[SID]", (Get-SID)).Replace("[TASKNAME]", $taskName).Replace("[ACTIONSCRIPT]", $as)

    Register-ScheduledTask -TaskName $taskName -Xml $xmls
    #Set-Content -Path 'scheduledtask.xml' -Value $xmls
    #schtasks.exe /Create /XML 'scheduledtask.xml' /tn $taskName
    #Remove-Item -Path 'scheduledtask.xml'
}

$actionScript = @'
$tn = '$(TaskName)'.SubString(1)
$suspiciousCommands = @('powershell.exe', 'cmd.exe', '.bat')
function Test-Dir {
    param ([string]$dir)
    (Get-Acl $dir | Select-Object -ExpandProperty Access | Where-Object {($_.identityreference -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -or ($_.identityreference -eq 'BUILTIN\Users')} | Select-Object FileSystemRights | Where-Object {($_.FileSystemRights -eq 'FullControl') -or ($_.FileSystemRights -contains 'Write')}) -ne $null
}

function Extract-Dir {
    param ([string] $str)
    if ($str -match '((?:[a-zA-Z]:\\)(?:[-\u4e00-\u9fa5\w\s.()~!@#$%^()\[\]{}+=]+\\)*)') {
        return $Matches[0]
    }
    return ''
}

function Get-TaskXML {
    param ([string] $taskname)
    [xml](get-scheduledtask -TaskName $taskname | export-scheduledtask)
}

function Get-Actions {
    param ([xml]$xmls)

    $cmds = $xmls.Task.Actions.Exec.Command
    $wdirs = $xmls.Task.Actions.Exec.WorkingDir
    $args = $xmls.Task.Actions.Exec.Arguments
    $alert = $false
    $foundBad = $suspiciousCommands | ?{$cmds -match $_}
    if ($foundBad.Count -ge 1) {
        #Write-Host 'Found bad command(s):' $foundBad
        $alert = $true
    }
    foreach ($c in $cmds) {
        $d = Extract-Dir($c)
        if ($d -ne '') {
            if (Test-Dir($d)) {
                $alert = $true
                #Write-Host $c 'is a writable command'
            }
        }
    }
    foreach ($a in $args) {
        $d = Extract-Dir($c)
        if ($d -ne '') {
            if (Test-Dir($d)) {
                $alert = $true
                #Write-Host $c 'is a writable directory in an argument'
            }
        }
    }
    return $alert
}
if ($tn -eq '[TASKNAME]') {
    Exit 0
}
if (Get-Actions -Xmls (Get-TaskXML $tn)) {
    Invoke-WebRequest -Uri '[TOKENURI]' -UserAgent $tn
}
'@

$xmltemplate = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-11-13T10:46:06.1899236</Date>
    <Author>[USERNAME]</Author>
    <URI>\[TASKNAME]</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4698]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <ValueQueries>
        <Value name="TaskName">Event/EventData/Data[@Name="TaskName"]</Value>
      </ValueQueries>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>[SID]</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-Command "[ACTIONSCRIPT]"</Arguments>
    </Exec>
  </Actions>
</Task>
'@

if ($args.Count -lt 1) {
    Write-Host "Usage: schedtask.ps1 <TOKENURL> <TASKNAME>"
} else {
    $turl = $args[0]
    Enable-SchedTaskEvents
    if ($args.Count -eq 2) {
        $tn = $args[1]
        Install-Task $turl $tn
    } else {
        Install-Task $turl
    }
}