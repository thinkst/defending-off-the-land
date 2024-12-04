param ($install = $false)

$ErrorActionPreference = "stop"
$savefile = "regmon.json"
$sensitivekeys = (Get-Content keys.json | ConvertFrom-Json)

# If you want canarytokens.org alerting, replace the following with a web bug token URL
$token_url = 'none'

function Show-BalloonNotification {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Title,
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    $Duration = 4000
    # Load required assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    # Create NotifyIcon object
    $balloon = New-Object System.Windows.Forms.NotifyIcon
    $balloon.Icon = [System.Drawing.SystemIcons]::Warning
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning

    # Configure notification
    $balloon.BalloonTipTitle = $Title
    $balloon.BalloonTipText = $Message
    $balloon.Visible = $true
    
    # Show notification
    $balloon.ShowBalloonTip($Duration)
    
    # Clean up after duration
    Start-Sleep -Milliseconds $Duration
    $balloon.Dispose()
}

function Get-RegKeyValue {
    param ([string]$key)
    $leaf = ($key -split "\\")[-1]

    $path = "Registry::" + $key.substring(0, $key.length - $leaf.length)
    try {
        $out = (Get-ItemProperty -Path $path -Name $leaf).$leaf
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        $out = $null
    }
    catch [System.Security.SecurityException] {
        Write-Host "Unable to check" $key "due to permissions!"
        $out = $null
    }
    return $out
}

function Save-State {
    param ($data, [string]$filename)
    $data | ConvertTo-Json | Set-Content -Path $filename
}

function Load-SaveState {
    param ([string]$filename)
    $res = @{}
    (Get-Content -Path $filename | ConvertFrom-Json).psobject.properties | Foreach { $res[$_.Name] = $_.Value }
    return $res
}

function Get-Keys {
    param($keys)
    $state = @{}
    foreach ($key in $keys) {
        $v = Get-RegKeyValue $key
        $state.add($key, $v)
    }
    return $state
}

function Install-Task {
    param ([int]$period = 30)
    $self = $MyInvocation.PSCommandPath
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ("-ep bypass -windowstyle hidden -File " + $self) -WorkingDirectory $MyInvocation.PSScriptRoot 
    $trigger = New-ScheduledTaskTrigger -At ((Get-Date) + (New-TimeSpan -Minutes 1)) -Once -RepetitionInterval (New-TimeSpan -Minutes $period)
    $settings = New-ScheduledTaskSettingsSet -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings
    Register-ScheduledTask "RegistryMonitor" -InputObject $task
}

function Do-Alerting {
    param ($keys)
    $message = "The following sensitive keys have changed:`n" +  ($keys -join("`n"))
    Show-BalloonNotification -Title ([string]$keys.Count  + ' Registry changes detected!') -Message $message

    if ($token_url -ne 'none') {
        # Alert to the token URL as well
        $headers = @{}
        $i = 1
        foreach ($key in $keys) {
            $headers.add('regKey' + $i, $key)
            $i++
        }
        Invoke-WebRequest -Uri $token_url -UserAgent 'RegistryMonitor' -Headers $headers -SkipHeaderValidation
    }
}

function Get-KeyChanges {
    param($oldstate)
    $allgood = 1
    $currentstate = Get-Keys $oldstate.keys
    $changes = @()
    foreach($k in $currentstate.keys) {
        if ((Compare-Object -ReferenceObject @($currentstate[$k] | Select-Object) -DifferenceObject @($oldstate[$k] | Select-Object)) -ne $null) {
            Write-Host "Change detected in" $k "(from" $oldstate[$k] "to" $currentstate[$k]")!!!"
            $allgood = $false
            $changes += $k
        }
    }
    if ($allgood) {
        Write-Host "No changes detected!"
    } else {
        Write-Host "Some changes detected!"
        Do-Alerting $changes
    }
    return $currentstate
}

if ($install) {
    # Create a scheduled task to run periodically
    $cs = Get-Keys $sensitivekeys
    Save-State -data $cs -filename $savefile
    Install-Task
} else {
    if (Test-Path -Path $savefile -PathType leaf) {
        $olds = Load-SaveState -filename $savefile
        $cs = Get-KeyChanges -oldstate $olds
        Save-State -data $cs -filename $savefile
    } else {
        Write-Host "First run, establishing baseline..."
        $cs = Get-Keys $sensitivekeys
        Save-State -data $cs -filename $savefile
    }
}