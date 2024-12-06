# Define variables for the VM name, key, and data
$vmName = "OpenCanary"
$vmNetwork = "CanaryNetwork"
$vmSwitch = "Canary"
$vmNetworkAddress = "172.16.10.0"
$vmIp = "172.16.10.101"
$vmNetmask = "24"
$vmIpAndNetmask = "$vmIp/$vmNetmask"
$vmGw = "172.16.10.254"
$vmDns = "8.8.8.8"
$canarySettings = '{
    "ssh.enabled": true,
    "ftp.enabled": true,
    "portscan.enabled": true,
    "redis.enabled": true,
    "mysql.enabled": true,
    "mssql.enabled": true,
    "telnet.enabled": true,
    "vnc.enabled": true
}'
$portMapping = @{
    21 = 21
    22 = 22
    23 = 23
    6379 = 6379
    5000 = 5000
    3306 = 3306
    1433 = 1433
}

$eventSource = "OpenCanary"

function AddKvpItem {
    [cmdletbinding()]
    Param (
        [string]
        $vmName,
        [string]
        $keyName,
        [string]
        $keyData
    )
    $vmMgmt = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='$vmName'"

    $kvpDataItem = ([WMIClass][String]::Format("\\{0}\{1}:{2}", `
        $vmMgmt.ClassPath.Server, `
        $vmMgmt.ClassPath.NamespacePath, `
        "Msvm_KvpExchangeDataItem")).CreateInstance()

    $kvpDataItem.Name = $keyName
    $kvpDataItem.Data = $keyData
    $kvpDataItem.Source = 0  # Source 0 indicates that the data is from the host to the guest

    $vmMgmt.AddKvpItems($vm, $kvpDataItem.PSBase.GetText(1)) > $null

    Write-Output "Key Name: $($kvpDataItem.Name)"
    Write-Output "Key Data: $($kvpDataItem.Data)"
}

function ViewKvpItem {
    [cmdletbinding()]
    Param (
        [string]
        $vmName,
        [string]
        $keyName
    )
    $VmMgmt = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='$vmName'"
    ($vm.GetRelated("Msvm_KvpExchangeComponent")[0]).GetRelated("Msvm_KvpExchangeComponentSettingData").HostExchangeItems | % { `
            $GuestExchangeItemXml = ([XML]$_).SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$keyName']")
            if ($GuestExchangeItemXml -ne $null) {
                $GuestExchangeItemXml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value
            }
    }
}

function ModifyKvpItem {
    [cmdletbinding()]
    Param (
        [string]
        $vmName,
        [string]
        $keyName,
        [string]
        $keyData
    )
    $VmMgmt = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='$vmName'"
    $kvpDataItem = ([WMIClass][String]::Format("\\{0}\{1}:{2}", $VmMgmt.ClassPath.Server, $VmMgmt.ClassPath.NamespacePath, "Msvm_KvpExchangeDataItem")).CreateInstance()

    $kvpDataItem.Name = "$keyName"
    $kvpDataItem.Data = "$keyData"
    $kvpDataItem.Source = 0

    $VmMgmt.ModifyKvpItems($Vm, $kvpDataItem.PSBase.GetText(1)) > $null
    Write-Output "Key Name: $($kvpDataItem.Name)"
    Write-Output "Key Data: $($kvpDataItem.Data)"
}

function DeleteKvpItem {
    [cmdletbinding()]
    Param (
        [string]
        $vmName,
        [string]
        $keyName
    )
    $VmMgmt = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='$vmName'"
    $kvpDataItem = ([WMIClass][String]::Format("\\{0}\{1}:{2}", $VmMgmt.ClassPath.Server, $VmMgmt.ClassPath.NamespacePath, "Msvm_KvpExchangeDataItem")).CreateInstance()

    $kvpDataItem.Name = "$keyName"

    $kvpDataItem.Data = [String]::Empty
    $kvpDataItem.Source = 0

    $VmMgmt.RemoveKvpItems($Vm, $kvpDataItem.PSBase.GetText(1)) > $null
    #Write-Output "Removed Key Name: $($kvpDataItem.Name)"
}

function SetupVM {
    $vm = Get-VM -Name "$vmName" -ErrorAction SilentlyContinue
    if ($vm -eq $null) {
        $vmPath = "$pwd\OpenCanary\Virtual Machines\2C87EBD1-C30B-4296-AB07-2ED9B321E946.vmcx"
        if (-not (Test-Path -Path $vmPath)) {
            Write-Error "The OpenCanary Virtual machine must be downloaded into this directory first."
            Write-Error "Run: wget -OutFile opencanary.zip https://opencanary-hyperv-image.s3.eu-west-1.amazonaws.com/opencanary.zip; Expand-Archive opencanary.zip -DestinationPath .\"
            exit 1
        }
        Write-Output "Importing the $vmName VM into Hyper-V"
        Import-VM -Path $vmPath -Copy -GenerateNewId
    }
}

function StartVM {
    $vm = Get-VM -Name "$vmName" -ErrorAction SilentlyContinue
    if ($vm.State -eq "Off") {
        Write-Output "Starting the $vmName VM"
        Start-VM -Name "$vmName"
    }
}

function StartOC {
    Write-Output "Starting the OpenCanary daemon in the VM"
    $vm = Get-VM -Name "$vmName" -ErrorAction SilentlyContinue
    if ($vm.State -eq "Running") {
        Enable-VMIntegrationService -VMName "$vmName" -Name "Guest Service Interface"
        $fileCopied = $false
        while (-not $fileCopied){
            try {
                Copy-VMFile -Name "$vmName" -SourcePath '.\oc_manager.py' -DestinationPath '/root' -FileSource Host -Force -ErrorAction Stop
                $fileCopied = $true
            } catch {
                Write-Output "Waiting for VM"
                Start-Sleep -Seconds 2
            }
        }
        
    } else {
        Write-Error "The VM $vmName is not running."
        exit 1
    }
}

function WriteNetworkInfo {
    Write-Output "Configuring the guest's network settings"
    $networkInfo = "$vmIpAndNetmask,$vmGw,$vmDns"
    DeleteKvpItem "$vmName" "NetworkInfo" 
    AddKvpItem "$vmName" "NetworkInfo" "$networkInfo"
}

function WriteCanarySettings {
    Write-Output "Configuring the guest's Canary settings"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canarySettings)
    $canarySettingsb64 = [Convert]::ToBase64String($bytes)
    DeleteKvpItem "$vmName" "CanarySettings"
    AddKvpItem "$vmName" "CanarySettings" "$canarySettingsb64"
}

function Get-Alert {
    [cmdletbinding()]
    Param (
        [string]
        $vmName,
        [int]
        $alertNumber
    )
    $filter = "ElementName='$vmName'"
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter $filter
    $GuestExchangeItems = $vm.GetRelated("Msvm_KvpExchangeComponent").GuestExchangeItems
    if ($GuestExchangeItems -ne $null) {
        $GuestExchangeItems | % {  $GuestExchangeItemXml = ([XML]$_).SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = 'opencanary-alert-$alertNumber']")
            if ($GuestExchangeItemXml -ne $null)
            {
                return $GuestExchangeItemXml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value
            }
        }
    }
}

function Get-Alert-Counter {
    [cmdletbinding()]
    Param (
        [string]
        $vmName
    )
    $filter = "ElementName='$vmName'"
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter $filter
    $GuestExchangeItems = $vm.GetRelated("Msvm_KvpExchangeComponent").GuestExchangeItems
    if ($GuestExchangeItems -ne $null) {
        $GuestExchangeItems | % {  $GuestExchangeItemXml = ([XML]$_).SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = 'opencanary-alerts']") 
            if ($GuestExchangeItemXml -ne $null)
            {
                return $GuestExchangeItemXml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value
            }
        }
    }
}

# Inspired by https://den.dev/blog/powershell-windows-notification/
function Show-Notification {
    [cmdletbinding()]
    Param (
        [string]
        $ToastTitle,
        [string]
        [parameter(ValueFromPipeline)]
        $ToastText
    )

    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastImageAndText02)

    $RawXml = [xml] $Template.GetXml()
    ($RawXml.toast.visual.binding.text|where {$_.id -eq "1"}).AppendChild($RawXml.CreateTextNode($ToastTitle)) > $null
    ($RawXml.toast.visual.binding.text|where {$_.id -eq "2"}).AppendChild($RawXml.CreateTextNode($ToastText)) > $null
    ($RawXml.toast.visual.binding.image|where {$_.id -eq "1"}).SetAttribute("src", "$pwd\oc.png") > $null

    $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $SerializedXml.LoadXml($RawXml.OuterXml)

    $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
    $Toast.Tag = $eventSource
    $Toast.Group = $eventSource
    $Toast.ExpirationTime = [DateTimeOffset]::Now.AddMinutes(1)

    $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($eventSource)
    $Notifier.Show($Toast);
}

function Forward-Port-To-Canary {
    [cmdletbinding()]
    Param(
        [string]
        $vmName,
        [string]
        $networkName,
        [string]
        $canaryIp,
        [int]
        $externalPort,
        [int]
        $vmPort
    )
    Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort  $externalPort -Protocol TCP -InternalIPAddress "$canaryIp" -InternalPort $vmPort -NatName "$networkName" > $null
}

function InstallNetNat {
    Write-Output "Configuring NAT for the VM"
    $natNetwork = Get-Command -Name Get-NetNat -ErrorAction SilentlyContinue
    if (-not $natNetwork) {
        Write-Error "NAT network commands are not available. Ensure the 'NetNat' module is installed."
        exit 1
    }
    $existingSwitch = Get-VMSwitch | Where-Object { $_.Name -eq $vmSwitch }
    if ($null -eq $existingSwitch) {
        Write-Output "The Hyper-V Virtual switch '$vmSwitch' does not exist. Creating it now..."
        New-VMSwitch  -SwitchName $vmSwitch  -SwitchType Internal
    }
    if ( (Get-VMNetworkAdapter -VMName OpenCanary).SwitchName -ne $vmSwitch ) {
        Write-Output "The VM is connected to another virtual switch. I'm changing that to $vmSwitch for you..."
        Connect-VMNetworkAdapter -VMName $vmName -SwitchName $vmSwitch
        Write-Output "Done."
    }
    $existingNetwork = Get-NetNat | Where-Object { $_.Name -eq $vmNetwork }
    if ($null -eq $existingNetwork) {
        Write-Output "The NAT network '$NetworkName' does not exist. Creating it now..."
        New-NetIPAddress  -IPAddress $vmGw  -PrefixLength $vmNetmask  -InterfaceAlias "vEthernet ($vmSwitch)"
        New-NetNat  -Name $vmNetwork -InternalIPInterfaceAddressPrefix "$vmNetworkAddress/$vmNetmask"
    }
}

function ClearPortForwarding {
    if ((Get-NetNatStaticMapping -NatName "CanaryNetwork" -ErrorAction SilentlyContinue) -ne $null) {
        Remove-NetNatStaticMapping -NatName "$vmNetwork" -Confirm:$false
    }
}

function InstallPortForwarding {
    Write-Output "Configuring the port fowarding rules"
    ClearPortForwarding
    foreach ($port in $portMapping.Keys) {
        Forward-Port-To-Canary "$vmName" "$vmNetwork" "$vmIp" $port $($portMapping[$port])
    }
}

function SetupEventLog {
    if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
        Write-Output "Creating an Event source called $eventSource"
        [System.Diagnostics.EventLog]::CreateEventSource($eventSource, "Application")
    }
}

function WatchOpenCanary {
    Write-Output "Waiting for OpenCanary alerts"
    $LastAlert=0
    while ($true) {
        # Write-Output "Looped"
        $CurrentCounter = Get-Alert-Counter "$vmName"
        if (($CurrentCounter -ne $null) -and ($CurrentCounter -ne $LastAlert)) {
            for ($i = $LastAlert + 1; $i -le $CurrentCounter; $i++) {
                $AlertData = Get-Alert "$vmName" "$i"
                if ($AlertData -ne $null ) {
                    $AlertObject = $AlertData | ConvertFrom-Json
                    Show-Notification $AlertObject.Header $AlertObject.Body
                    $Message = $AlertObject.Header
                    $Message += "`n`n"
                    $Message += $AlertObject.Body
                    Write-EventLog -LogName "Application" -Source "$eventSource" -EventID 1 -EntryType Information -Message "$Message" -Category 4
                    Write-Output "$AlertObject"
                    $LastAlert = $i
                }
            }
        }
        Start-Sleep -Seconds 5
    }
}

InstallNetNat
SetupVM
SetupEventLog
WriteNetworkInfo
WriteCanarySettings
StartVM
StartOC
InstallPortForwarding
WatchOpenCanary
