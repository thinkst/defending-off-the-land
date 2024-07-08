# RDP Token install script
# (C) 2024 Thinkst Applied Research, PTY
# Author: Jacob Torrey

function Install-RDPTokenCert {

    param (
        [string]$p12path = "token.p12"
    )

    $p12securestring = ConvertTo-SecureString "password" -AsPlainText -Force
    $certpath = "Cert:\LocalMachine\My"

    # Import the certificate into the local machine cert store
    $c = Import-PfxCertificate -Password $p12securestring -CertStoreLocation $certpath -FilePath $p12path

    $permission = [System.Security.AccessControl.FileSystemAccessRule]::new('NT AUTHORITY\NETWORK SERVICE', 'Read', 'Allow') 
    $cert = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object -FilterScript { $PSItem.FriendlyName -eq 'tokencert' } )
    # This must be a RSA key to work
    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $containerName = ""
    if ($privateKey.GetType().Name -ieq "RSACng")
    {
        $containerName = $privateKey.Key.UniqueName
    }
    else
    {
        $containerName = $privateKey.CspKeyContainerInfo.UniqueKeyContainerName
    }
    $keyfile = Get-ChildItem -Path $env:AllUsersProfile\Microsoft\Crypto -Recurse -Filter $containerName | Select -Expand FullName
    $acl = $keyfile | Get-Acl
    $acl.AddAccessRule($permission)
    $acl | Set-Acl
}

function Enable-RDPTokenServer {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    netsh advfirewall firewall set rule group="remote desktop" new enable=yes
}

function Set-RDPTokenCert {

    param (
        [string]$regfilepath = "token.reg"
    )

    reg import $regfilepath
}

function Get-RDPTokenUsers {
    $users = @()
    foreach ($u in wmic useraccount get Caption | select -skip 1) {
        if ($u -ne "") { $users += $u.Trim() }
    }
    return $users
}

function Add-RDPTokenDenyRight {

    param (
        [string]$username
    )

    .\helper_scripts\Set-UserRights.ps1 -AddRight -Username $username -UserRight SeDenyRemoteInteractiveLogonRight
}

function Refresh-RDPTokenGPO {
    gpupdate /force /target:computer
}

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write "This script needs to be run with Administrative permissions. Quitting..."
    exit
}

Write "This script will install the RDP Canarytoken to your system"
Write "It will:"
Write " - Install a tokened certificate into your certificate store"
Write " - Configure the RDP service to use that certificate for RDP connections"
Write " - Disable RDP logins for all users"
Write " - Enable the RDP service and open the RDP port on the local firewall"

$ptitle = 'Install RDP Canarytoken'
$pq = 'Would you like to continue and install the RDP Canarytoken?'
$pcs = '&Yes','&No'

$continue = $Host.UI.PromptForChoice($ptitle, $pq, $pcs, 1)

if ($continue -eq 1) {
    Write "Exiting without making any changes to the system."
    exit
}

Write "Installing the certificate..."
Install-RDPTokenCert
Write "Setting the RDP service to use that certificate"
Set-RDPTokenCert
Write "Disabling RDP access for all users"
foreach ($u in Get-RDPTokenUsers) {
    Add-RDPTokenDenyRight($u)
}
Refresh-RDPTokenGPO
Write "Enabling RDP service"
Enable-RDPTokenServer
