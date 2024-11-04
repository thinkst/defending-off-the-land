# WinRM Token install script
# (C) 2024 Thinkst Applied Research, PTY
# Author: Jacob Torrey

function Install-WinRMTokenCert {
    # Function that installs the tokened certificate (and private key) into the Local Machine's cert store and shares the key with the NETWORK SERVICE
    param (
        [string]$p12path = "token.p12",
        [string]$rootp12path = "root.p12"
    )

    $p12securestring = ConvertTo-SecureString "password" -AsPlainText -Force
    $certpath = "Cert:\LocalMachine\My"
    $rootpath = "Cert:\LocalMachine\Root"

    # Import the certificate into the local machine cert store
    $c = Import-PfxCertificate -Password $p12securestring -CertStoreLocation $certpath -FilePath $p12path

    # Import the root certificate into the local machine trusted CA
    $c = Import-PfxCertificate -Password $p12securestring -CertStoreLocation $rootpath -FilePath $rootp12path
}

function Remove-WinRMRootCert {
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'Thinkst Root CA' } | Remove-Item
}

function Enable-WinRMTokenServer {
    # This function enables the RDP service via the Windows Registry and opens the RDP port in the firewall ruleset
    winrm qc -q -transport:https
    netsh advfirewall firewall add rule name="winRM HTTPS" dir=in action=allow protocol=TCP localport=5986
}

function Add-WinRMTokenDenyRight {
    # This function puts in a SDDL that denies all users access
    winrm set winrm/config/service '@{RootSDDL = "O:NSG:BAD:P(D;;GA;;;BA)(D;;GAGR;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"}'
}

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write "This script needs to be run with Administrative permissions. Quitting..."
    exit
}

Write "This script will install the WinRM Canarytoken to your system"
Write "It will:"
Write " - Install a tokened certificate into your certificate store"
Write " - Configure the WinRM service to use that certificate for HTTPS connections"
Write " - Disable WinRM logins for all users"
Write " - Enable the WinRM service and open the WinRM HTTPS port on the local firewall"

$ptitle = 'Install WinRM Canarytoken'
$pq = 'Would you like to continue and install the WinRM Canarytoken?'
$pcs = '&Yes','&No'

$continue = $Host.UI.PromptForChoice($ptitle, $pq, $pcs, 1)

if ($continue -eq 1) {
    Write "Exiting without making any changes to the system."
    exit
}

Write "Installing the certificate..."
Install-WinRMTokenCert
Write "Setting the WinRM service to use that certificate"
Write "Disabling WinRM access for all users"
Add-WinRMTokenDenyRight
Write "Enabling WinRM service"
Enable-WinRMTokenServer
Remove-WinRMRootCert