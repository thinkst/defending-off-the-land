# Unconstrained Kerberos Delegation Canary
# (C) 2025 Thinkst Applied Research

# To be run as a Domain Administrator
# THIS SCRIPT CAN ADD RISK TO YOUR NETWORK!

# This script will:
# - Create a Ghost Server AD object (though we suggest not naming it Ghost Server 😛) named $GhostServerName
# - Configure the Ghost Server’s AD object to support Unconstrained Delegation and restrict its ACLs to writable only by Domain Admins (same permissions as the DC machine object)
# - Point the Ghost Server’s DNS at an IP or machine (CNAME) of your choosing (i.e., the domain-joined honeypot–we recommend Canary 👍)
# - Add SPN records for the Ghost Server and associated network services to the machine account of the honeypot


function New-KerberosDelegationCanary
{
    param
    (
        [parameter(Mandatory=$false)][String]$GhostServerName,
        [parameter(Mandatory=$false)][String]$GhostServerDomain,
        [parameter(Mandatory=$false)][String]$CanaryName,
        [parameter(Mandatory=$true)][String]$CanaryIP
        )

        # Import System.Web assembly
Add-Type -AssemblyName System.Web
# Generate random password
$machinePassword = [System.Web.Security.Membership]::GeneratePassword(128,32)

$machine_account_password = ConvertTo-SecureString $machinePassword -AsPlainText -Force
New-MachineAccount -MachineAccount $GhostServerName -Password $machine_account_password

## Set DNS Records

Add-DnsServerResourceRecordA -Name $GhostServerName -ZoneName $GhostServerDomain -AllowUpdateAny -IPv4Address $CanaryIP -TimeToLive 01:00:00
 
## Set SPN - 
## PowerShell or setspn.exe

Set-ADComputer $CanaryName -ServicePrincipalNames @{Add="HTTP/$GhostServerName","HTTP/$GhostServerName.$GhostServerDomain"}


## Set Unconstrined on Ghost Server
## https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/configure-kerberos-delegation-group-managed-service-accounts


Set-ADAccountControl -Identity $GhostserverName$ -TrustedForDelegation $true -TrustedToAuthForDelegation $false


}


function New-MachineAccount
{
    <#
    .SYNOPSIS
    This function adds a machine account with a specified password to Active Directory through an encrypted LDAP
    add request. By default standard domain users can add up to 10 systems to AD (see ms-DS-MachineAccountQuota).

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    The main purpose of this function is to leverage the default ms-DS-MachineAccountQuota attribute setting which
    allows all domain users to add up to 10 computers to a domain. The machine account and HOST SPNs are added
    directly through an LDAP connection to a domain controller and not by attaching the host system to Active
    Directory. This function does not modify the domain attachment and machine account associated with the host
    system.

    Note that you will not be able to remove the account without elevating privilege. You can however disable the
    account as long as you maintain access to the account used to create the machine account.

    .PARAMETER Credential
    PSCredential object that will be used to create the machine account.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER MachineAccount
    The machine account that will be added.

    .PARAMETER Password
    The securestring of the password for the machine account.

    .EXAMPLE
    Add a machine account named test.
    New-MachineAccount -MachineAccount test

    .EXAMPLE
    Add a machine account named test with a password of Summer2018!.
    $machine_account_password = ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force
    New-MachineAccount -MachineAccount test -Password $machine_account_password

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter a password for the new machine account" -AsSecureString
    }

    $password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $password_cleartext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($password_BSTR)

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }
    
    $Domain = $Domain.ToLower()
    $machine_account = $MachineAccount

    if($MachineAccount.EndsWith('$'))
    {
        $sam_account = $machine_account
        $machine_account = $machine_account.SubString(0,$machine_account.Length - 1)
    }
    else 
    {
        $sam_account = $machine_account + "$"
    }

    Write-Verbose "[+] SAMAccountName = $sam_account" 

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    $password_cleartext = [System.Text.Encoding]::Unicode.GetBytes('"' + $password_cleartext + '"')
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)

    if($Credential)
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier,$Credential.GetNetworkCredential())
    }
    else
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    }
    
    $connection.SessionOptions.Sealing = $true
    $connection.SessionOptions.Signing = $true
    $connection.Bind()
    $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
    $request.DistinguishedName = $distinguished_name
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass","Computer")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "SamAccountName",$sam_account)) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "userAccountControl","4096")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "DnsHostName","$machine_account.$Domain")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "ServicePrincipalName","HOST/$machine_account.$Domain",
        "RestrictedKrbHost/$machine_account.$Domain","HOST/$machine_account","RestrictedKrbHost/$machine_account")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "unicodePwd",$password_cleartext)) > $null
    Remove-Variable password_cleartext

    try
    {
        $connection.SendRequest($request) > $null
        Write-Output "[+] Machine account $MachineAccount added"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"

        if($error_message -like '*Exception calling "SendRequest" with "1" argument(s): "The server cannot handle directory requests."*')
        {
            Write-Output "[!] User may have reached ms-DS-MachineAccountQuota limit"
        }

    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

 
