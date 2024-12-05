<#
    .SYNOPSIS
        Get Local User Account rights from the Local Security Policy
    
    .DESCRIPTION
        This script will gather the local security policy User Rights from the local, or a remote machine.
    
    .PARAMETER ComputerName
        Comma separated list of servers you want to run this script against. To run locally, run without this switch.
    
    .PARAMETER FileOutputPath
        Location to store the Output File. Set the Type (CSV or Text) with FileOutputType
    
    .PARAMETER FileOutputType
        Set the type of file you would like to output as. Combine with the OutputPath parameter.
    
    .PARAMETER PassThru
        Output as an object that you can manipulate / access.
    
    .EXAMPLE
        Usage:
        Get Local User Account Rights and output to text in console:
        PS C:\> .\Get-UserRights.ps1
        
        Get Remote Server User Account Rights:
        PS C:\> .\Get-UserRights.ps1 -ComputerName SQL.contoso.com
        
        Get Local Machine and Multiple Server User Account Rights:
        PS C:\> .\Get-UserRights.ps1 -ComputerName $env:COMPUTERNAME, SQL.contoso.com
        
        Output to CSV in 'C:\Temp':
        PS C:\> .\Get-UserRights.ps1 -FileOutputPath C:\Temp -FileOutputType CSV
        
        Output to Text in 'C:\Temp':
        PS C:\> .\Get-UserRights.ps1 -FileOutputPath C:\Temp -FileOutputType Text
        Pass thru object:
        PS C:\> .\Get-UserRights.ps1 -ComputerName SQL.contoso.com -PassThru | Where {$_.Principal -match "Administrator"}
    
    .NOTES
        This script is located in the following GitHub Repository: https://github.com/blakedrumm/SCOM-Scripts-and-SQL
        Exact location: https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/General%20Functions/Get-UserRights.ps1
        
        Blog post: https://blakedrumm.com/blog/set-and-check-user-rights-assignment/
        
        Author: Blake Drumm (blakedrumm@microsoft.com)
        First Created on: June 10th, 2021
        Last Modified on: August 15th, 2022
#>
[CmdletBinding()]
[OutputType([string])]
param
(
	[Parameter(ValueFromPipeline = $true,
			   Position = 0,
			   HelpMessage = '(Server1, Server2) Comma separated list of servers you want to run this script against. To run locally, run without this switch. This argument accepts values from the pipeline.')]
	[Alias('servers')]
	[array]$ComputerName,
	[Parameter(Position = 1,
			   HelpMessage = '(ex. C:\Temp) Location to store the Output File. Set the Type with FileOutputType')]
	[string]$FileOutputPath,
	[Parameter(Position = 2,
			   HelpMessage = '(CSV or Text) Set the type of file you would like to output as. Combine with the OutputPath parameter.')]
	[ValidateSet('CSV', 'Text', '')]
	[string]$FileOutputType,
	[Parameter(Position = 3,
			   HelpMessage = 'Output as an object that you can manipulate / access.')]
	[switch]$PassThru
)
BEGIN
{
	#region Initialization
	if (!$PassThru)
	{
		Write-Host @"
===================================================================
==========================  Start of Script =======================
===================================================================
"@
	}
	$checkingpermission = "Checking for elevated permissions..."
	$scriptout += $checkingpermission
	if (!$PassThru)
	{
		Write-Host $checkingpermission
	}
	if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		$currentPath = $myinvocation.mycommand.definition
		$nopermission = "Insufficient permissions to run this script. Attempting to open the PowerShell script ($currentPath) as administrator."
		$scriptout += $nopermission
		Write-Warning $nopermission
		# We are not running "as Administrator" - so relaunch as administrator
		# ($MyInvocation.Line -split '\.ps1[\s\''\"]\s*', 2)[-1]
		Start-Process powershell.exe "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
		break
	}
	else
	{
		$permissiongranted = " Currently running as administrator - proceeding with script execution..."
		if (!$PassThru)
		{
			Write-Host $permissiongranted
		}
	}
	Function Time-Stamp
	{
		$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
		return "$TimeStamp - "
	}
	if (!$PassThru)
	{
		Write-Output "$(Time-Stamp)Starting main script execution."
	}
	#endregion Initialization
}
PROCESS
{
	#region MainFunctionSection
	function Get-UserRights
	{
		param
		(
			[Parameter(ValueFromPipeline = $true,
					   Position = 0,
					   HelpMessage = '(Server1, Server2) Comma separated list of servers you want to run this script against. To run locally, run without this switch. This argument accepts values from the pipeline.')]
			[Alias('servers')]
			[array]$ComputerName,
			[Parameter(Position = 1,
					   HelpMessage = '(ex. C:\Temp) Location to store the Output File. Set the Type with FileOutputType')]
			[string]$FileOutputPath,
			[Parameter(Mandatory = $false,
					   Position = 2,
					   HelpMessage = '(CSV or Text) Set the type of file you would like to output as. Combine with the OutputPath parameter.')]
			[ValidateSet('CSV', 'Text', '')]
			[string]$FileOutputType,
			[Parameter(Position = 3,
					   HelpMessage = 'Output as an object that you can manipulate / access.')]
			[switch]$PassThru
		)
		if (!$ComputerName)
		{
			$ComputerName = $env:COMPUTERNAME
		}
		[array]$localrights = $null
		foreach ($ComputerName in $ComputerName)
		{
			if (!$PassThru)
			{
				Write-Output "$(Time-Stamp)Gathering current User Account Rights on: $ComputerName"
			}
			#region Non-LocalMachine
			if ($ComputerName -notmatch $env:COMPUTERNAME)
			{
				$localrights += Invoke-Command -ScriptBlock {
					param ([int]$VerbosePreference)
					function Get-SecurityPolicy
					{
						#requires -version 2
						# Fail script if we can't find SecEdit.exe
						$SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
						if (-not (Test-Path $SecEdit))
						{
							Write-Error "File not found - '$SecEdit'" -Category ObjectNotFound
							return
						}
						Write-Verbose "Found Executable: $SecEdit"
						# LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display
						# names, so use this hashtable
						$UserLogonRights = @{
							"SeBatchLogonRight"				    = "Log on as a batch job"
							"SeDenyBatchLogonRight"			    = "Deny log on as a batch job"
							"SeDenyInteractiveLogonRight"	    = "Deny log on locally"
							"SeDenyNetworkLogonRight"		    = "Deny access to this computer from the network"
							"SeDenyRemoteInteractiveLogonRight" = "Deny log on through Remote Desktop Services"
							"SeDenyServiceLogonRight"		    = "Deny log on as a service"
							"SeInteractiveLogonRight"		    = "Allow log on locally"
							"SeNetworkLogonRight"			    = "Access this computer from the network"
							"SeRemoteInteractiveLogonRight"	    = "Allow log on through Remote Desktop Services"
							"SeServiceLogonRight"			    = "Log on as a service"
						}
						# Create type to invoke LookupPrivilegeDisplayName Win32 API
						$Win32APISignature = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeDisplayName(
  string systemName,
  string privilegeName,
  System.Text.StringBuilder displayName,
  ref uint cbDisplayName,
  out uint languageId
);
'@
						$AdvApi32 = Add-Type advapi32 $Win32APISignature -Namespace LookupPrivilegeDisplayName -PassThru
						# Use LookupPrivilegeDisplayName Win32 API to get display name of privilege
						# (except for user logon rights)
						function Get-PrivilegeDisplayName
						{
							param (
								[String]$name
							)
							$displayNameSB = New-Object System.Text.StringBuilder 1024
							$languageId = 0
							$ok = $AdvApi32::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref]$displayNameSB.Capacity, [Ref]$languageId)
							if ($ok)
							{
								$displayNameSB.ToString()
							}
							else
							{
								# Doesn't lookup logon rights, so use hashtable for that
								if ($UserLogonRights[$name])
								{
									$UserLogonRights[$name]
								}
								else
								{
									$name
								}
							}
						}
						# Outputs list of hashtables as a PSObject
						function Out-Object
						{
							param (
								[System.Collections.Hashtable[]]$hashData
							)
							$order = @()
							$result = @{ }
							$hashData | ForEach-Object {
								$order += ($_.Keys -as [Array])[0]
								$result += $_
							}
							$out = New-Object PSObject -Property $result | Select-Object $order
							return $out
						}
						# Translates a SID in the form *S-1-5-... to its account name;
						function Get-AccountName
						{
							param (
								[String]$principal
							)
							try
							{
								$sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
								$sid.Translate([Security.Principal.NTAccount])
							}
							catch { $principal }
						}
						$TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
						$LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
						$StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename
						Write-Verbose "$StdOut"
						if ($LASTEXITCODE -eq 0)
						{
							$dtable = $null
							$dtable = New-Object System.Data.DataTable
							$dtable.Columns.Add("Privilege", "System.String") | Out-Null
							$dtable.Columns.Add("PrivilegeName", "System.String") | Out-Null
							$dtable.Columns.Add("Principal", "System.String") | Out-Null
							$dtable.Columns.Add("ComputerName", "System.String") | Out-Null
							Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Foreach-Object {
								$Privilege = $_.Matches[0].Groups[1].Value
								$Principals = $_.Matches[0].Groups[2].Value -split ','
								foreach ($Principal in $Principals)
								{
									$nRow = $dtable.NewRow()
									$nRow.Privilege = $Privilege
									$nRow.PrivilegeName = Get-PrivilegeDisplayName $Privilege
									$nRow.Principal = Get-AccountName $Principal
									$nRow.ComputerName = $env:COMPUTERNAME
									$dtable.Rows.Add($nRow)
								}
								return $dtable
							}
						}
						else
						{
							$OFS = ""
							Write-Error "$StdOut"
						}
						Remove-Item $TemplateFilename, $LogFilename -ErrorAction SilentlyContinue
					}
					return Get-SecurityPolicy
				} -ArgumentList $VerbosePreference -computer $ComputerName -HideComputerName | Select-Object * -ExcludeProperty RunspaceID, PSShowComputerName, PSComputerName -Unique
			} #endregion Non-LocalMachine
			else #region LocalMachine
			{
				function Get-SecurityPolicy
				{
					#requires -version 2
					# Fail script if we can't find SecEdit.exe
					$SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
					if (-not (Test-Path $SecEdit))
					{
						Write-Error "File not found - '$SecEdit'" -Category ObjectNotFound
						return
					}
					Write-Verbose "Found Executable: $SecEdit"
					# LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display
					# names, so use this hashtable
					$UserLogonRights = @{
						"SeBatchLogonRight"				    = "Log on as a batch job"
						"SeDenyBatchLogonRight"			    = "Deny log on as a batch job"
						"SeDenyInteractiveLogonRight"	    = "Deny log on locally"
						"SeDenyNetworkLogonRight"		    = "Deny access to this computer from the network"
						"SeDenyRemoteInteractiveLogonRight" = "Deny log on through Remote Desktop Services"
						"SeDenyServiceLogonRight"		    = "Deny log on as a service"
						"SeInteractiveLogonRight"		    = "Allow log on locally"
						"SeNetworkLogonRight"			    = "Access this computer from the network"
						"SeRemoteInteractiveLogonRight"	    = "Allow log on through Remote Desktop Services"
						"SeServiceLogonRight"			    = "Log on as a service"
					}
					# Create type to invoke LookupPrivilegeDisplayName Win32 API
					$Win32APISignature = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeDisplayName(
  string systemName,
  string privilegeName,
  System.Text.StringBuilder displayName,
  ref uint cbDisplayName,
  out uint languageId
);
'@
					$AdvApi32 = Add-Type advapi32 $Win32APISignature -Namespace LookupPrivilegeDisplayName -PassThru
					# Use LookupPrivilegeDisplayName Win32 API to get display name of privilege
					# (except for user logon rights)
					function Get-PrivilegeDisplayName
					{
						param (
							[String]$name
						)
						$displayNameSB = New-Object System.Text.StringBuilder 1024
						$languageId = 0
						$ok = $AdvApi32::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref]$displayNameSB.Capacity, [Ref]$languageId)
						if ($ok)
						{
							$displayNameSB.ToString()
						}
						else
						{
							# Doesn't lookup logon rights, so use hashtable for that
							if ($UserLogonRights[$name])
							{
								$UserLogonRights[$name]
							}
							else
							{
								$name
							}
						}
					}
					# Outputs list of hashtables as a PSObject
					function Out-Object
					{
						param (
							[System.Collections.Hashtable[]]$hashData
						)
						$order = @()
						$result = @{ }
						$hashData | ForEach-Object {
							$order += ($_.Keys -as [Array])[0]
							$result += $_
						}
						$out = New-Object PSObject -Property $result | Select-Object $order
						return $out
					}
					# Translates a SID in the form *S-1-5-... to its account name;
					function Get-AccountName
					{
						param (
							[String]$principal
						)
						try
						{
							$sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
							$sid.Translate([Security.Principal.NTAccount])
						}
						catch { $principal }
					}
					$TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
					$LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
					$StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename
					Write-Verbose "$StdOut"
					if ($LASTEXITCODE -eq 0)
					{
						$dtable = $null
						$dtable = New-Object System.Data.DataTable
						$dtable.Columns.Add("Privilege", "System.String") | Out-Null
						$dtable.Columns.Add("PrivilegeName", "System.String") | Out-Null
						$dtable.Columns.Add("Principal", "System.String") | Out-Null
						$dtable.Columns.Add("ComputerName", "System.String") | Out-Null
						Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Foreach-Object {
							$Privilege = $_.Matches[0].Groups[1].Value
							$Principals = $_.Matches[0].Groups[2].Value -split ','
							foreach ($Principal in $Principals)
							{
								$nRow = $dtable.NewRow()
								$nRow.Privilege = $Privilege
								$nRow.PrivilegeName = Get-PrivilegeDisplayName $Privilege
								$nRow.Principal = Get-AccountName $Principal
								$nRow.ComputerName = $env:COMPUTERNAME
								$dtable.Rows.Add($nRow)
							}
							return $dtable
						}
					}
					else
					{
						$OFS = ""
						Write-Error "$StdOut"
					}
					Remove-Item $TemplateFilename, $LogFilename -ErrorAction SilentlyContinue
				}
				$localrights += Get-SecurityPolicy
			} #endregion LocalMachine
			$output += $localrights
			if (!$PassThru)
			{
				Write-Output "$(Time-Stamp)Gathering for $ComputerName completed."
			}
		}
		if (!$PassThru)
		{
			Write-Output "$(Time-Stamp)Main script execution completed!"
		}
		$output = $output | Select-Object Privilege, PrivilegeName, Principal, ComputerName -Unique | Sort-Object Privilege, ComputerName
		if ($PassThru)
		{
			return $output
		}
		elseif (!$FileOutputPath)
		{
			$output | Format-Table -AutoSize | Out-String -Width 2048
		}
		else
		{
			#region FileOutputType
			if ($FileOutputType -eq 'Text')
			{
				Write-Output "$(Time-Stamp)Writing output to `'$FileOutputPath\UserLogonRights.txt`'."
				$output | Format-Table -AutoSize | Out-String -Width 2048 | Out-File "$FileOutputPath\UserLogonRights.txt" -Force
			}
			elseif ($FileOutputType -eq 'CSV')
			{
				Write-Output "$(Time-Stamp)Writing output to `'$FileOutputPath\UserLogonRights.csv`'."
				$output | Export-CSV $FileOutputPath\UserLogonRights.csv -NoTypeInformation
			}
			else
			{
				Write-Output "Unsupported File Output Type."
			}
			#endregion FileOutputType
		}
	}
	#endregion MainFunctionSection
	if ($FileOutputPath -or $FileOutputType -or $ComputerName -or $PassThru)
	{
		Get-UserRights -FileOutputPath:$FileOutputPath -FileOutputType:$FileOutputType -ComputerName:$ComputerName -PassThru:$PassThru
	}
	else
	{
     <# Edit line 467 to modify the default command run when this script is executed.
       Example for output multiple servers to a text file: 
         Get-UserRights -ComputerName MS01-2019, IIS-2019 -FileOutputPath C:\Temp -FileOutputType Text
       Example for gathering locally:
         Get-UserRights
       #>
		Get-UserRights
	}
}
END
{
	Write-Verbose "$(Time-Stamp)Script Completed!"
}

# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhR0JZ8h2Qz0Rd
# FP++DBymbhTy4yeaI/Eq85nv0wLCBKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPN7PbSgF1cuGGyP7hwfc21P
# ng2apXjGVbhbBGMKB6gTMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB31dkDpaEsSAJTIZonsJ0v4KPwRxTLCHypwvuHSfB2XuVj1UVut+gP
# oMJlY3coAR5DoDPp1E406HhpN1ndOFKVmVEGAKG1M+2mZEBsvcriVFit6Mggcr98
# LYD5sHfvbZOUHDbtadJ3cLyCD4Rrw/FIHvjmLdEUpVdmB37GXIS6mUZCOviQ0kGR
# 6y58vCry2flPGtXyMvhOjT3AbcbVODtlkt2nP0jNN/UcqWYMI7rplr/S8dljGO2o
# zWTgTRK56ulhF/0eIuW6kdP+3mspVH9wYCBAwt8lmhpn6lmYXzbwUbGwhSdon2Ui
# W7DvIyOkcXxgh8E9cZaa5+aWJvKucYBsoYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDFKR2nlckUXMg5smGb/GFl7I+sQGps7xAhCwvSSe/zhAgZjbOxy
# qokYEzIwMjIxMTI5MjAzMDMyLjIzM1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCQkQt
# RTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHGMM0u1tOhwPQAAQAAAcYwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTM0WhcNMjQwMjAyMTkwMTM0WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JCRC1FMzM4LUU5QTExJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDvvSI6vq/geTWbdJmP7UFH+K6h+/5/p5VvsdzbVjHM
# DOujgbqQpcXjtgCwSCtZZPWiC+nQiugWbwJ1FlN/8OVDR9s0072kIDTUonTfMfzY
# KWaT3N72vWM8nVkloyexmYDLtWlj2Y2pf12E++dbX9nFtuIe/urDCDD1TZJPmZ9y
# k+62wj9Cv+AsLppMjdQJjOJU9n9B9qDw1CEqSkdk7cqvmvzdzLuPPg5Y/LkzZaK1
# a/lsknmsFNbnXxA8TMXDOrx7w/vbYJYpkkWM3x60GCwrTmAd4do32SaWlgkkvzi/
# 0mJpfs0UmQ5GECkQVmJQhpmgvEm3ilwEPN/5YP1QCNEoKsCx4n9yTNC86f3lfg63
# hqyc642FwJ1xBZytmjKQWYRqhiSuwPuf/icUUfAkMpRoFhlkvA+Pu7HjxLVh75wx
# xwzF1FKO6gbiuomqkR3qDN/Pbf2/fov4u06VCF8vlydyWE1JZ2YrDVMfJ6Qf3pE2
# 06kgTtz71Oey/VoT2GmF6Ms4nF+xdOTLDQUh2KVzQI/vPNSypoIYXaYVdHAviN9f
# VHJXtAYoR46m8ZmpAosdVlssPfbO1bwt+/33FDbh39MjE70tF64eyfCi2f7wGwKv
# O77/bi85wD1dyl3uQh5bjOZTGEWy/goJ+Koym1mGEwADRKoO6PbdyPXSyZdE4tSe
# FQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFHFf+UeJKEQKnWfaUxrobW4u82CUMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAAvMXvbiNe6ANTjzo8wFhHsJzpoevackOcayeSrBliaNGLbyq/pLUvLvvbPC
# bkMjXz3OABD33GESNbq5iStflSu1W7slRA/psEEEn3xzbwUAg8grd+RA0K/avFGN
# 9AwlJ1zCwl5Mrst3T064DmFjg9YIGAml9jvUtxpfPcVHwA08VfrNwphuBg5mt6C2
# kO5vfg3RCFHvBz8VyZX6Dgjch1MCgwPb9Yjlmx8pPMFSf9TcClSE3Bs6XlhIL5/1
# LUtK1tkvA/MxL58s9clRJ7tJK+yl9Kyv9UR7ShCGZpH7m9yr7swvDzrVYFWFiknt
# MHlgFLk5E71d0htylsEXBwc+ZvyJmpIipb0mmAbvr7k1BQs9XNnvnPlbZHlmLJCS
# 2IekzCNfY47b1nz6dPDa06xUJzDMf0ugQt52/c+NylvA7IuO2bVPhcdh3ept30Ne
# gGM1iRKN2Lfuk2nny76shOW0so6ONAInCPUWme4FjzbkHkLS4L81gRIQqxOJwSOF
# L/i6MFctw0YOFUGXa8cTqpj9hbiTLW9zKm9SuwbzWCm/b7z+KE7CDjBMs7teqKR4
# iJTdlYBQCg6lOXXi151CrFsdMO94lhHc5TTIoHbHB/zsRYIBvQImKaEObJBooS9J
# XR8tb2JXIjTBhwbhXZpU3pOtniav599qoNAP0X4ek+E/SmUDMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjozQkJELUUzMzgtRTlBMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUALTXK5iYhW+yiRJpwmZZ7wy7ZAW2g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOcwduUwIhgPMjAyMjExMjkyMDE3NDFaGA8yMDIyMTEzMDIwMTc0MVow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5zB25QIBADAHAgEAAgIN+TAHAgEAAgIR
# 1DAKAgUA5zHIZQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBACtLkv3nfUlo
# zlZEkQW8zSZ61C7Y/HTNCzisSAu/jhP5IKzTxgvTHLN0MPDMNleofyEX6eTC2dTd
# W+kqqmHmSAckrfFoyxHT/SmkOmfkWPvtVHCpulMOEL/PW6u9jkt0VkLpB1cajfxI
# Wir6wRLHcoQsa5zhyuEtcujR03PBzm+YMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHGMM0u1tOhwPQAAQAAAcYwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgyv2+wXrnyfKaZ2uJ+P1IR6r/CWgBVhsH48ArniKf0q0wgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBWMRNcVcm9mCnGJmqT8HANYDk/HDqF6FQu
# mQWv2uOvLTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABxjDNLtbTocD0AAEAAAHGMCIEIHrbXOJO2hDklVfy03X5RY4OZVKo5h/03iC4
# HvOjzTpvMA0GCSqGSIb3DQEBCwUABIICAGScLLvDYsYFOeMLczGQhGvZdvOoiM3b
# Ly+wDXiRITyEThUTrKB+0xu9kMyMRSKSYOX92eD7sXuX+W2Tq+AjhTaCZh/NYCsZ
# oqZwAViNiUWyO4/95/s+M3sv96d8j+xwPO+ZtjdDxTRqRckiEPn0Dt+ac53ELbZ9
# Yd+gaZJhOIEzi67cQvZu/n3BF+d9YO6Jkh4ySx6zBA3UsFSLCkPHoJDN+mjxYauA
# +qlm1tMq/gjO1qhQy6ZP2nyQj7APhJ67QqiESSP/AeHuT9Yi/vzrEDVDDFu0j2DQ
# OiW3ywS3mKc1mOJx16FbNFTrPc13H4V9iRuPhTsAw+0/QZn6gy6HDYQF+ccxD20T
# iky+a/dA8eS1JaozCRiZ8xoCkHqrrY6SfaU/I+W/wsb+6n65pvtHBr0H88zLc8DO
# 6ild2yhxanKwxxyNEElcLkaC+GRmq+fQq4v4uqtbNEG93Ob4/aFBbMRB0cy3yJtO
# PRIva+2VXINo/Je3mgii0aBqFWWhiTMiZRCWVkxjBQ2xDQWFuseH7g5qEk4gcaEe
# CS2r52c0M95Ji1JXN0e4kSRvxFeoef+VGoCmvfJc2Cz5Nc7pRmgfe2Pswk9hBTpI
# kfyb9N5cRYzdm5MexA7uD39cr/bgb/qBCDWV767MGKKmuaciun2grLoYjwFQNxWT
# Q+BDYBzFXQWd
# SIG # End signature block
