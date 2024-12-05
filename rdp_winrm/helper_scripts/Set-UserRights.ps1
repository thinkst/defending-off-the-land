<#
	.Synopsis
		Add and Remove User Right(s) for defined user(s) and computer(s).
	
	.DESCRIPTION
		Add and Remove User Rights via Powershell.
	
	.PARAMETER AddRight
		You want to Add a user right.
	
	.Parameter ComputerName
		Defines the name of the computer where the user right should be granted. This can be multiple values, comma seperated.
		Default is the local computer on which the script is run.
	
	.PARAMETER RemoveRight
		You want to Remove a user right.
	
	.Parameter Username
		Defines the Username under which the service should run. This can be multiple values, comma seperated.
		Use the form: domain\Username.
		Default is the user under which the script is run.
	
	.PARAMETER UserRight
		Defines the User Right you want to set. This can be multiple values, comma seperated.
		Name of the right you want to add to: SeServiceLogonRight
		There is no default for this argument
		
		All of the Options you can use:
			Replace a process level token (SeAssignPrimaryTokenPrivilege)
			Generate security audits (SeAuditPrivilege)
			Back up files and directories (SeBackupPrivilege)
			Log on as a batch job (SeBatchLogonRight)
			Bypass traverse checking (SeChangeNotifyPrivilege)
			Create global objects (SeCreateGlobalPrivilege)
			Create a pagefile (SeCreatePagefilePrivilege)
			Create permanent shared objects (SeCreatePermanentPrivilege)
			Create symbolic links (SeCreateSymbolicLinkPrivilege)
			Create a token object (SeCreateTokenPrivilege)
			Debug programs (SeDebugPrivilege)
			Obtain an impersonation token for another user in the same session (SeDelegateSessionUserImpersonatePrivilege)
			Deny log on as a batch job (SeDenyBatchLogonRight)
			Deny log on locally (SeDenyInteractiveLogonRight)
			Deny access to this computer from the network (SeDenyNetworkLogonRight)
			Deny log on through Remote Desktop Services (SeDenyRemoteInteractiveLogonRight)
			Deny log on as a service (SeDenyServiceLogonRight)
			Enable computer and user accounts to be trusted for delegation (SeEnableDelegationPrivilege)
			Impersonate a client after authentication (SeImpersonatePrivilege)
			Increase scheduling priority (SeIncreaseBasePriorityPrivilege)
			Adjust memory quotas for a process (SeIncreaseQuotaPrivilege)
			Increase a process working set (SeIncreaseWorkingSetPrivilege)
			Allow log on locally (SeInteractiveLogonRight)
			Load and unload device drivers (SeLoadDriverPrivilege)
			Lock pages in memory (SeLockMemoryPrivilege)
			Add workstations to domain (SeMachineAccountPrivilege)
			Perform volume maintenance tasks (SeManageVolumePrivilege)
			Access this computer from the network (SeNetworkLogonRight)
			Profile single process (SeProfileSingleProcessPrivilege)
			Modify an object label (SeRelabelPrivilege)
			Allow log on through Remote Desktop Services (SeRemoteInteractiveLogonRight)
			Force shutdown from a remote system (SeRemoteShutdownPrivilege)
			Restore files and directories (SeRestorePrivilege)
			Manage auditing and security log (SeSecurityPrivilege)
			Log on as a service (SeServiceLogonRight)
			Shut down the system (SeShutdownPrivilege)
			Synchronize directory service data (SeSyncAgentPrivilege)
			Modify firmware environment values (SeSystemEnvironmentPrivilege)
			Profile system performance (SeSystemProfilePrivilege)
			Change the system time (SeSystemtimePrivilege)
			Take ownership of files or other objects (SeTakeOwnershipPrivilege)
			Act as part of the operating system (SeTcbPrivilege)
			Change the time zone (SeTimeZonePrivilege)
			Access Credential Manager as a trusted caller (SeTrustedCredManAccessPrivilege)
			Remove computer from docking station (SeUndockPrivilege)
	
	.Example
		Usage:
		Single Users
			Add User Right "Log on as a service" for CONTOSO\User:
			.\Set-UserRights.ps1 -AddRight -Username CONTOSO\User -UserRight SeServiceLogonRight
			
			Add User Right "Log on as a batch job" for CONTOSO\User:
			.\Set-UserRights.ps1 -AddRight -Username CONTOSO\User -UserRight SeBatchLogonRight

			Remove User Right "Log on as a batch job" for CONTOSO\User:
			.\Set-UserRights.ps1 -RemoveRight -Username CONTOSO\User -UserRight SeBatchLogonRight
			
			Add User Right "Allow log on locally" for current user:
			.\Set-UserRights.ps1 -AddRight -UserRight SeInteractiveLogonRight

			Remove User Right "Allow log on locally" for current user:
			.\Set-UserRights.ps1 -RemoveRight -UserRight SeInteractiveLogonRight
		
		Multiple Users / Services / Computers
			Add User Right "Log on as a service" and "Log on as a batch job" for CONTOSO\User and run on, local machine and SQL.contoso.com:
			.\Set-UserRights.ps1 -AddRight -UserRight SeServiceLogonRight, SeBatchLogonRight -ComputerName $env:COMPUTERNAME, SQL.contoso.com -UserName CONTOSO\User1, CONTOSO\User2
	
	.Notes
		Original Creator: Bill Loytty (weloytty)
		Based on this script found here: https://github.com/weloytty/QuirkyPSFunctions/blob/ab4b02f9cc05505eee97d2f744f4c9c798143af1/Source/Users/Grant-LogOnAsService.ps1
		I modified to my own needs: https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/General%20Functions/Set-UserRights.ps1
		
		My blog post: https://blakedrumm.com/blog/set-and-check-user-rights-assignment/
		
		Author: Blake Drumm (blakedrumm@microsoft.com)
		First Created on: January 5th, 2022
		Last Modified on: October 12th, 2022
#>
param
(
	[Parameter(Position = 0,
			   HelpMessage = 'You want to Add a user right.')]
	[Alias('add')]
	[switch]$AddRight,
	[Parameter(Position = 1)]
	[Alias('computer')]
	[array]$ComputerName,
	[Parameter(Position = 2,
			   HelpMessage = 'You want to Remove a user right.')]
	[switch]$RemoveRight,
	[Parameter(Position = 3)]
	[Alias('user')]
	[array]$Username,
	[Parameter(Mandatory = $false,
			   Position = 4)]
	[ValidateSet('SeNetworkLogonRight', 'SeBackupPrivilege', 'SeChangeNotifyPrivilege', 'SeSystemtimePrivilege', 'SeCreatePagefilePrivilege', 'SeDebugPrivilege', 'SeRemoteShutdownPrivilege', 'SeAuditPrivilege', 'SeIncreaseQuotaPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeLoadDriverPrivilege', 'SeBatchLogonRight', 'SeServiceLogonRight', 'SeInteractiveLogonRight', 'SeSecurityPrivilege', 'SeSystemEnvironmentPrivilege', 'SeProfileSingleProcessPrivilege', 'SeSystemProfilePrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeTakeOwnershipPrivilege', 'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeUndockPrivilege', 'SeManageVolumePrivilege', 'SeRemoteInteractiveLogonRight', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege', 'SeDelegateSessionUserImpersonatePrivilege', 'SeMachineAccountPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeTcbPrivilege', 'SeCreateTokenPrivilege', 'SeCreatePermanentPrivilege', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeEnableDelegationPrivilege', 'SeLockMemoryPrivilege', 'SeRelabelPrivilege', 'SeSyncAgentPrivilege', IgnoreCase = $true)]
	[Alias('right')]
	[array]$UserRight
)
BEGIN
{
	
	Write-Output '==================================================================='
	Write-Output '==========================  Start of Script ======================='
	Write-Output '==================================================================='
	
	$checkingpermission = "Checking for elevated permissions..."
	$scriptout += $checkingpermission
	Write-Output $checkingpermission
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
		Write-Output $permissiongranted
	}
	
	Function Time-Stamp
	{
		$TimeStamp = Get-Date -UFormat "%B %d, %Y @ %r"
		return "$TimeStamp - "
	}
}
PROCESS
{
	function Inner-SetUserRights
	{
		param
		(
			[Parameter(Position = 0,
					   HelpMessage = 'You want to Add a user right.')]
			[Alias('add')]
			[switch]$AddRight,
			[Parameter(Position = 1)]
			[Alias('computer')]
			[array]$ComputerName,
			[Parameter(Position = 2,
					   HelpMessage = 'You want to Remove a user right.')]
			[switch]$RemoveRight,
			[Parameter(Position = 3)]
			[Alias('user')]
			[array]$Username,
			[Parameter(Mandatory = $false,
					   Position = 4)]
			[Alias('right')]
			[array]$UserRight
		)
		if (!$UserRight)
		{
			Write-Warning "Inner Function: Unable to continue because you did not supply the '-UserRight' parameter."
			break
		}
		if (!$AddRight -and !$RemoveRight)
		{
			Write-Warning "Inner Function: Unable to continue because you did not supply the '-AddRight' or '-RemoveRight' switches."
			break
		}
		elseif ($AddRight -and $RemoveRight)
		{
			Write-Warning "Inner Function: Unable to continue because you used both the '-AddRight' and '-RemoveRight' switches. Run again with just one of these present, either Add or Remove."
			break
		}
		elseif ($AddRight)
		{
			Write-Verbose "Inner Function: Detected -AddRight switch in execution."
			$ActionType = 'Adding'
		}
		elseif ($RemoveRight)
		{
			Write-Verbose "Inner Function: Detected -RemoveRight switch in execution."
			$ActionType = 'Removing'
		}
		else
		{
			Write-Warning "Something is wrong, detected logic is broken before executing main function. Exiting."
			break
		}
		Function Time-Stamp
		{
			$TimeStamp = Get-Date -UFormat "%B %d, %Y @ %r"
			return "$TimeStamp - "
		}
		$tempPath = [System.IO.Path]::GetTempPath()
		$import = Join-Path -Path $tempPath -ChildPath "import.inf"
		if (Test-Path $import) { Remove-Item -Path $import -Force }
		$export = Join-Path -Path $tempPath -ChildPath "export.inf"
		if (Test-Path $export) { Remove-Item -Path $export -Force }
		$secedt = Join-Path -Path $tempPath -ChildPath "secedt.sdb"
		if (Test-Path $secedt) { Remove-Item -Path $secedt -Force }
		$Error.Clear()
		try
		{
			foreach ($right in $UserRight)
			{
				$UserLogonRight = switch ($right)
				{
					"SeBatchLogonRight"				    { "Log on as a batch job (SeBatchLogonRight)" }
					"SeDenyBatchLogonRight"			    { "Deny log on as a batch job (SeDenyBatchLogonRight)" }
					"SeDenyInteractiveLogonRight"	    { "Deny log on locally (SeDenyInteractiveLogonRight)" }
					"SeDenyNetworkLogonRight"		    { "Deny access to this computer from the network (SeDenyNetworkLogonRight)" }
					"SeDenyRemoteInteractiveLogonRight" { "Deny log on through Remote Desktop Services (SeDenyRemoteInteractiveLogonRight)" }
					"SeDenyServiceLogonRight"		    { "Deny log on as a service (SeDenyServiceLogonRight)" }
					"SeInteractiveLogonRight"		    { "Allow log on locally (SeInteractiveLogonRight)" }
					"SeNetworkLogonRight"			    { "Access this computer from the network (SeNetworkLogonRight)" }
					"SeRemoteInteractiveLogonRight"	    { "Allow log on through Remote Desktop Services (SeRemoteInteractiveLogonRight)" }
					"SeServiceLogonRight"			    { "Log on as a service (SeServiceLogonRight)" }
					Default 							{ "($right)" }
				}
				Write-Output ("$(Time-Stamp)$ActionType `"$UserLogonRight`" right for user account: '$Username' on host: '$env:COMPUTERNAME'")
				if ($Username -match "^S-.*-.*-.*$|^S-.*-.*-.*-.*-.*-.*$|^S-.*-.*-.*-.*-.*$|^S-.*-.*-.*-.*$")
				{
					$sid = $Username
				}
				else
				{
					$sid = ((New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier])).Value
				}
				secedit /export /cfg $export | Out-Null
				#Change the below to any right you would like
				$sids = (Select-String $export -Pattern "$right").Line
				if ($ActionType -eq 'Adding')
				{
					# If right has no value it needs to be added
					if ($sids -eq $null)
					{
						$sids = "$right = *$sid"
						$sidList = $sids
					}
					else
					{
						$sidList = "$sids,*$sid"
					}
				}
				elseif ($ActionType -eq 'Removing')
				{
					$sidList = "$($sids.Replace("*$sid", '').Replace("$Username", '').Replace(",,", ',').Replace("= ,", '= '))"
				}
				Write-Verbose $sidlist
				foreach ($line in @("[Unicode]", "Unicode=yes", "[System Access]", "[Event Audit]", "[Registry Values]", "[Version]", "signature=`"`$CHICAGO$`"", "Revision=1", "[Profile Description]", "Description=$ActionType `"$UserLogonRight`" right for user account: $Username", "[Privilege Rights]", "$sidList"))
				{
					Add-Content $import $line
				}
			}
			
			secedit /import /db $secedt /cfg $import | Out-Null
			secedit /configure /db $secedt | Out-Null
			gpupdate /force | Out-Null
			Write-Verbose "The script will not delete the following paths due to running in verbose mode, please remove these files manually if needed:"
			Write-Verbose "`$import : $import"
			Write-Verbose "`$export : $export"
			Write-Verbose "`$secedt : $secedt"
			
			if ($VerbosePreference.value__ -eq 0)
			{
				Remove-Item -Path $import -Force | Out-Null
				Remove-Item -Path $export -Force | Out-Null
				Remove-Item -Path $secedt -Force | Out-Null
			}
		}
		catch
		{
			Write-Output ("$(Time-Stamp)Failure occurred while granting `"$right`" to user account: '$Username' on host: '$env:COMPUTERNAME'")
			Write-Output "Error Details: $error"
		}
	}
	$InnerSetUserRightFunctionScript = "function Inner-SetUserRights { ${function:Inner-SetUserRights} }"
	function Set-UserRights
	{
		param
		(
			[Parameter(Position = 0,
					   HelpMessage = 'You want to Add a user right.')]
			[Alias('add')]
			[switch]$AddRight,
			[Parameter(Position = 1)]
			[Alias('computer')]
			[array]$ComputerName,
			[Parameter(Position = 2,
					   HelpMessage = 'You want to Remove a user right.')]
			[switch]$RemoveRight,
			[Parameter(Position = 3)]
			[Alias('user')]
			[array]$Username,
			[Parameter(Mandatory = $false,
					   Position = 4)]
			[ValidateSet('SeNetworkLogonRight', 'SeBackupPrivilege', 'SeChangeNotifyPrivilege', 'SeSystemtimePrivilege', 'SeCreatePagefilePrivilege', 'SeDebugPrivilege', 'SeRemoteShutdownPrivilege', 'SeAuditPrivilege', 'SeIncreaseQuotaPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeLoadDriverPrivilege', 'SeBatchLogonRight', 'SeServiceLogonRight', 'SeInteractiveLogonRight', 'SeSecurityPrivilege', 'SeSystemEnvironmentPrivilege', 'SeProfileSingleProcessPrivilege', 'SeSystemProfilePrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeTakeOwnershipPrivilege', 'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeUndockPrivilege', 'SeManageVolumePrivilege', 'SeRemoteInteractiveLogonRight', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege', 'SeDelegateSessionUserImpersonatePrivilege', 'SeMachineAccountPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeTcbPrivilege', 'SeCreateTokenPrivilege', 'SeCreatePermanentPrivilege', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeEnableDelegationPrivilege', 'SeLockMemoryPrivilege', 'SeRelabelPrivilege', 'SeSyncAgentPrivilege', IgnoreCase = $true)]
			[Alias('right')]
			[array]$UserRight
		)
		if (!$Username)
		{
			$Username = "$env:USERDOMAIN`\$env:USERNAME"
		}
		if (!$UserRight)
		{
			Write-Warning "Main Function: Unable to continue because you did not supply the '-UserRight' parameter."
			break
		}
		if (!$AddRight -and !$RemoveRight)
		{
			Write-Warning "Main Function: Unable to continue because you did not supply the '-AddRight' or '-RemoveRight' switches."
			break
		}
		elseif ($AddRight -and $RemoveRight)
		{
			Write-Warning "Main Function: Unable to continue because you used both the '-AddRight' and '-RemoveRight' switches. Run again with just one of these present, either Add or Remove."
			break
		}
		elseif ($AddRight)
		{
			Write-Verbose "Main Function: Detected -AddRight switch in execution."
			$ActionType = 'Adding'
		}
		elseif ($RemoveRight)
		{
			Write-Verbose "Main Function: Detected -RemoveRight switch in execution."
			$ActionType = 'Removing'
		}
		if (!$ComputerName)
		{
			$ComputerName = $env:ComputerName
		}
		foreach ($user in $Username)
		{
			foreach ($right in $UserRight)
			{
				foreach ($computer in $ComputerName)
				{
					if ($computer -match $env:COMPUTERNAME)
					{
						Inner-SetUserRights -UserRight $right -Username $user -AddRight:$AddRight -RemoveRight:$RemoveRight
					}
					else
					{
						Invoke-Command -ComputerName $Computer -Script {
							param ($script,
								[string]$Username,
								[Parameter(Mandatory = $true)]
								[array]$UserRight,
								$AddRight,
								$RemoveRight,
								$VerbosePreference)
							. ([ScriptBlock]::Create($script))
							$VerbosePreference = $VerbosePreference
							$Error.Clear()
							try
							{
								if ($VerbosePreference -eq 0)
								{
									Inner-SetUserRights -Username $Username -UserRight $UserRight -AddRight:$AddRight -RemoveRight:$RemoveRight
								}
								else
								{
									Inner-SetUserRights -Username $Username -UserRight $UserRight -AddRight:$AddRight -RemoveRight:$RemoveRight -Verbose
								}
							}
							catch
							{
								$info = [PSCustomObject]@{
									Exception = $Error.Exception.Message
									Reason    = $Error.CategoryInfo.Reason
									Target    = $Error.CategoryInfo.TargetName
									Script    = $Error.InvocationInfo.ScriptName
									Line	  = $Error.InvocationInfo.ScriptLineNumber
									Column    = $Error.InvocationInfo.OffsetInLine
									Date	  = Get-Date
									User	  = $env:username
								}
								Write-Warning "$info"
							}
							
						} -ArgumentList $InnerSetUserRightFunctionScript, $user, $right, $AddRight, $RemoveRight, $VerbosePreference
					}
				}
			}
		}
		
	}
	if ($ComputerName -or $Username -or $UserRight -or $RemoveRight)
	{
		foreach ($user in $Username)
		{
			Set-UserRights -ComputerName $ComputerName -Username $user -UserRight $UserRight -AddRight:$AddRight -RemoveRight:$RemoveRight
		}
	}
	else
	{
		
	 <# Edit line 437 to modify the default command run when this script is executed.
	   Example: 
	        Set-UserRights -AddRight -UserRight SeServiceLogonRight, SeBatchLogonRight -ComputerName $env:COMPUTERNAME, SQL.contoso.com -UserName CONTOSO\User1, CONTOSO\User2
	        or
	        Set-UserRights -AddRight -UserRight SeBatchLogonRight -Username S-1-5-11
	        or
	        Set-UserRights -RemoveRight -UserRight SeBatchLogonRight -Username CONTOSO\User2
	        or
	        Set-UserRights -RemoveRight -UserRight SeServiceLogonRight, SeBatchLogonRight -Username CONTOSO\User1
	   #>
		Set-UserRights
	}
}
END
{
	Write-Output "$(Time-Stamp)Script Completed!"
}

# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC95Llw4AZ34vSd
# dcaKQ2RUIrq54f3GO9qvaNoRStHd+KCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEII3liyFs/Dunhh7+6ZwVc/p/
# IMcpBQe+M6A8nZBSGeUoMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCvVE3+GJ3ZwlK3nab4gaAyQvBIJ3M8CtPUS1FtiPeQusEwePE2UE21
# 07uvI74KXDMjRXxeDqaPjcavxl+BsZJilJPp0NfvW+CIH7z4t5PmG6gld7e8iwlt
# Ypgx2QOJCnMSKuKsaWp7cohVNGUSvgIk0TL3rkbqkWNjhTNncNwmkJE9Ft/+aviO
# BosizMB8CZXtEWkYZvVr0ZNax1/5uw35HPi/0vqapvD1FqAF94jPK0sbFgLT2FTB
# tT+FpH006eF0NUBDFaPLz72bliIJGKglVwIB7Eapq8BzpAa7YaxBX36xgcfFRLZI
# AJWI7No6JVJjvQ9YJQITZkiQQDdaAh9noYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIONyT2/T2YADjY4e9kxDIfl1SDoZGOSr46S9ISR7g1J6AgZjbSXQ
# WegYEzIwMjIxMTI5MjAzMDM3LjE0MlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkU1QTYt
# RTI3Qy01OTJFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAG+9CCi7pbWINYAAQAAAb4wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTIyWhcNMjQwMjAyMTkwMTIyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RTVBNi1FMjdDLTU5MkUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQClX/LbPsNrucy7S3KQtjyiWHtnTcSoU3PeIWUyn2A5
# 9WZkAGaF4JzztG491DY/44dQmKoJABY241Kgj9DWLETD0ADrnuV0Pxnf8SS2mbEo
# cdq86HBBIU9ylMYVVcjEoLCg7zbiCLIc8bzh1+F2LpZTt/sP7zkto8HR06w8coow
# aUL2nrou/3JDO8CFkYWYWGW6wLL96CvPolf84c5P2oLC6CGsvQg9/jtQt7WlBIQS
# KHLjfwnBL6tlTgBXK9BzOUwLbpexO4M+ARAqXPH2u7sS81X32X8oJT1tsV/lKeQ3
# WahSApSrT01aUrHMsYS+GR7ZA0yimfzomHV+X89V683/GtlKlXbesziUHuWHtdKw
# I94WyVNiiMo3aKg4LqncHLuQSa9kKHqsCw8qwBEkhJ3MpAIyr6aoO6I/qav8u+5Y
# qKc/7ZkaYr8LX+yS+VOO0h6G7nTKhc0OWHUI30HdAuCVBj5QIESomiD8HECfelZ1
# HTWj/rpchpyBcj93TAbb/HQ61uMQYCRpx9CWbDRsNzTZ2FAWSL/VD1VvCHiQLtWA
# CIkDxsLnMQhhYc1TsL4d7r0Hj/Z1mlGOB3mkSkdsX05iIB/uzkydgScc3/mj9sY7
# RqMBvtUjh/1q/rawLrG+EpMHlHiWHEQxYXTPi/sFDkIfIw2Qv6hOfMkuqctV1ee4
# zQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFOsqIBahhEGg8a1vC9uGFfprb6KqMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAMeV+71zQiaF0GKzXKPnpsG85LIakL+tJK3L7UXj1N/p+YUR6rGHBNMdUc54
# hE13yBwMtLPR3v2ZcKqrzKerqAmDLa7gvLICvYubDMVW67GgZVHxi5SdG2+wMfkn
# 66fJ7+cyTAeIL4bzaHe5Dx9waP7YfSco+ZSlS19Cu4xRe/MuNXk3JGMOIIvlz9/l
# 5ybPTV2emcK8TqQjP8VOmS855UmTbYjZqQVmE/PbgPo5PoqRO3AFGlIQcNioJDhx
# n7tJfHuPPN3tv7Sn28NuioLLtLBaAqkZAb7BVsqtObiEqRkPNx0ASBip6FfPvwbT
# SZgguINPJSKTBCmhntqb2kDoF1M9j6jW/oJHNyd4g6clhqcdbPRH4oRH9lEW0sLI
# Ey8vNIcSfSxHT7SQuSWdwqMZ0DVgDjbM5vrXVR4gbK1n1WE3CfjCzkYnqfo8mYw8
# 77I8SQ7LZ/w4GK6FqqWKmJaHMa23lSwLSB4bSxb2rBrhABbWxBYiuFKXbgw45XA2
# X8Cb39mq8tFavXHie6l5Hwbv4M3KfgxODbzIVlFTWS1K/IExRK83Yr30E7qnWBLH
# /C9KxHjl0bfc8Mbl8qoc6APFy2MFTltfj14mqM0vtL9Sd0sXtLQ5Yv2Z2T+M9Uc/
# Yjpe03QrhWN1HC8iCveM2JvcZnIYmc5Gn9kxtjYO/WYpzHt1MIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpFNUE2LUUyN0MtNTkyRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAaK1aUve8+7wQ04B76Lb7jB9MwHug
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOcwsFwwIhgPMjAyMjExMzAwMDIyNTJaGA8yMDIyMTIwMTAwMjI1Mlow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5zCwXAIBADAKAgEAAgISqgIB/zAHAgEA
# AgIRLzAKAgUA5zIB3AIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAE2VzhiZ
# iTMSbljLfLyDAFAQ3TIV0ZTChtRmCulXNY883JEANF8oHbPUmLDcLdBjWmagfZAJ
# ebjYwIh+ZwFzZ+ysNltqT6eyz8JsHWiTGj3Zdz0IZoRGAf4S5CMgZolxgB2k/Qv8
# kDgwrcscjLLs5fALlodzDeD85iqe7LiSFmS/MYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG+9CCi7pbWINYAAQAAAb4wDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgYSbv9TcKar6UCQlBWKaZp8w2NF34OnwZQxOyjmowk4owgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCU7oqvrfb87L1ltc+uEQ+J00CD8V5/
# srdJmD4PGOEMLzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABvvQgou6W1iDWAAEAAAG+MCIEIE7BZY3XdTEngGnCiLileum3gPrXno0d
# /LKYf97N5RaRMA0GCSqGSIb3DQEBCwUABIICADZnvk+8UATICXqsJzRHj6Usg6Xz
# ElBax/o6S6uypXOU/X/pQoZvfICdpbXgnaVXnj/hJFqbyFGYOk4MNzk5Q/e0dgPE
# Dda1SP+B72+XVEBAbgKkQZNyCOMOYChlfmw6ylhw0reR+HgPxTfhNRn6ES5gvwe6
# qRz26/VzRIXBSHHqGAMi4/5oCfaSoIxmE2jrlNbsYZpD5Nea0n0n2ig3iqX6W+/e
# Mv3NVVm1F679KZEGil+IRGpr+CFmI853VXcezH9A+gae0hP/bYMVV0WOk8qH74U3
# RcqdI4X/0dU1rUThU34ZgARp/ASMInkF5Dt/9WN9UEmDh34GXwDHSINy7J20fDIF
# QfpggIhSf4vj7LkarLfgvz1+Y7Z08VbJqzaKdRE7t8hCU9OdY4BkiIr0UXC5zwC4
# J27qw5vZv6gdfKYkY9//jlCX4qD8FQY5p1W71hPANxqJSDJpICY0l4NNQ07Pxxgb
# CMtje/bptGc1xoB6T9j+EAsJaC3+sxQggk2ciHFUjHLUpoRY1RN3oaXmEFocZEn1
# da5acaNaitg2/6S5KrM0/oZEVqvqGGBUnziRQyRwUuhvoSLLcM/sKFVOAewt5Jrk
# ZHbLcfCrjsnqP/IGl7TMPzfK/mpbT4736/rQ8DzcoWQBN6o3Uz6d31G7j7UjUCTF
# b47IUdsOgsOh+OMV
# SIG # End signature block
