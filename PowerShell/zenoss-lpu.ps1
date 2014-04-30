#
# Copyright 2013 Zenoss Inc., All rights reserved
#


<#
	.SYNOPSIS
	Configure local system permissions to support least privilege user access for Zenoss Resource Manager monitoring.
	.DESCRIPTION
	Need to add some more info here 
	.EXAMPLE
	zen-setup.ps1 -check_only
	.EXAMPLE
	zen-setup.ps1 -user zenmonitor -group zenoss -password "lkasdf" -add_all

	.EXAMPLE
	zen-setup.ps1 -user zenmonitor@zenoss.com -group....


#>


$username = 'zenny'					# Username alone
$domaintype = 'domain'		# local or domain

# The following values will be set at runtime. They are place holders here.
$usersid

# Default settings
$inherit = $True      # Set to false (not recommended) if you do not want WMI Acl inheritance
$namespaceParams = @{Namespace=$namespace;Path="__systemsecurity=@"}

$OBJECT_INHERIT_ACE_FLAG = 0x1
$CONTAINER_INHERIT_ACE_FLAG = 0x2

# Set account information
if($domaintype.ToLower() -ne 'local'){
	$domain = $env:USERDOMAIN
	$userfqdn = "{0}@{1}" -f $username, $domain 
}
else {
	$domain = $env:USERDNSDOMAIN
	$userfqdn = "{1}\{0}" -f $username, $domain
}


function get_user_sid($getuser=$userfqdn) {
	$objUser = New-Object System.Security.Principal.NTAccount($getuser)
	$objSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
	return $objSID.Value
}

function allow_access_to_winrm($usersid) {
	#check to confirm sid is set.
	if($usersid.Length -gt 5) {
		$sddlstart = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
	} 
	else {
		throw "Error getting WinRM SDDL"
	}
}

function get_accessmask($permissions){
	<#
	$permission = Enable,MethodExecute,ReadSecurity,RemoteAccess
	#>

	$permTable = @{
		"enable" 			= 1;
		"methodexecute" 	= 2;
		"fullwrite"			= 4;
		"partialwrite"		= 8;
		"providerwrite"		= 0x10;
		"remoteaccess"		= 0x20;
		"readsecurity"		= 0x20000;
		"writesecurity"		= 0x40000
	}

	$accessMask = 0
	foreach ($perm in $permissions) {
		$perm = $perm.ToLower()
		if($permTable.ContainsKey($perm)){
			$accessMask += $permTable[$perm]
		}
		else {
		    throw "Unknown permission: $perm"
		}
	}
	return $accessMask
}

<#

Might be able to remove this function

function get_user_account(){
	$accountparams = @{
		Class="Win32_Account";
		Filter="Domain='$domain' and Name='$username'"}

	$objUser = Get-WmiObject @accountparams

	if ($objUser -eq $null){
		throw "Account was not found: $userfqdn"
	}

	return $objUser
}
#>

function add_ace($accessMask, $namespace){
	$currentSecurityDescriptor = Invoke-WmiMethod @namespaceParams -Name GetSecurityDescriptor
	if($currentSecurityDescriptor.ReturnValue -ne 0){
		throw "Failed to get security descriptor for namespace: $namespace"
	}
	$objACL = $currentSecurityDescriptor.Descriptor

	$objACE = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
	$objACE.AccessMask = $accessMask
	if ($inherit){
		$objACE.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
	}
	else {
	    $objACE.AceFlags = 0
	}
	$objTrust = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
	$objTrust.SidString = $usersid
	$objACE.Trustee = $objTrust
	$objACE.AceType = 0x0
	$objACL.DACL += $objACE.psobject.immediateBaseObject
	$daclparams = @{
		Name="SetSecurityDescriptor";
		ArgumentList=$objACL.psobject.immediateBaseObject
	} + $namespaceParams
	$setresults = Invoke-WmiMethod @daclparams
	if ($setresults.ReturnValue -ne 0) {
		throw "Set Security Descriptor FAILED: $($setresults.ReturnValue)"
		}
}

function allow_access_to_wminamespace($namespace){
	$permissions = @("Enable","MethodExecute","ReadSecurity","RemoteAccess")
	$accessmap = get_accessmask $permissions
	add_ace $accessmap $namespace
}


# Initialize user information
$usersid = get_user_sid
$namespaces = @("Root", "root/CIMv2")
foreach ($namespace in $namespaces) {
	allow_access_to_wminamespace($namespace)
}
