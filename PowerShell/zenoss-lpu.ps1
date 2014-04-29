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


$username
$userfqdn			# Example zenmonitor@zenoss.com


# The following values will be set at runtime. They are place holders here.
$usersid
$userdomain



function get_user_sid($getuser=$userfqdn) {
	$objUser = New-Object System.Security.Principal.NTAccount($getuser)
	$objSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
	return $objSID.Value
}



function allow_access_to_winrm($username) {
	#check to confirm sid is set.
	if $usersid.Length -gt 5 {
		$sddlstart = (Get-Item WSMan:\localhost\Service\RootSDDL).Value

	} 
	else {
	    #send error message
	}
	$sddlstart = ()
}

function allow_access_to_wminamespace($ns, $user=){

	
}



# Initialize user information
$usersid = get_user_sid

