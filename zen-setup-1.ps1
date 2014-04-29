#
# Copyright 2013 Zenoss Inc., All rights reserved
#

<#
   .SYNOPSIS
   Setup permissions for a user/group to be able to monitor this computer via Zenoss Resource Manager
   .DESCRIPTION
   This script will add, verify or remove permissions required for monitoring a Windows Server by a specified local or AD user/group.  Local user and group can be created and deleted, but while Active Directory users and groups can be granted permissions, modifications to AD is not supported.
   Modification is made to several registry entries, registry ACLs, namespace ACLs, local group memberships and services to allow remote access via WMI.  Once the specified group has been granted permission, any user in that group will inherit the appropriate rights.  User specification is present only to allow scripted creation of a user and to verify group membership.  Firewall settings will need to be adjusted manually to allow remote monitoring.
   This script must be run as a user with Administrative rights to the computer.
   This script has been tested on Win2008R2AP1 (with and without AD), Win20012 (without AD) and Win7 (requires an additional step of allowing remoteAdmin (eg. "netsh firewall set service RemoteAdmin enable" or "netsh advfirewall firewall set rule group="remote admin" new enable=Yes"))
   .EXAMPLE
   zen-setup.ps1 -check_only 
   Without modifying the system in any way, verifies the following:
      - required services are running
      - required services auto-start at boot
      - 'zenmonitor' local user exists,
      - 'zenmongrp' local group exists and that 'zenmonitor is a member'
      - 'zenmongrp' is in the approprate local groups
      - 'zenmongrp' has appropriate permissions for monitoring via Zenoss Resource Manager
   Only exceptions are noted.
      
   The above verification is done for all invokations of this script, after any modifications are made.
   .Example
   zen-setup.ps1 -user zentester -group zenoss -password "Sup3rs3cr3t" -add_all
   Creates the specified user local if non-existant
   Creates the specified local group if non-existant
   Adds user to the specified local group if not already a member
   Adds the local group to appropriate local groups if not already a member
   Gives the specified local group appropriate permissions for monitoring via Zenoss Resource Manager, removing conflicting permissions if required
   .Example
   zen-setup.ps1 -user zentester@domain.loc -group zenoss@domain.loc -ldap_user admin@domain.loc -ldap_password "Sup3rs3cr3t" -add_user_access -add_group_access -dont_start_services
   Uses the provided LDAP credentials to verify the existance of the specified AD user and group, and that the user is a member of the group
   Adds the AD user to the appropriate local groups
   Gives the AD group appropriate permissions for monitoring via Zenoss Resource Manager, removing conflicting permissions if required
#>   
   

Param
(
   [Parameter(HelpMessage="Groupname to create or check.  Simple name for local group, 'name@domain' for domain group.  Domain groups will not be created and no users will be added to Domain groups.")]
   [Alias('ZenossGroup','Groupname','Group')]
   [string]
   $mon_group = "zenmongrp",

   [Parameter(HelpMessage="Username to create or check.  Simple name for local user, 'name@domain' for domain user.  Domain users will not be created.")]
   [Alias('ZenossUser','Username','User')]
   [string]
   $mon_user = "zenmonitor",

   [Parameter(HelpMessage="Password to be set when creating new local user")]
   [Alias('Userpw','passwd','Password','pw')]
   [ValidateNotNullOrEmpty()]
   [string]
   $mon_user_password,

   [ValidateNotNullOrEmpty()]
   [string]
   $computer = $env:computername,

   [Parameter(HelpMessage="Domain user with which to authenticate to AD if required.  In the form 'domain\user'.")]
   [ValidateNotNullOrEmpty()]
   [string]
   $ldap_user,

   [Parameter(HelpMessage="Password for domain user with which to authenticate to AD if required.")]
   [ValidateNotNullOrEmpty()]
   [string]
   $ldap_password,

   [Parameter(HelpMessage="Make no modifications, check access only.")]
   [Alias('Check')]
   [switch]
   $check_only,

   [Parameter(HelpMessage="Remove access for specified user and group")]
   [switch]
   $remove_access,

   [Parameter(HelpMessage="Remove access for specified user")]
   [switch]
   $remove_user_access,

   [Parameter(HelpMessage="Remove access for specified group")]
   [switch]
   $remove_group_access,

   [Parameter(HelpMessage="Remove specified local user")]
   [Alias('Remove_zenossuser')]
   [switch]
   $remove_user,
   
   [Parameter(HelpMessage="Remove specified local group")]
   [Alias('Remove_zenossgroup')]
   [switch]
   $remove_group,

   [Parameter(HelpMessage="Remove access for specified user/group and remove local user/group")]
   [Alias('Remove','Remove_everything')]
   [switch]
   $remove_all,

   [Parameter(HelpMessage="Add access for specified user and group")]
   [switch]
   $add_access,

   [Parameter(HelpMessage="Add access for specified user")]
   [switch]
   $add_user_access,

   [Parameter(HelpMessage="Add access for specified group")]
   [switch]
   $add_group_access,

   [Parameter(HelpMessage="Add specified local user")]
   [Alias('Add_zenossuser')]
   [switch]
   $add_user,
   
   [Parameter(HelpMessage="Add specified local group")]
   [Alias('Add_zenossgroup')]
   [switch]
   $add_group,

   [Parameter(HelpMessage="Add access for specified user/group and add local user/group")]
   [Alias('Add','Add_everything')]
   [switch]
   $add_all,

   [Parameter(HelpMessage="Supress the starting of required services")]
   [switch]
   $dont_start_services,

   [Parameter(HelpMessage="Supress the setting of required services to auto-start on boot")]
   [switch]
   $dont_auto_services
)

if ($remove_all) {
  $remove_access = $True
  $remove_user = $True
  $remove_group = $True
}
if ($remove_access) {  
   $remove_user_access = $True
   $remove_group_access = $True
}

if ($remove_user) { $remove_user_access = $True}
if ($remove_group) { $remove_group_access = $True}

if ($add_all) {
   $add_access = $True
   $add_user = $True
   $add_group = $True
}
if ($add_access) {  
   $add_user_access = $True
   $add_group_access = $True
}

if ($add_group) { $add_group_access = $True}

$add_set = ($add_user -or $add_user_access -or $add_group -or $add_group_access)

$remove_set = ($remove_user -or $remove_user_access -or $remove_group -or $remove_group_access)

if ($check_only -and ($add_set -or $remove_set)) {
   write-host "Error: Cannot specify 'Check Only' mode with add- or remove- parameters"
   exit
}

if ($add_set -and $remove_set) {
   write-host "Error: Both add- and remove- arguments specified."
   exit
}

# by default assume "-add_all"
if (!($add_set -or $remove_set -or $check_only)) {
   $add_user = $add_group = $add_user_access = $add_group_access = $True
}

if ($check_only -or $dont_start_services) {
   $start_services = $False
}

if ($check_only -or $dont_auto_services) {
   $auto_services = $False
}

# check to see if the user specified is a domain user, and separate the name from the domain (path)
$mon_user_principalName = $mon_user
$mon_user, $mon_user_path = $mon_user_principalName.split("@")
if ($mon_user_path) {
   $add_user = $False
}

if ($add_user) { 
   if (!($mon_user_password)) {
      Write-error "password must be supplied when adding a local user"
      exit
   }
   $add_user_access = $True
}

# check to see if the group specified is a domain user, and separate the name from the domain (path)
$mon_group_principalName = $mon_group
$mon_group, $mon_group_path = $mon_group_principalName.split("@")
if ($mon_group_path) {
   $add_group = $False
}

$required_services = @(
"Windows Management Instrumentation",
"DCOM Server Process Launcher",
"Remote Procedure Call (RPC)",
"Remote Registry"
)

# local groups we need to be in to provide additional permissions for monitoring (by 
$groupnames = "Event Log Readers", "Performance Monitor Users", "Distributed COM Users"

# set context for local users/groups
$dir_context = "WinNT://$computer"
# use the ADSI provider for manipulating local users/groups.  It does not support authentication, so we can't use this for AD
$localDirectory = [ADSI]"$dir_context"

if ($dont_auto_services) {
   $auto_services = $False
} else {
   $auto_services = $True
}
if ($dont_start_services) {
   $start_services = $False
} else {
   $start_services = $True
}

$reset_password = $False
$add_membership = $True

# userflags values used when creating new local user
$ADS_UF_DONT_EXPIRE_PASSWD = 0x10000
$ADS_UF_DO_NOT_ALLOW_PASSWD_CHANGE = 0x0040

# check that services are running and set to auto, optionally fix them to be so

write-verbose "Services:"
foreach ($dname in $required_services) {
   $serv = get-service -DisplayName $dname
   if ($serv.Status -ne 'Running') {
      write-host "Service '$dname' is not running"
      if ($start_services) {
         write-host "  Starting Service '$dname'"
         start-service $serv.name
      }
   }
   $wmiserv = get-wmiobject win32_service -filter "displayname = '$dname'"
   if ($wmiserv.StartMode -ne 'Auto') {
      write-host "Service '$dname' is not starting as automatic ($serv.StartMode)"
      if ($auto_services) {
         write-host "   Setting to 'Auto'"
         set-service $serv.name -startuptype automatic
      }
   }
}


# check for existance of user and group and that user is member of group
# optionally setup any missing parts

write-verbose "User:"

$user_sid = $False

if ($mon_user_path) {
   # path is only set if specified user is a domain user
   $user_LDAP = $True
   # set user context for AD lookup and connect using credentials if supplied
   $mon_user_context = "LDAP://$mon_user_path"
   if ($ldap_user) {
      $remoteDirectory = New-Object System.DirectoryServices.DirectoryEntry($mon_user_context, $ldap_user, $ldap_password)
   } else {
      $remoteDirectory = New-Object System.DirectoryServices.DirectoryEntry($mon_user_context)
   }
   # Create an AD searcher object to find the user, filtering by objectClass and sam-account-name (aka shortname)
   $remoteSearch = New-Object System.DirectoryServices.DirectorySearcher($remoteDirectory)
   $remoteSearch.Filter = "(&(samaccountname=$mon_user)(objectclass=user))"
   $user = $remoteSearch.findOne()
   # the find will error out if the user does not exist in that domain or if we have no rights to search or 
   #  if the domain doesn't exist, etc, so we don't need to do any error handling here to get appropriate messages
   
   # dig through the returned DirectoryServices object to get the binary-encoded SID and convert it to text SID for
   #  later use
   $user_sid = (New-Object System.Security.Principal.SecurityIdentifier($user.properties['objectsid'][0],0)).value
   # setup a local context that will resolve to the AD user to be able to add it to local groups
   $mon_user_context = "WinNT://$mon_user_path/$mon_user"
} else {
   $user_LDAP = $False
   # local users are a bit simpler to get context for
   $mon_user_context = "$dir_context/$mon_user"
   $mon_user_principalName = $mon_user

   # use the ADSI provider for local users.  It does not support authentication, so we couldn't use this for AD
   $localDirectory = [ADSI]"$dir_context"

   # just a common function for setting passwords on local users
   # also set theuser to have an un-expiring password and to be unable to change their password (like a service account)
   Function set-password ($user, $passwd) {
      $user.setpassword($passwd)
      $user.setInfo()
      $user.userflags = $user.userflags[0] -bor $ADS_UF_DONT_EXPIRE_PASSWD
      $user.userflags = $user.userflags[0] -bor $ADS_UF_DO_NOT_ALLOW_PASSWD_CHANGE
      $user.setInfo()
   }   

   # we can't easily use the ADSI provider to search for a user, and it also doesn not priovide a text SID, so we use WMI
   # get a list of all local users, and loop through to see if ours exists
   $users = get-wmiobject -class win32_useraccount -Filter "LocalAccount='$True'"
   $wmiuser = $False
   foreach ($userobj in $users) {
      if ($userobj.name -eq $mon_user) {
         $wmiuser = $userobj
      }
   }
   # if we didn't exist, create us and set the password.
   # creation isn't done via WMI, so we create using ADSI and then grab the new user via WMI to have access to the SID
   if (!$wmiuser) {
      write-host "User $mon_user does not exist in context $dir_context"
      if ($add_user) {
         write-host "  Creating user $mon_user"
         $user = $localDirectory.Create("User", $mon_user)
         set-password $user $mon_user_password
         $wmiuser =  get-wmiobject -class win32_useraccount -Filter "LocalAccount='$True' and name='$mon_user'"
      }
   }

   $user_sid = $wmiuser.sid

   # if we didn't just create a new user, get an ADSI reference to the user for later use
   if ($wmiuser -and !$user) {
      $user = [ADSI]"$dir_context/$mon_user,user"
   }   

   # reset the user's password if we were asked to (there's no command-line option for this yet, but it would work)
   if ($user) {
      if ($reset_password) {
         write-host "Resetting password for $mon_user"
         set-password $user $mon_user_password
      }
   }
}

write-verbose "Group:"

$group_sid = $False

if ($mon_group_path) {
   # path is only set if specified group is a domain group
   $group_LDAP = $True
   # set group context for AD lookup and connect using credentials if supplied
   $mon_group_context = "LDAP://$mon_group_path"
   if ($ldap_user) {
      $remoteGDirectory = New-Object System.DirectoryServices.DirectoryEntry($mon_group_context, $ldap_user, $ldap_password)
   } else {
      $remoteGDirectory = New-Object System.DirectoryServices.DirectoryEntry($mon_group_context)
   }
   # Create an AD searcher object to find the group, filtering by objectClass and sam-account-name (aka shortname)
   $remoteGSearch = New-Object System.DirectoryServices.DirectorySearcher($remoteGDirectory)
   $remoteGSearch.Filter = "(&(samaccountname=$mon_group)(objectclass=group))"
   $group = $remoteGSearch.findOne()
   # the find will error out if the user does not exist in that domain or if we have no rights to search or 
   #  if the domain doesn't exist, etc, so we don't need to do any error handling here to get appropriate messages
   
   # dig through the returned DirectoryServices object to get the binary-encoded SID and convert it to text SID for
   #  later use
   $group_sid = (New-Object System.Security.Principal.SecurityIdentifier($group.properties['objectsid'][0],0)).value
   $mon_group_context = "WinNT://$mon_group_path/$mon_group"
} else {
   $group_LDAP = $False
   $group = $False
   $mon_group_context = "$dir_context/$mon_group"
   $mon_group_principalName = $mon_group
   
   # we can't easily use the ADSI provider to search for a group, and it also doesn not priovide a text SID, so we use WMI
   # get a list of all local users, and loop through to see if ours exists
   $groups = get-wmiobject -class win32_group -Filter "LocalAccount='$True'"
   $wmigroup = $False
   foreach ($groupobj in $groups) {
      if ($groupobj.name -eq $mon_group) {
         $wmigroup = $groupobj
      }
   }
   # if we didn't exist, create us
   # creation isn't done via WMI, so we create using ADSI and then grab the new group via WMI to have access to the SID
   if (!$wmigroup) {
      write-host "Group $mon_group does not exist in context $dir_context"
      if ($add_group) {
         write-host "  Creating group $mon_group"
         $group = $localDirectory.Create("Group", $mon_group)
         $group.setInfo()
         $wmigroup =  get-wmiobject -class win32_group -Filter "LocalAccount='$True' and name='$mon_group'"
      }
   } else {
      if ($remove_group) {
         write-host "Removing group $mon_group"
         $result = $localDirectory.Delete("Group", $mon_group)
         $group = $False
      }
   }

   $group_sid = $wmigroup.sid

   # if we didn't just create a new group, get an ADSI reference to the user for later use
   if ($wmigroup -and !$group -and !$remove_group) {
      $group = [ADSI]"$dir_context/$mon_group,group"
   }   

   if ($group) {
      $groupnames += $mon_group
   }
}


write-verbose "Group Membership:"

# this loops throught he required local groups (including any newly created one) and adds the user to them
# mon_user_context is set above to relfect if the user is local or AD
if ($add_user_access -or $remove_user_access) {
   foreach ($groupname in $groupnames) {
      $groupobj = [ADSI]"$dir_context/$groupname,group"
      if ($groupname -eq $mon_group) {
         $member_to_check = $mon_user
         $member_to_add = $mon_user_context
      } else {
         $member_to_check = $mon_group
         $member_to_add = $mon_group_context
      }
      # this bit is ugly, because there's no simple way to test for group membership, and members object is
      #  a different object type that we can't call methods on directly
      $members = $groupobj.members() | foreach-object {$_.GetType().Invokemember("Name", 'GetProperty', $null, $_, $null) }
      if (!($members -contains $member_to_check)) {
         # the member Name will be the shortname for local users or principalName (user@domain) for AD users
         #  so we set this up above when checking the user. along with setting the appropriate context for
         #  adding the different types of users
         if ($add_user_access) {
            write-host "  Adding $member_to_add to $groupname"
            $groupobj.add($member_to_add)
         } else {
            write-host "  Removing $member_to_add from $groupname"
            $groupobj.remove($member_to_add)
         }
         $groupobj.setInfo()
      }
   }
}

# Here we do the validation step to ensure we are in the correct groups
# We loop again here to ensure the add/remove function worked properly
foreach ($groupname in $groupnames) {
   $groupobj = [ADSI]"$dir_context/$groupname,group"
      if ($groupname -eq $mon_group) {
         $member_to_check = $mon_user
         $member_to_add = $mon_user_context
      } else {
         $member_to_check = $mon_group
         $member_to_add = $mon_group_context
      }
   $members = $groupobj.members() | foreach-object {$_.GetType().Invokemember("Name", 'GetProperty', $null, $_, $null) }
   if (!($members -contains $member_to_check)) {
      write-host "User $member_to_add is not a member of $groupname"
   }
}

# Here we check if an AD user if a member of an AD group.  It's much easier to do!
# Local users can't be members of AD groups, and we don't support modifying AD in this script
#  so this is it.
if ($mon_group_path -and $mon_user_path) {
   if (!($group.properties['member'] -contains $user.properties['distinguishedname'][0])) {
      write-host "User $mon_user_principalName is not a member of $mon_group_principalname"
   }
}

# If we have a valid group to work with, we can check and add/remove permissions for the group
#  allowing it's members to have the ability to monitor this computer from Zenoss
if ($group_sid) {
   $sid = $group_sid
   
   # This helper object is used to convert SIDs from binarySD format to/from SDDL (text) format
   $helper = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper

   # These SDDL strings are the defaults found on Win7Sp1, Win2008R2SP1 adn Win2012
   # If at some point a malformed SDDL or BinarySD is stored, the ACLs we are working with get blanked out
   #  and a default set of security rules are applied, which cannot be queried from the running system.  Each
   #  tool that manipulates these must provide it's own defaults to use if the values are blank (which is
   #  completely insane, but that's Microsoft for ya) 
   $defaultWMISDDL = "O:BAG:BAD:(A;CIID;CCDCLCSWRPWPRCWD;;;BA)(A;CIID;CCDCRP;;;NS)(A;CIID;CCDCRP;;;LS)(A;CIID;CCDCRP;;;AU)"
   $defaultWinregSDDL = "O:BAG:BAD:PAI(A;CIIO;GR;;;LS)(A;;KR;;;LS)(A;CIIO;GA;;;BA)(A;;KA;;;BA)(A;;KR;;;BO)"
   $defaultPerflibSDDL = "O:BAG:BAD:PAI(A;CIIO;GA;;;CO)(A;CIIO;GR;;;IU)(A;;KR;;;IU)(A;CIIO;GA;;;SY)(A;;KA;;;SY)(A;CIIO;GR;;;LS)(A;;KR;;;LS)(A;CIIO;GR;;;NS)(A;;KR;;;NS)(A;;KA;;;BA)(A;CIIO;GA;;;BA)(A;CIIO;GR;;;MU)(A;;KR;;;MU)(A;CIIO;GR;;;LU)(A;;KR;;;LU)"   
   $defaultDCOMLaunchSDDL = "O:BAG:BAD:(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;BA)(A;;CCDCLCSWRP;;;LU)(A;;CCDCLCSWRP;;;S-1-5-32-562)"
   $defaultDCOMAccessSDDL = "O:BAG:BAD:(A;;CCDCLC;;;WD)(A;;CCDC;;;AN)(A;;CCDCLC;;;S-1-5-32-562)(A;;CCDCLC;;;LU)"
   $defaultSCMSDDL = "D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)"

   # This function is used to manipulate SDDL values, removing and inserting values as required
   #  'operation' can be one of "check", "add" or "remove"
   Function acl-check-add-remove ($SDDL, $value, $operation="check") {
      # check for the specific Access Control in the ACL using regex.  We take the AC we want to add and make a pattern from it
      #  that has the same basic type (first 4 characters) and the same SID, so that we can remove any AC for the same user that
      #  might have different permissions than what we are adding
      $pattern = [regex]::escape($value.substring(0,4))+'[^)]+'+$sid+'\)'
      write-debug ($value + " >> [" + $pattern + "]")
      if ($SDDL -match "(.*)$pattern(.*)") {
         if ($operation -eq 'check') {
            return $True
         }
         # If we found a match and are either adding or removing pull out the offending entry and reassemble the SDDL without it
         write-debug ("split: [" + $matches[1] + "]  [" + $matches[2] + "]")
         $SDDL = $matches[1] + $matches[2]
      } else {
         # didn't find a match
         if ($operation -eq 'check') {
            return $False
         }
      }
      # If we aren't removing the entry, add the new entry to the end (order is not important in this case)
      if ($operation -ne 'remove') {
         $SDDL += $value
      }
      write-debug ("return: [" + $SDDL + "]")
      return $SDDL
   }

   # Function to add/remove/check ACLs on a registry key
   # This is for an ACL for the key itself, not an ACL on a registry value or an ACL stored in a registry value
   Function add-reg-acl-perms ($path, $value, $operation, $default=$defaultPerflibSDDL) {
      # The get-acl cmdlet is easier but returns too much structure and causes issues when setting, so we have to
      #  get the item reference and then pull out the DACL entry only to work with
      $ACL = (get-item $path).GetAccessControl("Access")
      # There is a GetSecurityDescriptorSDDLform(), but I could make it not fail so went with this
      $SDbin = $ACL.GetSecurityDescriptorbinaryform()
      # Convert the binary for to SDDL so we can actually work with it
      $SDDL = $helper.BinarySDToSDDL($SDbin)
      write-debug ("$path = " + $SDDL.SDDL)
      # If we have no valid SDDL, assign our hard-coded default because we have no other choice
      if (!$SDDL.SDDL) { $SDDL.SDDL = $default ; write-host "Debug: $path\\$property changed to = ", $SDDL.SDDL }
      $modSDDL = acl-check-add-remove $SDDL.SDDL $value $operation
      if ($operation -eq "check") {
         return $modSDDL
      }
      # Convert back to binary because we can't set it as SDDL
      $SD = $helper.SDDLToBinarySD($modSDDL)
      # Put the SDDL back into the ACL, overwriting the old DACL and then save it back
      $result = $ACL.SetSecurityDescriptorBinaryForm($SD.BinarySD)
      # We can use set-acl here as our ACL only contains the DACL and so it won't try to modity the other bits
      #  (SACL, owner, etc)
      $result = set-acl $path $ACL
   }
   
   # Function to add/remove/check ACLs in a registry key property
   # This is for an ACL stored in a registry value not for the registry key itself or an ACL on a registry value
   Function add-reg-perms ($path, $property, $value, $operation, $default=$defaultDCOMLaunchSDDL) {
      # Get the registry property object
      $propObj = get-itemproperty $path -Name $property
      # Create an SDDL copy of the BinarySD value contained in the property value
      # the extra redirection is jyst due to the way properties are represented as objects
      $SDDL = $helper.BinarySDToSDDL($propObj.$property)
      write-debug ("$path\\$property = " + $SDDL.SDDL)
      # If we have no valid SDDL, assign our hard-coded default because we have no other choice
      if (!$SDDL.SDDL) { $SDDL.SDDL = $default ; write-host "Debug: $path\\$property changed to = ", $SDDL.SDDL  }
      $modSDDL = acl-check-add-remove $SDDL.SDDL $value $operation
      if ($operation -eq "check") {
         return $modSDDL
      }
      # Convert our modified SDDL to BinarySD and store it back in the registry property
      $SD = $helper.SDDLToBinarySD($modSDDL)
      $result = set-itemproperty $path -Name $property -Value $SD.BinarySD
   }

   write-verbose "Permissions:"

   # presently we add the permissions to the group rather than each user
   # (I suppose we are technically adding the group into the various ACLs but whatever)
   
   $operation = $null
   if ($add_group_access) {
      $operation = "add"
   }
   if ($remove_group_access) {
      $operation = "remove"
   }
   
   #DCOM perms: Launch

   if ("add", "remove" -contains $operation) {
      add-reg-perms "HKLM:\software\microsoft\ole" "MachineLaunchRestriction" "(A;;CCDCLCRP;;;$sid)" $operation $defaultDCOMLaunchSDDL
   }
   $valid = add-reg-perms "HKLM:\software\microsoft\ole" "MachineLaunchRestriction" "(A;;CCDCLCRP;;;$sid)" "check"

   if (!$valid) {
      write-host "MachineLaunchRestriction permission not set"
   }

   #DCOM perms: Access

   if ("add", "remove" -contains $operation) {
      add-reg-perms "HKLM:\software\microsoft\ole" "MachineAccessRestriction" "(A;;CCDCLC;;;$sid)" $operation $defaultDCOMAccessSDDL
   }
   $valid = add-reg-perms "HKLM:\software\microsoft\ole" "MachineAccessRestriction" "(A;;CCDCLC;;;$sid)" "check"

   if (!$valid) {
      write-host "MachineAccessRestriction permission not set"
   }


   #WMI perms

   # WMI access need to be set on the actual WMI namespace, so we can't use the helper functions that work in the registry

   # grab the SystemSecurity object for WMI namespace "root/cimv2"
   $syssec = Get-WmiObject -ComputerName $computer -Namespace root/cimv2 -Class __SystemSecurity
   $secDesc = @($null)
   # snag the binary Security Descriptor and convert to SDDL
   $result = $syssec.PsBase.InvokeMethod("GetSD",$secDesc)
   $sddl = $helper.BinarySDToSDDL($secDesc[0])
   # If we have no valid SDDL, assign our hard-coded default because we have no other choice
   if (!$sddl.SDDL) { $SDDL.SDDL = $defaultWMISDDL }
   write-debug ("WMI root/cimv2 SD = " + $sddl.SDDL)
   if ("add", "remove" -contains $operation) {
      # user the helper to add/remove the appropriate but in the SDDL
      $modSDDL = acl-check-add-remove $sddl.SDDL "(A;;CCWP;;;$sid)" $operation $defaultWMISDDL
      # convert back to BinarySD
      $wmiSD = $helper.SDDLToBinarySD($modSDDL)
      # create an array with out Binardy SD in it ('cause that's what they seem to want)
      $wmiPerms = ,$wmiSD.BinarySD
      # slap it back down on the namespace
      $result = $syssec.PsBase.InvokeMethod("SetSD",$wmiPerms)
      # now re-read the perms for the check
      $secDesc = @($null)
      $result = $syssec.PsBase.InvokeMethod("GetSD",$secDesc)
      $sddl = $helper.BinarySDToSDDL($secDesc[0])
   }
   $valid = acl-check-add-remove $sddl.SDDL "(A;;CCWP;;;$sid)" "check"
   if (!$valid) {
      write-host "WMI permission not set"
   }

   
   #winreg perms
   
   if ("add", "remove" -contains $operation) {
      add-reg-acl-perms "HKLM:\system\currentcontrolset\control\securepipeservers\winreg" "(A;CI;KR;;;$sid)" $operation $defaultWinregSDDL
   }
   $valid = add-reg-acl-perms "HKLM:\system\currentcontrolset\control\securepipeservers\winreg" "(A;CI;KR;;;$sid)" "check"

   if (!$valid) {
      write-host "WinReg permission not set"
   }
   
   
   #perflib perms
   
   # note that PerfLib requires 2 separate AccessControl entries for each SID to make the access work
   
   if ("add", "remove" -contains $operation) {
      add-reg-acl-perms "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" "(A;CIIO;GR;;;$sid)" $operation $defaultPerflibSDDL
   }
   $valid = add-reg-acl-perms "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" "(A;CIIO;GR;;;$sid)" "check"

   if (!$valid) {
      write-host "Perflib permission 1 not set"
   }

   if ("add", "remove" -contains $operation) {
      add-reg-acl-perms "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" "(A;;KR;;;$sid)" $operation $defaultPerflibSDDL
   }
   $valid = add-reg-acl-perms "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" "(A;;KR;;;$sid)" "check"

   if (!$valid) {
      write-host "Perflib permission 2 not set"
   }
   
   
   # scmanager perms
   
   # ServiceControlManager access is needed to be able to see service states and configuration
   # Technically the ACLs fro this are stored in a registry key property, and that key is updated properly when the 
   #  Microsoft-provided SC.EXE tool is used to change the ACL, and if the registry key property is balnked
   #  out, it will reset to a default state.  Unfortunately, any other change to the registry key value has no effect
   #  on the ACL actually used by SCManager, so we are forced to use the Microsoft tool
   
   # grab the SDDL from the output of the command
   $SCMsddl = (c:\windows\system32\sc.exe sdshow SCMANAGER)[1]
   # if we get anything that doesn't look like SDDL, slap in our hard-coded default
   if (!($SCMsddl -like "D:(A*")) { $SCMsddl = $defaultSCMSDDL }
   write-debug "SCMANAGER SD = $SCMsddl"
   if ("add", "remove" -contains $operation) {
      # If we are adding/removing, pull out any existing entries first
      $modSCMsddl = acl-check-add-remove $SCMsddl "(A;;CCLCRPRC;;;$sid)" "remove"
      if ($operation -eq "add") {
         # this particular ACL has both DACL and SACL in the entry, se we need to split out the SACL as it must come
         #  after all the DACL entries
         $parts = $modSCMsddl -split "S:"
         $modSCMsddl = $parts[0] + "(A;;CCLCRPRC;;;$sid)S:" + $parts[1]
      }
      # smack it back down and hope for the best
      $result = c:\windows\system32\sc.exe sdset SCMANAGER $modSCMsddl
      # re-read after the change
      $SCMsddl = (c:\windows\system32\sc.exe sdshow SCMANAGER)[1]
      write-debug "SCMANAGER SD = $SCMsddl"
   }

   $valid = acl-check-add-remove $SCMsddl "(A;;CCLCRPRC;;;$sid)" "check"

   if (!$valid) {
      write-host "SCManager permission not set"
   }
   
   # Now that perms are applied, restart WMI so they take effect (it's better than re-booting!)
   # Note that several other services rely on WMI and there's no guarantee they will restart when it does
   #  but it hasn't broken anything in any of my test environments so far
   if ($start_services) {
      restart-service -DisplayName "Windows Management Instrumentation" -Force
   }
   
   # Note: the first time you model after setting perms, you may not get software.  It seems to work the second time...
} else {
   write-host "Group $mon_group does not exist so no permissions can be checked"
}

# removal of a local user we defer to the end, as it has to exist when we remove it from the local group
if ($wmiuser) {
   if ($remove_user) {
      write-host "Removing user $mon_user"
      $user = $localDirectory.Delete("User", $mon_user)
   }
}

