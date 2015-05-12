########################################################
# Functions to add permissions to user
########################################################
 
function add_user([String]$username, [String]$pass='Install_new!') {
    $cmd = "NET USER $($username) $($pass) /ADD"
    cmd $cmd
}
 
function allow_access_to_winrm($username) {
    $sid = get_sid $username
    $sddl = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
    $sddl = add_sid_with_A_GA $sddl $sid
    Set-Item WSMan:\localhost\Service\RootSDDL -Value $sddl
}
 
function allow_access_to_powershell_session($username) {
    $sid = get_sid $username
    $sddl = (Get-PSSessionConfiguration -name Microsoft.PowerShell).SecurityDescriptorSddl
    $sddl = add_sid_with_A_GA $sddl $sid
    
    # Is not working throught remote. It throws:
    # Processing data from remote server failed with the following error message: 
    # The I/O operation has been aborted because of either a thread exit or an application request. 
    # For more information, see the about_Remote_Troubleshooting Help topic.
    Set-PSSessionConfiguration -name Microsoft.PowerShell -SecurityDescriptorSddl $sddl -Force
}
 
function cmd($command) {
    Write-Host $cmd;
    CMD.EXE /C $cmd;
}
 
function get_sid($username) {
    $objUser = New-Object System.Security.Principal.NTAccount($username)
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $strSID.Value
}
 
 
function add_user_to_group($username, $group) {
    $cmd = "NET LOCALGROUP `"$($group)`" `"$($username)`" /ADD";
    cmd $cmd;
}
 
 
function add_sid_with_A_GA($sddl, $sid) {
    # Modifies SDDL by adding to it new ACE (A;;GA;;;$sid)
    $security_descriptor = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList @($false, $false, $sddl);
 
    $security_descriptor.DiscretionaryAcl.AddAccess("Allow", $sid, 268435456,"None","None")
 
    # Convert the Security Descriptor back into SDDL
    $security_descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All);
}
 
function set_wmi_namespace_permission([String]$username, [String]$ns='root/CIMv2') {
    $ComputerName = hostname;
    $DomainName = (whoami).split('\')[0]; # current domain
 
    Set-WMINamespaceSecurity $ns add "$DomainName\$UserName" Enable,MethodExecute,ReadSecurity,RemoteAccess -computer $ComputerName;
}
 
 
# Copyright (c) Microsoft Corporation.  All rights reserved. 
# For personal use only.  Provided AS IS and WITH ALL FAULTS.
 
# Set-WmiNamespaceSecurity.ps1
# Example: Set-WmiNamespaceSecurity root/cimv2 add steve Enable,RemoteAccess
Function Set-WmiNamespaceSecurity {
 
Param ([parameter(Mandatory=$true,Position=0)][string] $namespace,
    [parameter(Mandatory=$true,Position=1)][string] $operation,
    [parameter(Mandatory=$true,Position=2)][string] $account,
    [parameter(Position=3)][string[]] $permissions = $null,
    [bool] $allowInherit = $false,
    [bool] $deny = $false,
    [string] $computer = ".",
    [System.Management.Automation.PSCredential] $credential = $null)
   
Process {
    $ErrorActionPreference = "Stop"
 
    if ($PSBoundParameters.ContainsKey("Credential")) {
        $remoteparams = @{ComputerName=$computer;Credential=$credential}
    } else {
        $remoteparams = @{ComputerName=$computerName}
    }
       
    $invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@"} + $remoteParams
 
    $output = Invoke-WmiMethod @invokeparams -Name GetSecurityDescriptor
    if ($output.ReturnValue -ne 0) {
        throw "GetSecurityDescriptor failed: $($output.ReturnValue)"
    }
 
    $acl = $output.Descriptor
    $OBJECT_INHERIT_ACE_FLAG = 0x1
    $CONTAINER_INHERIT_ACE_FLAG = 0x2
 
    $computerName = (Get-WmiObject @remoteparams Win32_ComputerSystem).Name
   
    if ($account.Contains('\')) {
        $domainaccount = $account.Split('\')
        $domain = $domainaccount[0]
        if (($domain -eq ".") -or ($domain -eq "BUILTIN")) {
            $domain = $computerName
        }
        $accountname = $domainaccount[1]
    } elseif ($account.Contains('@')) {
        $domainaccount = $account.Split('@')
        $domain = $domainaccount[1].Split('.')[0]
        $accountname = $domainaccount[0]
    } else {
        $domain = $computerName
        $accountname = $account
    }
 
    $getparams = @{Class="Win32_Account";Filter="Domain='$domain' and Name='$accountname'"}
 
    $win32account = Get-WmiObject @getparams
 
    if ($win32account -eq $null) {
        throw "Account was not found: $account"
    }
 
    switch ($operation) {
        "add" {
            if ($permissions -eq $null) {
                throw "-Permissions must be specified for an add operation"
            }
            $accessMask = Get-AccessMaskFromPermission($permissions)
   
            $ace = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
            $ace.AccessMask = $accessMask
            if ($allowInherit) {
                $ace.AceFlags = $OBJECT_INHERIT_ACE_FLAG + $CONTAINER_INHERIT_ACE_FLAG
            } else {
                $ace.AceFlags = 0
            }
                       
            $trustee = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
            $trustee.SidString = $win32account.Sid
            $ace.Trustee = $trustee
           
            $ACCESS_ALLOWED_ACE_TYPE = 0x0
            $ACCESS_DENIED_ACE_TYPE = 0x1
 
            if ($deny) {
                $ace.AceType = $ACCESS_DENIED_ACE_TYPE
            } else {
                $ace.AceType = $ACCESS_ALLOWED_ACE_TYPE
            }
 
            $acl.DACL += $ace.psobject.immediateBaseObject
        
        }
       
        "delete" {
            if ($permissions -ne $null) {
                throw "Permissions cannot be specified for a delete operation"
            }
       
            [System.Management.ManagementBaseObject[]]$newDACL = @()
            foreach ($ace in $acl.DACL) {
                if ($ace.Trustee.SidString -ne $win32account.Sid) {
                    $newDACL += $ace.psobject.immediateBaseObject
                }
            }
 
            $acl.DACL = $newDACL.psobject.immediateBaseObject
        }
       
        default {
            throw "Unknown operation: $operation`nAllowed operations: add delete"
        }
    }
 
    $setparams = @{Name="SetSecurityDescriptor";ArgumentList=$acl.psobject.immediateBaseObject} + $invokeParams
 
    $output = Invoke-WmiMethod @setparams
    if ($output.ReturnValue -ne 0) {
        throw "SetSecurityDescriptor failed: $($output.ReturnValue)"
    }
}
}
 
Function Get-AccessMaskFromPermission($permissions) {
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa374896%28v=vs.85%29.aspx
    $WBEM_ENABLE            = 1
    $WBEM_METHOD_EXECUTE = 2
    $WBEM_FULL_WRITE_REP   = 4
    $WBEM_PARTIAL_WRITE_REP              = 8
    $WBEM_WRITE_PROVIDER   = 0x10
    $WBEM_REMOTE_ACCESS    = 0x20
    $WBEM_RIGHT_SUBSCRIBE = 0x40
    $WBEM_RIGHT_PUBLISH      = 0x80
    $READ_CONTROL = 0x20000
    $WRITE_DAC = 0x40000
   
    $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE,$WBEM_METHOD_EXECUTE,$WBEM_FULL_WRITE_REP,
        $WBEM_PARTIAL_WRITE_REP,$WBEM_WRITE_PROVIDER,$WBEM_REMOTE_ACCESS,
        $READ_CONTROL,$WRITE_DAC
    $WBEM_RIGHTS_STRINGS = "Enable","MethodExecute","FullWrite","PartialWrite",
        "ProviderWrite","RemoteAccess","ReadSecurity","WriteSecurity"
 
    $permissionTable = @{}
 
    for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
        $permissionTable.Add($WBEM_RIGHTS_STRINGS[$i].ToLower(), $WBEM_RIGHTS_FLAGS[$i])
    }
   
    $accessMask = 0
 
    foreach ($permission in $permissions) {
        if (-not $permissionTable.ContainsKey($permission.ToLower())) {
            throw "Unknown permission: $permission</code>nValid permissions: $($permissionTable.Keys)"
        }
        $accessMask += $permissionTable[$permission.ToLower()]
    }
   
    $accessMask
}
 
########################################################
# Utility functions for login
########################################################
function credential([String]$user, [String]$password) {
    $pass = ConvertTo-SecureString –String $password –AsPlainText -Force
    New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $user, $pass
}
 
 
$ips = @{};
$ips['2012'] = '192.168.173.206';
$ips['2008'] = '192.168.240.181';
 
function login_to($name) {
   $server, $user = $name.Split(' ')
   $ip = $ips[$server];
   Write-Host "Logging to $($ip)";
   Enter-PSSession -ComputerName $ip -Credential $(credential $user 'Install_new!') -Authentication 'Basic'
}
 
function os_caption() {
    (Get-WmiObject -class Win32_OperatingSystem).Caption
}
 
 
<#
$pwd = 'Install_new!'
 
Invoke-Command -ComputerName 192.168.173.206 -Credential (credential Administrator $pwd) -Authentication basic -ScriptBlock { 2 + 2} 
# gives 4
Invoke-Command -ComputerName 192.168.173.206 -Credential (credential lpu1 $pwd) -ScriptBlock { 2 + 2}
# gives 4
winrs -r:192.168.173.206 -u:Administrator -p:$pwd 'powershell -command "2+2"'
# gives 4
winrs -r:192.168.173.206 -u:lpu1 -p:$pwd 'powershell -command "2+2"'
# Gives Winrs error: Access is denied.
#>