<#
.Synopsis
    Generate AD Report.
.Description
    Generate AD Report based on the fields selected from input.
.Example
    JSON input goes as follows.
        Computers
        Users
        Groups
        Other

# $reportType = 'computer'

# $computerOption = 1  # =>> "All Computers",
# $computerOption = 2  # =>> "Computer with specified GUID",
    $cmpSearchWithGuid = "d0983cf8-007c-466f-830a-303a0f360a07"

# $computerOption = 3  # =>> "Computer with specified name",
    $cmpSearchWithName = "computer Name"

# $computerOption = 4  # =>> "Computers created in last 30 days.",
    $cmpCreatedNoOfDays = 30

# $computerOption = 5  # =>> "Computers deleted in last 30 days.",
    $cmpDeletedNoOfDays = 30

# $computerOption = 6  # =>> "Computers that are direct members of specified groups",
    $cmpSearchWithGroupName = "group Name"

# $computerOption = 7  # =>> "Computers that are direct or indirect members of specified groups",
    $cmpSearchWithGroupName = "group Name"

# $computerOption = 8  # =>> "Computers running Specific Operating System",
    $cmpWin10      = $false # $true | $false
    $cmpWin2k8r2   = $false # $true | $false
    $cmpWin2012r2  = $false # $true | $false
    $cmpWin2016    = $false # $true | $false
    $cmpWin2019    = $false # $true | $false


# $computerOption = 9  # =>> "Computers that are not protected from deletion"
# $computerOption = 10 # =>> "Computers that are protected from deletion"
# $computerOption = 11 # =>> "Computers that have never logged on for 60 days"
# $computerOption = 12 # =>> "Disabled computers"
# $computerOption = 13 # =>> "Enabled computers"
# $computerOption = 14 # =>> 
# $computerOption = 15 # =>> 
# $computerOption = 16 # =>> 
# $computerOption = 17 # =>> 
# $computerOption = 18 # =>> 


# $reportType = 'user'

# $userOption = "1"  # =>>  "All users",
# $userOption = "2"  # =>>  "Deleted users",
# $userOption = "3"  # =>>  "Enabled users",
# $userOption = "4"  # =>>  "Disabled users",
# $userOption = "5"  # =>>  "User with specified employee ID",
# $userOption = "6"  # =>>  "User with specified GUID",
# $userOption = "7"  # =>>  "User with Specified name",
# $userOption = "8"  # =>>  "User with specified SID",
# $userOption = "9"  # =>>  "User created in the last X days",
# $userOption = "10" # =>>  "User modified in last X days",
# $userOption = "11" # =>>  "Users that are direct members of specified group",
# $userOption = "12" # =>>  "Users that are directly and indirectly members of specified group",
# $userOption = "13" # =>>  "Users that cannot change their passwords",
# $userOption = "14" # =>>  "Users that have not logged on for X days",
# $userOption = "15" # =>>  "Users that will expire in next X days",
# $userOption = "16" # =>>  "Users with locked out accounts",
# $userOption = "17" # =>>  "Users with passwords that never expire",
# $userOption = "18" # =>>  "Users with no logon script",
# $userOption = "19" # =>>  "Users with specified logon script"


# $reportType = 'group'

# $groupOption = "1"  # =>> "All Groups",
# $groupOption = "2"  # =>> "Domain Local Groups",
# $groupOption = "3"  # =>> "Global Groups",
# $groupOption = "4"  # =>> "Security groups",
# $groupOption = "5"  # =>> "Universal groups",
# $groupOption = "6"  # =>> "Group with specified GUID",
# $groupOption = "7"  # =>> "Group with specified name",
# $groupOption = "8"  # =>> "Group with specified SID",
# $groupOption = "9"  # =>> "Group created in last 30 days",
# $groupOption = "10" # =>> "Groups deleted in last 30 days",
# $groupOption = "11" # =>> "Groups modified in last 30 days",
# $groupOption = "12" # =>> "Groups that are direct members of specified group",
# $groupOption = "13" # =>> "Groups that are not protected from deletion ",
# $groupOption = "14" # =>> "Groups that are protected from deletion",
# $groupOption = "15" # =>> "Groups that do not contains specified member",
# $groupOption = "16" # =>> "Groups with specified member",
# $groupOption = "17" # =>> "Groups with no members"

# $reportType = 'gpo'

# $gpoOption = "1" # =>> "All GPOs"
# $gpoOption = "2" # =>> "GPO with specified Unique ID"
# $gpoOption = "3" # =>> "GPOs created in last 30 days"
# $gpoOption = "4" # =>> "GPOs modified in last 30 days"
# $gpoOption = "5" # =>> "GPOs with all settings disabled"
# $gpoOption = "6" # =>> "GPOs with all settings enabled"
# $gpoOption = "7" # =>> "GPOs with computer settings disabled"
# $gpoOption = "8" # =>> "GPOs with user settings disabled"


# 'Select Attributes' section >> this option lets users select all or custom attributes that to be generated in the report.
$OptionType = "selectAll" # "selectAll" | "customFields"

$OptionType = 'selectAll' # will set all custom attributes to $true automatically

$OptionType = "customFields"

# for computer

$cmpCreationDate = $false # $true | $false
$cmpDNShostName = $false # $true | $false
$cmpName = $false # $true | $false
$cmpOS = $false # $true | $false
$cmpParentContainer = $false # $true | $false
$cmpServicePack = $false # $true | $false
$cmpPwdAge = $false # $true | $false
$cmpPwdLastCh = $false # $true | $false
$cmpLstLgnDt = $false # $true | $false
$cmpLstLgnDC = $false # $true | $false
$cmpGrpMemberShip = $false # $true | $false
$cmpDistinguishedName = $false # $true | $false
$cmpGUID = $false # $true | $false
$cmpSID = $false # $true | $false
$cmpAccidentalDeletionProtection = $false # $true | $false

# for user

$userCreationDate  = $false # $true | $false
$userDisplayName  = $false # $true | $false
$userEmailAddress  = $false # $true | $false
$userEmployeeID  = $false # $true | $false
$userFirstName  = $false # $true | $false
$userLastName  = $false # $true | $false
$userIsAccountLocked  = $false # $true | $false
$userIsAccountDisabled  = $false # $true | $false
$userExpirationDate  = $false # $true | $false
$userPwdChNxtLgn  = $false # $true | $false
$userPassWordAge  = $false # $true | $false
$userPwdExpDate  = $false # $true | $false
$userPwdLstCh  = $false # $true | $false
$userPwdNvrExp  = $false # $true | $false
$userCntChPwd  = $false # $true | $false
$userNm  = $false # $true | $false

# for group

$groupCreationDate = $false # $true | $false
$groupDisplayName = $false # $true | $false
$groupScope = $false # $true | $false
$groupType = $false # $true | $false
$groupModificationDate = $false # $true | $false
$groupParentContainer = $false # $true | $false
$groupMembershipAll = $false # $true | $false
$groupMemberShipDirect = $false # $true | $false
$groupMembershipIndirect = $false # $true | $false
$groupCntMemFrmExtDomain = $false # $true | $false
$groupMemAll = $false # $true | $false
$groupMemDirect = $false # $true | $false
$groupCriticalSysObj = $false # $true | $false
$groupIsDeleted = $false # $true | $false
$groupDistinguishedName = $false # $true | $false
$groupGUID = $false # $true | $false
$groupLastKnownLocation = $false # $true | $false
$groupAccidentalDeletionProtection = $false # $true | $false
$groupSID = $false # $true | $false

# for gpo

$gpoCreationDate = $false # $true | $false
$gpoDisplayName = $false # $true | $false
$gpoModificationDate = $false # $true | $false
$gpoParentContainer = $false # $true | $false
$gpoStatus = $false # $true | $false
$gpoComputerVersion = $false # $true | $false
$gpoUserVersion = $false # $true | $false
$gpoDistinguishedName = $false # $true | $false
$gpoGUID = $false # $true | $false
$gpoSYSVOLFilePath = $false # $true | $false





$cmpSearchWithGuid
$cmpSearchWithName
$cmpCreatedNoOfDays
$cmpDeletedNoOfDays
$cmpSearchWithGroupName
$cmpWin10
$cmpWin2k8r2
$cmpWin2012r2
$cmpWin2016
$cmpWin2019

$cmpNvrLoggedOnDays
$userSearchWithEmployeeID
$userSearchWithGuid
$userSearchWithName
$userSearchWithSID
$userCreatedNoDays
$userDeletedNoDays
$userDirectGroupMemShip
$userInDirectGroupMemship
$userNotloggedonDays
$userExpiryOnDays
$userSearchwithLogonScriptName
$groupSearchWithGUID
$groupSearchWithName
$groupSearchWithSID
$groupCreatedDays
$groupDeletedDays
$groupModifiedDays
$groupDirectMemship
$groupSearchForMemberExclude
$groupSearchForMember
$gpoSearchWithUID
$optionType
$cmpCreationDate
$cmpDNShostName
$cmpName
$cmpOS
$cmpParentContainer
$cmpServicePack
$cmpPwdAge
$cmpPwdLastCh
$cmpLstLgnDt
$cmpLstLgnDC
$cmpGrpMemberShip
$cmpDistinguishedName
$cmpGUID
$cmpSID
$cmpAccidentalDeletionProtection
$cmpCreationDate1
$cmpDNShostName1
$cmpName1
$cmpOS1
$cmpParentContainer1
$cmpServicePack1
$cmpPwdAge1
$cmpPwdLastCh1
$cmpLstLgnDt1
$cmpLstLgnDC1
$cmpGrpMemberShip1
$cmpDistinguishedName1
$cmpGUID1
$cmpSID1
$cmpAccidentalDeletionProtection1
$userCreationDate
$userDisplayName
$userEmailAddress
$userEmployeeID
$userFirstName
$userLastName
$userIsAccountLocked
$userIsAccountDisabled
$userExpirationDate
$userPwdChNxtLgn
$userPassWordAge
$userPwdExpDate
$userPwdLstCh
$userPwdNvrExp
$userCntChPwd
$userNm
$userCreationDate1
$userDisplayName1
$userEmailAddress1
$userEmployeeID1
$userFirstName1
$userLastName1
$userIsAccountLocked1
$userIsAccountDisabled1
$userExpirationDate1
$userPwdChNxtLgn1
$userPassWordAge1
$userPwdExpDate1
$userPwdLstCh1
$userPwdNvrExp1
$userCntChPwd1
$userNm1
$groupCreationDate
$groupDisplayName
$groupScope
$groupType
$groupModificationDate
$groupParentContainer
$groupMembershipAll
$groupMemberShipDirect
$groupMembershipIndirect
$groupCntMemFrmExtDomain
$groupMemAll
$groupMemDirect
$groupCriticalSysObj
$groupIsDeleted
$groupDistinguishedName
$groupGUID
$groupLastKnownLocation
$groupAccidentalDeletionProtection
$groupSID
$groupCreationDate1
$groupDisplayName1
$groupScope1
$groupType1
$groupModificationDate1
$groupParentContainer1
$groupMembershipAll1
$groupMemberShipDirect1
$groupMembershipIndirect1
$groupCntMemFrmExtDomain1
$groupMemAll1
$groupMemDirect1
$groupCriticalSysObj1
$groupIsDeleted1
$groupDistinguishedName1
$groupGUID1
$groupLastKnownLocation1
$groupAccidentalDeletionProtection1
$groupSID1
$gpoCreationDate
$gpoDisplayName
$gpoModificationDate
$gpoParentContainer
$gpoStatus
$gpoComputerVersion
$gpoUserVersion
$gpoDistinguishedName
$gpoGUID
$gpoSYSVOLFilePath
$gpoCreationDate1
$gpoDisplayName1
$gpoModificationDate1
$gpoParentContainer1
$gpoStatus1
$gpoComputerVersion1
$gpoUserVersion1
$gpoDistinguishedName1
$gpoGUID1
$gpoSYSVOLFilePath1



#>

# #AD Report Option Type
# $ErrorActionPreference = "Stop"
# $reportType = 'computer'  # 'computer' | 'user' | 'group' | 'gpo'
# $computerOption = 1 # dropDown options with enum list of choices 1 to 13
# $userOption = 1 # drop down options with enum list of choices 1 to 19
# $groupOption = 1 # drop down options with enum list of choices 1 to 17
# $gpoOption = 1 # drop down options with enum list of choices 1 to 8

<# Architecture check started and PS changed to the OS compatible #>
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    #write-warning "Excecuting the script under 64 bit powershell"
    if ($myInvocation.Line) {
        &"$env:systemroot\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile $myInvocation.Line
    }
    else {
        &"$env:systemroot\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -file "$($myInvocation.InvocationName)" $args
    }
    exit $lastexitcode
}
<#Architecture check completed #>

<# Compatibility check if found incompatible will exit #>
try {
    [double]$OSVersion = [Environment]::OSVersion.Version.ToString(2)
    $PSVersion = $PSVersionTable.PSVersion
    if (($OSVersion -lt 6.1) -or ($PSVersion.Major -lt 2)) {
        Write-Output "[MSG: System is not compatible with the requirement. Either Resource is below Windows 7 / Windows 2008R2 or Powershell version is lower than 2.0"
        Exit
    }
}
catch { Write-Output "[MSG: ERROR : $($_.Exception.message)]" }
<# Compatibility Check Code Ends #>

<#---------------------------------------------------------#>
<#-------------- Input Validation -------------------------#>
<#---------------------------------------------------------#>




<#---------------------------------------------------------#>
<#------------ user defined functions ---------------------#>
<#---------------------------------------------------------#>

function LogMessage {
    param($str)
    Write-Output "=>> $str`n"
}

function Get-WMIInfo {
    [CmdletBinding()]
    param($class, $filter)
    
    try {
        if ($null -ne $filter) {
            Get-CimInstance -ClassName $class -ErrorAction Stop -Filter "$filter"
        }
        else {
            Get-CimInstance -ClassName $class -ErrorAction Stop
        }

    }
    catch [System.Management.Automation.CommandNotFoundException] {

        if ($null -ne $filter) {
            Get-WmiObject -Class $class -Filter "$filter" -ErrorAction Stop
        }
        else {
            Get-WmiObject -Class $class -ErrorAction Stop
        }
        
    }
    catch {
        Write-Error "ERROR: Get-WmiInfo : $($_.Exception.Message)"
    }
}

function LegacyOSCheck {
    # check windows NT kernel version
    [double]$OSVersion = [Environment]::OSVersion.Version.ToString(2)
    if ( $OSVersion -lt 6.1 ) {
        return $true
    }
    return $false
}

function DomainControllerCheck {
    # check if the machine is domain controller or not.
    $osInfo = Get-WmiInfo -class Win32_OperatingSystem -ErrorAction SilentlyContinue

    if (-not $osInfo) {
        # if wmi/cim class returns nothing
        return $false
    }

    if ($osInfo.ProductType -ne 2) {
        # if Machine is not domain controller
        return $false
    }

    return $true
}

function ADWSServiceCheckStatus {

    $serviceName = 'adws'
    
    try {
        $adwsSvcObj = Get-WMIInfo -class "Win32_Service" -filter "name='$serviceName'" -ErrorAction Stop
    }
    catch {
        LogMessage "[Error]:: $($_.Exception.Message)"
        exit
    }

    if ($adwsSvcObj) {
        return $adwsSvcObj
    }
    else {
        return $null
    }


}

function NTDSServiceCheckStatus {

    
    $serviceName = 'NTDS'
    
    try {
        $ntdsSvcObj = Get-WMIInfo -class "Win32_Service" -filter "name='$serviceName'" -ErrorAction Stop
    }
    catch {
        LogMessage "[Error]:: $($_.Exception.Message)"
        exit
    }

    if ($ntdsSvcObj) {
        return $ntdsSvcObj
    }
    else {
        return $null
    }

}

function ADServicePreCheck {
    $ntdsSvcObj = NTDSServiceCheckStatus
    $adwsSvcObj = ADWSServiceCheckStatus 

    if (-not $ntdsSvcObj) {
        LogMessage "NTDS service not found.exiting the script."
        exit
    }
    
    if (-not $adwsSvcObj) {
        LogMessage "ADWS service not found.exiting the script."
        exit        
    }

    if (($ntdsSvcObj.State -ne "Running") -or ($adwsSvcObj.State -ne "Running") ) {
        
        LogMessage "[ERROR]:: one of the 'NTDS' or 'ADWS' Service are not running. Cannot continue further and generate AD report. exiting the script."
        # display the services
        ($ntdsSvcObj, $adwsSvcObj) | Select-Object Caption, Name, State, StartMode | Format-List
        exit
    }

    # to do service disable handler

}

function SysVolShareCheck {
    $netShare = Invoke-Expression "net share 2>&1"
    $SysVolShare = $netShare | Where-Object { "$_".trim() -like "SYSVOL*" }
    if ($SysVolShare) {
        return $true
    }
    else {
        return $false
    }
}

function NetLogonShareCheck {
    $netShare = Invoke-Expression "net share 2>&1"
    $NetLogonShare = $netShare | Where-Object { "$_".trim() -like "NETLOGON*" }
    
    if ($NetLogonShare) {
        return $true
    }
    else {
        return $false
    }

}

<# will define all the computer sub routines here #>
# 1. all computers

function GetCmpAllComputers {
    [CmdletBinding()]
    
    param ()

    try {

        $allComputers = Get-ADComputer -filter "*" -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer
    
}

function getCmpwithGUID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $guid
    )
    
    try {
        
        $allComputers = Get-ADComputer -Filter "ObjectGUID -eq '$guid'" -ErrorAction Stop
    }
    catch {
        #YTD
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpWithName {
    param(
        [Parameter(Mandatory = $true)]    
        $name
    )

    try {

        $allComputers = Get-ADComputer -filter "Name -eq '$name'" -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpCreatedinLastXdays {
    param($days)
    try {

        $date = (Get-Date).AddDays(- $days)
        $allComputers = Get-ADComputer -filter { whenCreated -ge $date } -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpDeletedinLastXdays {

    try {

        $allComputers = Get-ADComputer -filter "*" -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpDirectMemberShip {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $GroupName
    )
    try {
        $adGroup = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue
        $allComputers = Get-ADGroupMember $adGroup | 
        Where-Object { $_.objectclass -eq 'computer' } | ForEach-Object { Get-ADComputer $_  -properties * }
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpDirectIndirectMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $GroupName
    )
    try {
        $allComputers = Get-ADGroupMember $adGroup -Recursive | 
        Where-Object { $_.objectclass -eq 'computer' } | ForEach-Object { Get-ADComputer $_ -properties * }
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer
}

function getCmpRunningSpecificOS {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $os
    )

    $allComputers = @()

    try {
        # if nothing is selected then set windows 10 computers as default
        if (-not $($cmpWin10 -or $cmpWin2012r2 -or $cmpWin2016 -or $cmpWin2019 -or $cmpWin2k8r2)) {
            $cmpWin10 = $true
        }

        if ($cmpWin10) {
            $cmpWin10Computers = Get-ADComputer -filter { OperatingSystem -like "*windows*10*" } -properties "*" -ErrorAction Stop
            $allComputers += $cmpWin10Computers
        }

        if ($cmpWin2k8r2) {
            $cmpWin2k8r2Computers = Get-ADComputer -filter { OperatingSystem -like "*windows*server*2008*r2*" } -properties "*" -ErrorAction Stop
            $allComputers += $cmpWin2k8r2Computers
        }

        if ($cmpWin2012r2) {
            $cmpWin2012r2Computers = Get-ADComputer -filter { OperatingSystem -like "*Windows*server*2012*r2*" } -properties "*" -ErrorAction Stop
            $allComputers += $cmpWin2012r2Computers
        }

        if ($cmpWin2016) {
            $cmpWin2016Computers = Get-ADComputer -filter { OperatingSystem -like "*Windows*server*2016*" } -properties "*" -ErrorAction Stop
            $allComputers += $cmpWin2016Computers
        }

        if ($cmpWin2019) {
            $cmpWin2019Computers = Get-ADComputer -filter { OperatingSystem -like "windows*server*2019*" } -properties "*" -ErrorAction Stop
            $allComputers += $cmpWin2019Computers
        }

        # $allComputers = Get-ADComputer -filter {OperatingSystem -like } -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpProtectedFromDeletion {

    try {

        $allComputers = Get-ADComputer -Filter * -Properties * | Where-Object { $_.ProtectedFromAccidentalDeletion -eq $true }

    }
    catch {
        # YTD
        Write-Error $_
    }
    if ($allComputers) {
        GetSelectedAttributes -InputObject $allComputers -Computer
    }
}

function getCmpNotProtectedFromDeletion {
    try {

        $allComputers = Get-ADComputer -Filter * -Properties * | Where-Object { $_.ProtectedFromAccidentalDeletion -ne $true }

    }
    catch {
        # YTD
        Write-Error $_
    }
    if ($allComputers) {
        GetSelectedAttributes -InputObject $allComputers -Computer
    }
}

function getCmpNvrLoggedinXdays {

    param($days)
    try {
        $date = (Get-Date).AddDays(- $days)
        $allComputers = Get-ADComputer -filter "LastLogonDate -gt '$date'" -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpDisabled {
    try {

        $allComputers = Get-ADComputer -filter "Enabled -eq '$true'" -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer
}

function getCmpEnabled {
    
    try {

        $allComputers = Get-ADComputer -filter "Enabled -eq '$true'" -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer
}

<# computer sub routines end #>

<# will define all the user sub routines here #>
<# user sub routines end #>

<# will define all the group sub routines here #>
<# group sub routines end #>

<# will define all the user sub routines here #>
<# user sub routines end #>

<# section: filter out selected attributes. utility functions #> 

function GetComputerSelectAttributes {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject
    )
    
    if ($null -eq $optionType) {
        $optionType = 'selectAll'
    }

    if ($optionType -eq 'selectAll') {

        $cmpCreationDate = $true # whenCreated
        $cmpDNShostName = $true # DNSHostName
        $cmpName = $true # Name
        $cmpOS = $true # OperatingSystem
        $cmpParentContainer = $true # Select-Object @{n='ParentContainer';e={$_.distinguishedname -replace '^.+?,(CN|OU.+)','$1'}}
        $cmpServicePack = $true # OperatingSystemServicePack
        $cmpPwdAge = $true # 
        $cmpPwdLastCh = $true
        $cmpLstLgnDt = $true
        $cmpLstLgnDC = $true
        $cmpGrpMemberShip = $true
        $cmpDistinguishedName = $true
        $cmpGUID = $true
        $cmpSID = $true
        $cmpAccidentalDeletionProtection = $true
    
    }

    $Attributes = @( )

    if ($cmpName) {
        $Attributes += "Name"
    }
    
    if ($cmpCreationDate) {
        $Attributes += "whenCreated"

    }

    if ($cmpDNShostName) {
        $Attributes += "DNSHostName"
    }

    if ($cmpOS) {
        $Attributes += "OperatingSystem"
    }

    if ($cmpParentContainer) {
        $Attributes += "ParentContainer"
    }

    if ($cmpServicePack) {
        $Attributes += "OperatingSystemServicePack"
    }

    if ($cmpPwdAge) {
        $Attributes += "PasswordLastSet" # to be modified.
    }

    if ($cmpPwdLastCh) {
        $Attributes += "PasswordLastSet1"
    }

    if ($cmpLstLgnDt) {
        $Attributes += "LastLogonDate"
    }

    if ($cmpLstLgnDC) {
        $Attributes += "LastLogonDate1"
    }

    if ($cmpGrpMemberShip) {
        $Attributes += "MemberOf"
    }

    if ($cmpDistinguishedName) {
        $Attributes += "DistinguishedName"
    }

    if ($cmpGUID) {
        $Attributes += "ObjectGUID"
    }

    if ($cmpSID) {
        $Attributes += "objectSid"
    }

    if ($cmpAccidentalDeletionProtection) {
        $Attributes += "ProtectedFromAccidentalDeletion"
    }

    if ($Attributes.Count -eq 0) {
        $Attributes += "Name"
    }

    try {
        $computerObj = $InputObject | Select-Object $Attributes -ErrorAction Stop
        return $computerObj
    }
    catch {
        Write-Error $($_.Exception.Message)
    }

}

function GetUserSelectAttributes {
    <# get selected attributes for user ad object type #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $InputObject
    )


}

function GetGroupSelectAttributes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $InputObject
    )
}

function GetGPOSelectAttributes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject
    )


}

function GetSelectedAttributes {  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject,
        [switch]$Computer,
        [switch]$User,
        [switch]$Group,
        [switch]$GPO
    )

    if ($Computer) {
        return $(GetComputerSelectAttributes -InputObject $InputObject)
    }

    if ($User) {
        return $(GetUserSelectAttributes -InputObject $InputObject)
    }

    if ($Group) {
        return $(GetGroupSelectAttributes -InputObject $InputObject)
    }

    if ($GPO) {
        return $(GetGPOSelectAttributes -InputObject $InputObject)
    }

}


<# section: filter out selected attributes #>
function Get-ADCustomComputerReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $computerOption
    )

    begin {

        $computerOption = [int]$computerOption

    }
    process {

        try {
            switch ($computerOption) {
            
                # 1. All Computers
                1 {
                    GetCmpAllComputers -ErrorAction Stop
                    break
                }
    
                # 2. "Computer with specified GUID"
                2 {
                    getCmpwithGUID -ErrorAction Stop
                }
    
                # 3. "Computer with specified name"
                3 {
                    getCmpWithName -ErrorAction Stop
                }
    
                # 4. "Computer created in last 30 days"
                4 {
                    getCmpCreatedinLastXdays -ErrorAction Stop
                }
    
                # 5. computers deleted in last 30 days
                5 {
                    getCmpDeletedinLastXdays -ErrorAction Stop
                }
    
                # 6. computers that are direct members of specified groups
                6 {
                    getCmpDirectMemberShip -ErrorAction Stop
                }
                
                # 7. computers that are direct and indirect members of specified groups
                7 {
                    getCmpDirectIndirectMembership -ErrorAction Stop
                }
    
                # 8. computers running specific operating system
                8 {
                    getCmpRunningSpecificOS -ErrorAction Stop
                }
    
                # 9. computers that are not protected from deletion
                9 {
                    getCmpNotProtectedFromDeletion -ErrorAction Stop
                }
    
                # 10. computers that are protected from deletion.
                10 {
                    getCmpProtectedFromDeletion -ErrorAction Stop
                }
    
                # 11. computers that are never logged on for 60 days
                11 {
                    getCmpNvrLoggedinXdays -ErrorAction Stop
                }
    
                # 12. disabled computers
                12 {
                    getCmpDisabled -ErrorAction Stop
                }
    
                # 13. enabled computers
                13 {
                    getCmpEnabled -ErrorAction Stop
                }
    
                Default {
                    LogMessage "invalid computer option selected."
                    break
                }
            }
        }
        catch {

        }

    }
    end {

    }


}

function Get-ADCustomUserReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $userOption
    )
    begin{
        $userOption = [int]$userOption
    }
    process{

        try{

            switch ($userOption) {
                condition {  }
                Default {}
            }

        }
        catch{
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }

    }
    end{

    }

}

function Get-ADCustomGroupReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $groupOption
    )

}

function Get-ADCustomGPOReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $gpoOption
    )
    
}

function Get-ADCustomReport {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $reportType
    )

    begin {

        $script:FinalReport = "" | Select-Object DisplayMessage, Report, ErrLog
        $script:FinalReport.DisplayMessage = @()
        $script:FinalReport.Report = @()
        $script:FinalReport.ErrLog = @()

    }
    process {
        try {
            switch ($reportType) {
    
                #case custom computer report.
                'computer' {
                    
                    Get-ADCustomComputerReport -computerOption $computerOption -ErrorAction Stop
                    break;
            
                }
            
                # Case custom user report.
                'user' {
            
                    Get-ADCustomUserReport -userOption $userOption -ErrorAction Stop
                    break;
            
                }
            
                # custom group report.
                'group' {
            
                    Get-ADCustomGroupReport -groupOption $groupOption -ErrorAction Stop
                    break;
            
                }
            
                # generate group policy custom report.
                'gpo' {
            
                    Get-ADCustomGPOReport -gpoOption $gpoOption -ErrorAction Stop
                    break;
            
                }
            
                # default case.
                default {
            
                    LogMessage "[ERROR]:: Invalid report type selected."
                    break;
            
                }
            }

        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }


    }
    end {

    }

}


#####################################################################
# user defined functions end ########################################
#####################################################################






#####################################################################
# controller logic main #############################################
#####################################################################

# step 1,2,3 : check if the machine has legacy os

$legacyOSFound = LegacyOSCheck

if ($legacyOSFound) {
    LogMessage "Legacy OS found."
    exit
}


# step 4 : check if the machine is a domain controller

$isMachineDomainController = DomainControllerCheck

if (-not $isMachineDomainController) {
    LogMessage "This machine is not a domain controller, exiting the script"
    exit
}

# step 5: 

ADServicePreCheck # Warning: this function has exit commands

# step 6:

$SysVolShared = SysVolShareCheck
$NetLogonShared = NetLogonShareCheck

if (-not ($SysVolShared -and $NetLogonShared)) {

    LogMessage "Sysvol or netlogon is not shared for this domain controller, Hence cannot proceed further." 
    LogMessage "SysVol shared : $SysVolShared"
    LogMessage "NetLogon Shared : $NetLogonShared"
    exit
}

# step 7:

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    LogMessage "Unable to Import ActiveDirectory Module. unable to proceed further."
    LogMessage "[ERROR]:: $($_.Exception.Message)"
    exit
}

# step 8,9,10,11 : Generate Custom AD Report

Get-ADCustomReport -reportType $reportType -ErrorAction Stop

# Step 12: Email the report feature

<# ---  To be tested and implemented. --- #>