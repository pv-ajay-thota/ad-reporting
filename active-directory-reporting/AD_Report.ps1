

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

# $computerOption = 5  # =>> "Computers deleted recently.",

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
    $cmpNvrLoggedOnDays = 60 # for eaxample
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
$userModifiedNoDays
$userDirectGroupMemShip
$userInDirectGroupMemship
$userNotloggedonDays
$userExpiryOnDays
$userSearchwithLogonScriptName
$groupSearchWithGUID
$groupSearchWithName
$groupSearchWithSID
$groupCreatedDays
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


$usrProperties = @("*", "msDS-UserPasswordExpiryTimeComputed", "ScriptPath")
$cmpProperties = @("*")
$grpProperties = @("*")
# $gpoProperties = @("*")


<#---------------------------------------------------------#>
<#------------ user defined functions ---------------------#>
<#---------------------------------------------------------#>

function LogMessage {
    param($str)
    $Global:LogMsgVar += "=>> $str`n"
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
        $script:SysVolFilePath = ($SysVolShare -split " " | Where-Object { "$_".trim() -ne "" })[1]
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

function ConvertFromDN {
    param (
        [Parameter(Mandatory, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string[]]$dn
    )
    process {
        if ($dn) {
            $d = ""; $p = "";
            $dn -split '(?<!\\),' | ForEach-Object { 
                if ($_.StartsWith('DC=')) { 
                    $d += $_.Substring(3) + '.' 
                } 
                else { 
                    $p = $_.Substring(3) + '\' + $p 
                } 
            }
            Write-Output $($d.Trim('.') + '\' + $p.TrimEnd('\'))
        }
    }
}

function filterCSVInput {
    [CmdletBinding()]
    param($inputStr)
    $items = $inputStr -split ",(?=(?:[^\`"]*\`"[^\`"]*\`")*[^\`"]*$)" 
    $List = foreach ( $item in $items ) {
        $i = "$item".trim("`"", "'")
        if ($i -ne "") {
            $i
        }
    }

    $List = @($List)
    if ($List.Count -gt 0) {
        $List
    }
    else {
        LogMessage "[ERROR]:: invalid input. please provide valid input. `n`n$inputStr"
    }

}

# Process Custom Report Attributes and queries




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

        $cmpCreationDate = `
            $cmpDNShostName = `
            $cmpName = `
            $cmpOS = `
            $cmpParentContainer = `
            $cmpServicePack = `
            $cmpPwdAge = `
            $cmpPwdLastCh = `
            $cmpLstLgnDt = `
            $cmpLstLgnDC = `
            $cmpGrpMemberShip = `
            $cmpDistinguishedName = `
            $cmpGUID = `
            $cmpSID = `
            $cmpAccidentalDeletionProtection = $true
    
    }

    if (         
    ($cmpCreationDate -eq $false) -and
    ($cmpDNShostName -eq $false) -and
    ($cmpName -eq $false) -and
    ($cmpOS -eq $false) -and
    ($cmpParentContainer -eq $false) -and
    ($cmpServicePack -eq $false) -and
    ($cmpPwdAge -eq $false) -and
    ($cmpPwdLastCh -eq $false) -and
    ($cmpLstLgnDt -eq $false) -and
    ($cmpLstLgnDC -eq $false) -and
    ($cmpGrpMemberShip -eq $false) -and
    ($cmpDistinguishedName -eq $false) -and
    ($cmpGUID -eq $false) -and
    ($cmpSID -eq $false) -and
    ($cmpAccidentalDeletionProtection -eq $false)
    ) {
        # set default options to $true


        $cmpCreationDate = `
        $cmpDNShostName = `
        $cmpName = `
        $cmpOS = `
        $cmpLstLgnDt = `
        $cmpLstLgnDC = `
        $cmpGrpMemberShip = `
        $cmpDistinguishedName = `
        $cmpAccidentalDeletionProtection = $true
        
        # $cmpParentContainer = `
        # $cmpServicePack = `
        # $cmpPwdAge = `
        # $cmpPwdLastCh = `
        # $cmpGUID = `
        # $cmpSID = `

    }

    $InputObject | Select-Object @(

        $(    if ($cmpName) {
                @{n = "Name"; e = { $_.Name } }
            }
        ),  

        $(if ($cmpCreationDate) {
                @{n = "whenCreated"; e = { $_.whenCreated } }
            }),

        $(if ($cmpDNShostName) {
                @{n = "DNSHostName"; e = { $_.DNSHostName } }
            }),

        $(if ($cmpOS) {
                @{n = "OperatingSystem"; e = { $_.OperatingSystem } }
            }),

        $(if ($cmpParentContainer) {
                @{n = "ParentContainer"; e = { 
                        $_.distinguishedname -replace '^.+?,(CN|OU.+)', '$1'
                    } 
                }
            }),

        $(if ($cmpServicePack) {
                @{n = "OperatingSystemServicePack"; e = { $_.OperatingSystemServicePack } }
            }),

        $(if ($cmpPwdAge) {
                @{n = "PasswordAge"; e = { 

                        if ($_.PasswordLastSet) { 
                            "$(([timespan]( (Get-Date) - ([datetime]($_.PasswordLastSet)) )).Days) days ago" 
                        }

                    } 
                }
            }),

        $(if ($cmpPwdLastCh) {
                @{n = "PasswordLastSet"; e = { $_.PasswordLastSet } }
            }),

        $(if ($cmpLstLgnDt) {
                @{n = "LastLogonDate"; e = { $_.LastLogonDate } }
            }),

        $(if ($cmpLstLgnDC) {
                @{n = "LastLogonDC"; e = { $_.LastLogonDate } }
            }),

        $(if ($cmpGrpMemberShip) {
                @{n = "MemberOf"; e = { $_.MemberOf -join ";`n" } }
            }),

        $(if ($cmpDistinguishedName) {
                @{n = "DistinguishedName"; e = { $_.DistinguishedName } }
            }),

        $(if ($cmpGUID) {
                @{n = "ObjectGUID"; e = { $_.ObjectGUID } }
            }),

        $(if ($cmpSID) {
                @{n = "objectSid"; e = { $_.ObjectSid } }
            }),

        $(if ($cmpAccidentalDeletionProtection) {
                @{n = "ProtectedFromAccidentalDeletion"; e = {
                        $_.ProtectedFromAccidentalDeletion
                    } 
                }
            })
    ) -ErrorAction Stop

}

function GetUserSelectAttributes {
    <# get selected attributes for user ad object type #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $InputObject
    )

    if ($null -eq $optionType) {
        $optionType = 'selectAll'
    }

    if ($optionType -eq 'selectAll') {

        $userCreationDate = `
            $userDisplayName = `
            $userEmailAddress = `
            $userEmployeeID = `
            $userFirstName = `
            $userLastName = `
            $userIsAccountLocked = `
            $userIsAccountDisabled = `
            $userExpirationDate = `
            $userPwdChNxtLgn = `
            $userPassWordAge = `
            $userPwdExpDate = `
            $userPwdLstCh = `
            $userPwdNvrExp = `
            $userCntChPwd = `
            $userNm = $true

    }

    if (
            ($userCreationDate -eq $false) -and
            ($userDisplayName -eq $false) -and
            ($userEmailAddress -eq $false) -and
            ($userEmployeeID -eq $false) -and
            ($userFirstName -eq $false) -and
            ($userLastName -eq $false) -and
            ($userIsAccountLocked -eq $false) -and
            ($userIsAccountDisabled -eq $false) -and
            ($userExpirationDate -eq $false) -and
            ($userPwdChNxtLgn -eq $false) -and
            ($userPassWordAge -eq $false) -and
            ($userPwdExpDate -eq $false) -and
            ($userPwdLstCh -eq $false) -and
            ($userPwdNvrExp -eq $false) -and
            ($userCntChPwd -eq $false) -and
            ($userNm -eq $false)
    ) {
        # set the default options to $true

        $userCreationDate = `
        $userDisplayName = `
        $userEmailAddress = `
        $userEmployeeID = `
        $userFirstName = `
        $userLastName = `
        $userIsAccountLocked = `
        $userIsAccountDisabled = `
        $userPwdChNxtLgn = `
        $userPwdExpDate = `
        $userPwdLstCh = `
        $userNm = $true
        
        # $userExpirationDate = `
        # $userPassWordAge = `
        # $userPwdNvrExp = `
        # $userCntChPwd = `
    }

    try {
        $InputObject | Select-Object @(

            $(if ($userNm) {
                    @{n = "Name"; e = { $_.Name } } 
                }),

            $(if ($userCreationDate) {
                    @{n = "whenCreated"; e = { $_.whenCreated } } 
                }),

            $(if ($userDisplayName) {
                    @{n = "DisplayName"; e = { $_.DisplayName } } 
                }),

            $(if ($userEmailAddress) {
                    @{n = "EmailAddress"; e = { $_.EmailAddress } } 
                }),

            $(if ($userEmployeeID) {
                    @{n = "EmployeeID"; e = { $_.EmployeeID } } 
                }),

            $(if ($userFirstName) {
                    @{n = "Surname"; e = { $_.GivenName } } 
                }),

            $(if ($userLastName) {
                    @{n = "LastName"; e = { $_.Surname } } 
                }),

            $(if ($userIsAccountLocked) {
                    @{n = "LockedOut"; e = { $_.LockedOut } } 
                }),

            $(if ($userIsAccountDisabled) {
                    @{n = "Disabled"; e = { -not $_.Enabled } } 
                }),

            $(if ($userExpirationDate) {
                    @{n = "AccountExpirationDate"; e = { $_.AccountExpirationDate } } 
                }),

            $(if ($userPwdChNxtLgn) {
                    @{n = "pwd_changeNextLogin"; e = { if (-not $_.PasswordLastSet) { 
                                $true 
                            }
                            else { 
                                $false 
                            } 
                        } 
                    } 
                }),

            $(if ($userPassWordAge) {
                    @{n = "PasswordAge"; e = { if ($_.PasswordLastSet) { "$(([timespan]( (Get-Date) - ([datetime]($_.PasswordLastSet)) )).Days) days ago" } } } 
                }),

            $(if ($userPwdExpDate) {
                    @{n = "PasswordExpiresOn"; e = { 

                            if ($_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $False) {
                                [datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")
                            }

                        } 
                    }
                }),

            $(if ($userPwdLstCh) {
                    @{n = "PasswordLastSet"; e = {
                            $_.PasswordLastSet
                        } 
                    } 
                }),

            $(if ($userPwdNvrExp) {
                    @{n = "PasswordNeverExpires"; e = {
                            $_.PasswordNeverExpires
                        } 
                    } 
                }),

            $(if ($userCntChPwd) {
                    @{n = "CannotChangePassword"; e = {
                            $_.CannotChangePassword
                        } 
                    } 
                })
                
        ) -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: $($_.Exception.Message)"
    }

}

function GetGroupSelectAttributes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $InputObject
    )

    if ($null -eq $optionType) {
        $optionType = 'selectAll'
    }

    if ($optionType -eq 'selectAll') {
        $groupCreationDate = `
            $groupDisplayName = `
            $groupScope = `
            $groupType = `
            $groupModificationDate = `
            $groupParentContainer = `
            $groupMembershipAll = `
            $groupMemberShipDirect = `
            $groupMembershipIndirect = `
            $groupCntMemFrmExtDomain = `
            $groupMemAll = `
            $groupMemDirect = `
            $groupCriticalSysObj = `
            $groupIsDeleted = `
            $groupDistinguishedName = `
            $groupGUID = `
            $groupLastKnownLocation = `
            $groupAccidentalDeletionProtection = `
            $groupSID = $true
    }

    if (
        ($groupCreationDate = $false) -and
        ($groupDisplayName = $false) -and
        ($groupScope = $false) -and
        ($groupType = $false) -and
        ($groupModificationDate = $false) -and
        ($groupParentContainer = $false) -and
        ($groupMembershipAll = $false) -and
        ($groupMemberShipDirect = $false) -and
        ($groupMembershipIndirect = $false) -and
        ($groupCntMemFrmExtDomain = $false) -and
        ($groupMemAll = $false) -and
        ($groupMemDirect = $false) -and
        ($groupCriticalSysObj = $false) -and
        ($groupIsDeleted = $false) -and
        ($groupDistinguishedName = $false) -and
        ($groupGUID = $false) -and
        ($groupLastKnownLocation = $false) -and
        ($groupAccidentalDeletionProtection = $false) -and
        ($groupSID = $false)
    ) {
        # set the default options to $true

        $groupCreationDate = `
        $groupDisplayName = `
        $groupScope = `
        $groupType = `
        $groupMembershipAll = `
        $groupMemberShipDirect = `
        $groupMembershipIndirect = `
        $groupCntMemFrmExtDomain = `
        $groupDistinguishedName = `
        $groupAccidentalDeletionProtection = `
        $groupSID = $true

        
        # $groupModificationDate = `
        # $groupParentContainer = `
        # $groupMemAll = `
        # $groupMemDirect = `
        # $groupCriticalSysObj = `
        # $groupIsDeleted = `
        # $groupGUID = `
        # $groupLastKnownLocation = `

    }

    try {
        $InputObject | Select-Object @(
            $( if ($groupCreationDate) {
                    @{n = "groupCreationDate"; e = {
                            $_.whenCreated
                        }
                    }
                }
            ),
            $( if ($groupDisplayName) {
                    @{n = "DisplayName"; e = {
                            $_.DisplayName
                        }
                    }
                }
            
            ),
            $( if ($groupScope) {
                    @{n = "GroupScope"; e = {
                            $_.GroupScope
                        }
                    }
                }
            
            ),
            $( if ($groupType) {
                    @{n = "groupType"; e = {
                            $_.groupType
                        }
                    }
                }
            ),
            $( if ($groupModificationDate) {
                    @{n = "Modified"; e = {
                            $_.Modified
                        }
                    }
                }
            
            ),
            $( if ($groupParentContainer) {
                    @{n = "ParentContainer"; e = { 
                            $_.distinguishedname -replace '^.+?,(CN|OU.+)', '$1'
                        } 
                    }
                }
            
            ),
            $( if ($groupMembershipAll) {
                    @{n = "groupMembershipAll"; e = {
                        (Get-ADGroup -Filter "member -RecursiveMatch '$($_.DistinguishedName)'" -ErrorAction Stop | 
                            Select-Object -ExpandProperty DistinguishedName | ConvertFromDN) -join "`n"
                        }
                    }
                }
            
            ),
            $( if ($groupMemberShipDirect) {
                    @{n = "groupMemberShipDirect"; e = {
                        ($_.MemberOf | ConvertFromDN) -join "`n"
                        }
                    }
                }
            
            ),
            $( if ($groupMembershipIndirect) {
                    @{n = "groupMembershipIndirect"; e = {
                            $dm = $_.MemberOf
                            ((Get-ADGroup -Filter "member -RecursiveMatch '$($_.DistinguishedName)'" -ErrorAction Stop | 
                                Select-Object -ExpandProperty DistinguishedName) | 
                            Where-Object { $_ -notin $dm } | 
                            ConvertFromDN 
                            ) -join "`n"
                        }
                    }
                }
            ),
            $( if ($groupCntMemFrmExtDomain) {
                    @{n = "groupCntMemFrmExtDomain"; e = {

                        }
                    }
                }
            
            ),
            $( if ($groupMemAll) {
                    @{n = "groupMemAll"; e = {
                        (Get-ADGroupMember $_ -Recursive | Select-Object -ExpandProperty DistinguishedName | ConvertFromDN) -join "`n"
                        }
                    }
                }
            
            ),
            $( if ($groupMemDirect) {
                    @{n = "groupMemDirect"; e = {
                        (Get-ADGroupMember $_ | Select-Object -ExpandProperty DistinguishedName | ConvertFromDN) -join "`n"
                        }
                    }
                }
            
            ),
            $( if ($groupCriticalSysObj) {
                    @{n = "isCriticalSystemObject"; e = {
                            $_.isCriticalSystemObject
                        }
                    }
                }
            
            ),
            $( if ($groupIsDeleted) {
                    @{n = "groupIsDeleted"; e = {
                            $_.isDeleted
                        }
                    }
                }
            
            ),
            $( if ($groupDistinguishedName) {
                    @{n = "DistinguishedName"; e = {
                            $_.DistinguishedName
                        }
                    }
                }
            
            ),
            $( if ($groupGUID) {
                    @{n = "ObjectGUID"; e = {
                            $_.ObjectGUID
                        }
                    }

                }
            
            ),
            $( if ($groupLastKnownLocation) {
                    @{n = "LastKnowParent"; e = {
                            $_.LastKnownParent
                        }
                    }
                }
            ),
            $( if ($groupAccidentalDeletionProtection) {
                    @{n = "ProtectedFromAccidentalDeletion"; e = {
                            $_.ProtectedFromAccidentalDeletion
                        }
                    }
                }
            
            ),
            $( if ($groupSID) {
                    @{n = "SID"; e = {
                            $_.SID
                        }
                    }
                }
            
            )
        )


    }
    catch {
        LogMessage "[ERROR]:: $($_.Exception.Message)"
    }






}

function GetGPOSelectAttributes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    if ($null -eq $optionType) {
        $optionType = 'selectAll'
    }

    if ($optionType -eq 'selectAll') {
        $gpoCreationDate = `
            $gpoDisplayName = `
            $gpoModificationDate = `
            $gpoParentContainer = `
            $gpoStatus = `
            $gpoComputerVersion = `
            $gpoUserVersion = `
            $gpoDistinguishedName = `
            $gpoGUID = `
            $gpoSYSVOLFilePath = $true
    }

    if (
        ($gpoCreationDate -eq $false) -and
        ($gpoDisplayName -eq $false) -and
        ($gpoModificationDate -eq $false) -and
        ($gpoParentContainer -eq $false) -and
        ($gpoStatus -eq $false) -and
        ($gpoComputerVersion -eq $false) -and
        ($gpoUserVersion -eq $false) -and
        ($gpoDistinguishedName -eq $false) -and
        ($gpoGUID -eq $false) -and
        ($gpoSYSVOLFilePath -eq $false)
    ) {
        # Set the default options to $true
        $gpoCreationDate = `
        $gpoDisplayName = `
        $gpoModificationDate = `
        $gpoParentContainer = `
        $gpoStatus = `
        $gpoComputerVersion = `
        $gpoUserVersion = `
        $gpoDistinguishedName = `
        $gpoGUID = `
        $gpoSYSVOLFilePath = $true

    }


    $InputObject | Select-Object @(
        $( if ($gpoCreationDate) {
                @{
                    n = "CreationTime";
                    e = {
                        $_.CreationTime
                    }
                }
            }),
        $( if ($gpoDisplayName) {
                @{
                    n = "DisplayName";
                    e = {
                        $_.DisplayName
                    }
                }
            }),
        $( if ($gpoModificationDate) {
                @{
                    n = "ModificationTime";
                    e = {
                        $_.ModificationTime
                    }
                }
            }),
        $( if ($gpoParentContainer) {
                @{
                    n = "ParentContainer";
                    e = {
                        "$($_.Path -replace '^.+?,(CN|OU.+)', '$1')"
                    }
                }
            }),
        $( if ($gpoStatus) {
                @{
                    n = "GpoStatus";
                    e = {
                        $_.GpoStatus
                    }
                }
            }),
        $( if ($gpoComputerVersion) {
                @{
                    n = "ComputerVersion";
                    e = {
                        "AD Version $($_.Computer.DSVersion) ; SysVolVersion $($_.Computer.SysVolVersion)"
                    }
                }
            }),
        $( if ($gpoUserVersion) {
                @{
                    n = "UserVersion";
                    e = {
                        "AD Version $($_.User.DSVersion) ; SysVolVersion $($_.User.SysVolVersion)"
                    }
                }
            }),
        $( if ($gpoDistinguishedName) {
                @{
                    n = "DistinguishedName";
                    e = {
                        $_.Path
                    }
                }
            }),
        $( if ($gpoGUID) {
                @{
                    n = "GUID";
                    e = {
                        $_.id
                    }
                }
            }),
        $( if ($gpoSYSVOLFilePath) {
                @{
                    n = "SysVolFilePath";
                    e = {
                        $path = "$($script:SysVolFilePath)\Contoso.com\Policies\{$($_.ID)}"
                        if (Test-Path $path) {
                            $path
                        }
                    }
                }
            })
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
    $guids = filterCSVInput -inputStr $guid
    $erStr = ""
    $allComputers = foreach ($guid in $guids) {
        try {
            Get-ADComputer -Filter "ObjectGUID -eq '$guid'" -ErrorAction Stop
        }
        catch {
            $erStr += "`n[ERROR]:: $_.Exception.Message" 
        }
    }

    if ($erStr -ne "" ) {
        LogMessage $erStr
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpWithName {
    param(
        [Parameter(Mandatory = $true)]    
        $name
    )

    $Names = filterCSVInput -inputStr $name

    $allComputers = foreach ($name in $Names) {

        try {

            Get-ADComputer -filter "Name -eq '$name'" -properties "*" -ErrorAction Stop
        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }
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
        LogMessage "[ERROR]:: $($_.Exception.Message)"
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpDeletedinLastXdays {

    try {

        $allComputers = Get-ADObject -Filter { isDeleted -eq $true -and ObjectClass -eq 'computer' } -IncludeDeletedObjects -Properties $cmpProperties -ErrorAction Stop
    }
    catch {
        # YTD
        LogMessage  "[ERROR]:: $($_.Exception.Message)"
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
        $adGroup = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue
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
    # [CmdletBinding()]
    # param (
    #     [Parameter(Mandatory = $true)]
    #     $os
    # )

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
        LogMessage "[ERROR]:: $($_.Exception.Message)"
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpProtectedFromDeletion {

    try {

        $allComputers = Get-ADComputer -Filter * -Properties * | Where-Object { $_.ProtectedFromAccidentalDeletion -eq $true }

    }
    catch {
        LogMessage "[ERROR]:: $($_.Exception.Message)"
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
        LogMessage "[ERROR]:: $($_.Exception.Message)"
    }
    if ($allComputers) {
        GetSelectedAttributes -InputObject $allComputers -Computer
    }
}

function getCmpNvrLoggedinXdays {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $days
    )

    try {
        $date = (Get-Date).AddDays(- $days)
        $allComputers = Get-ADComputer -filter { LastLogonDate -lt $date -or LastLogonDate -notlike '*' } -properties "*" -ErrorAction Stop
    }
    catch {
        # YTD
        Write-Error $_
    }
    
    GetSelectedAttributes -InputObject $allComputers -Computer

}

function getCmpDisabled {
    try {

        $allComputers = Get-ADComputer -filter "Enabled -ne '$true'" -properties "*" -ErrorAction Stop
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

function getUsrAll {
    try {
        Get-ADUser -Filter * -Properties $usrProperties -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
        # ytd

    }
}
function getUsrDeleted {
    # ytd
    try {
        Get-Adobject -includedeletedobjects -filter { ObjectClass -eq "user" -and isdeleted -eq $true } -Properties $cmpProperties | 
        Where-Object { $_.ObjectClass -eq "user" }
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
    }
}
function getUsrEnabled {
    # ytd
    try {
        Get-AdUser -filter "Enabled -eq '$true'" -properties "*" -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"

    }
}
function getUsrDisabled {
    Get-AdUser -filter "Enabled -eq '$false'" -properties "*" -ErrorAction Stop
}
function getUsrWithEmployeeID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $EmployeeID
    )
    $EmployeeIDs = filterCSVInput -inputStr $EmployeeID
    foreach ($EmployeeID in $EmployeeIDs) {
        try {
            $employee = Get-ADUser -Filter "EmployeeID -eq '$EmployeeID'" -Properties $usrProperties -ErrorAction Stop
            if ($employee) {
                $employee
            }
            else {
                LogMessage "Employee with employeeID '$EmployeeID' not found."
            }
        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }

    }


}
function getUsrWithGUID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $guid
    )
    $guids = filterCSVInput -inputStr $guid

    foreach ($guid in $guids) {
        
        try {
            Get-ADUser -Filter "ObjectGUID -eq '$guid'"  -Properties $usrProperties  -ErrorAction Stop
        }
        catch {
            LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
        }

    }


}
function getUsrWithName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Name
    )
    $Names = filterCSVInput -inputStr $name
    foreach ($name in $Names) {
        try {
            Get-ADUser -Filter "Name -eq '$Name'"  -Properties $usrProperties  -ErrorAction Stop
        }
        catch {
            LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
        }
    }

}
function getUsrWithSID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $sid
    )

    $sids = filterCSVInput -inputStr $sid

    foreach ($sid in $sids) {
        try {
            Get-ADUser -Filter "ObjectSID -eq '$sid'"  -Properties $usrProperties  -ErrorAction Stop 
        }
        catch {
            LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
    
        }
    }
    
}
function getUsrCreatedInXdays {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true )]    
        $days
    )
    try {
        $date = (Get-Date -ErrorAction Stop).AddDays(- $days)
        Get-ADUser -filter { whenCreated -ge $date } -properties $usrProperties -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
    }
}
function getUsrModifiedInXdays {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true )]    
        $days
    )

    try {
        $date = (Get-Date).AddDays(- $days)
        Get-ADUser -filter { Modified -ge $date } -properties $usrProperties -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"

    }
}
function getUsrDirectMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $GroupName
    )

    try {
        $adGroup = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue
        Get-ADGroupMember $adGroup | 
        Where-Object { $_.objectclass -eq 'user' } | 
        ForEach-Object { Get-ADUser $_  -properties $usrProperties }
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
    }

}
function getUsrDirectInidrectMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $GroupName
    )

    try {
        $adGroup = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue
        Get-ADGroupMember $adGroup -Recursive | 
        Where-Object { $_.objectclass -eq 'user' } | 
        ForEach-Object { Get-ADUser $_ -properties $usrProperties }
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"

    }
}
function getUsrCantChangePwd {
    # ytd
    try {
        Get-ADUser -filter * -properties $usrProperties -ErrorAction Stop | Where-Object {$_.CannotChangePassword}
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"

    }
}
function getUsrNotLoggedInXdays {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $days
    )

    try {
        $date = (Get-Date).AddDays(- $days)
        Get-ADUser -filter { LastLogonDate -lt $date -or LastLogonDate -notlike '*' } -properties $usrProperties -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"

    }
}
function getUsrExpireInXdays {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $days
    )

    try {
        $date = (Get-Date).AddDays($days)
        Get-ADUser -filter { AccountExpirationDate -lt $date -or AccountExpirationDate -notlike '*' } -properties $usrProperties -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"

    }

}
function getUsrLockedOutAcnts {
    
    try {
        Get-ADUser -filter * -properties $usrProperties -ErrorAction Stop | Where-Object { $_.LockedOut -eq $true }
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
    }
}
function getUsrPwdNvrExpires {
    # ytd
    try {
        Get-ADUser -filter { PasswordNeverExpires -eq $true } -properties $usrProperties -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"

    }
}
function getUsrWithLogonScript {
    # ytd
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $ScriptName
    )
    try {
        Get-ADUser -Filter { ScriptPath -like "*$ScriptName*" } -properties $usrProperties -ErrorAction Stop
        # -or ScriptPath -like */$ScriptName -or ScriptPath -like *\$ScriptName
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"

    }
}
function getUsrWithNoLogonScript {
    # ytd
    try {
        Get-ADUser -Filter { scriptpath -notlike "*" } -properties $usrProperties -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
    }
}

<# user sub routines end #>

<# will define all the group sub routines here #>
function getGrpAll {
    Get-ADGroup -Filter * -Properties $grpProperties -ErrorAction Stop
}
function getGrpDomainLocal {
    Get-ADGroup -Filter { GroupScope -eq "DomainLocal" } -ErrorAction Stop
}

function getGrpGlobal {
    # YTD
    Get-ADGroup -Filter { GroupScope -eq "Global" } -ErrorAction Stop
}
function getGrpSecurity {
    Get-ADGroup -Filter { GroupCategory -eq "Security" } -ErrorAction Stop
}

function getGrpDistribution {
    Get-ADGroup -Filter { GroupCategory -eq "Distribution" } -ErrorAction Stop
}

function getGrpUniversal {
    # YTD
    Get-ADGroup -Filter { GroupScope -eq "Universal" } -ErrorAction Stop
}
function getGrpWithGUID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $guid
    )

    $guids = filterCSVInput -inputStr $guid

    foreach ($guid in $guids) {
        try {
            Get-ADGroup -Filter { ObjectGUID -eq "$guid" } -ErrorAction Stop
        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }

    }

}

function getGrpWithName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $name
    )
    $names = filterCSVInput -inputStr $name 
    foreach ($name in $names) {
        try {
            Get-ADGroup -Filter { Name -eq "$name" }  -ErrorAction Stop
        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }     
    }
}

function getGrpWithSID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $sid
    )
    $sids = filterCSVInput -inputStr $sid

    foreach ($sid in $sids) {
        try {
            Get-ADGroup -Filter { ObjectSID -eq "$SID" }  -ErrorAction Stop
        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }
    }
}

function getGrpCreatedInXdays {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true )]    
        $days
    )
    try {
        $date = (Get-Date).AddDays(- $days)
        Get-ADGroup -filter { whenCreated -ge $date } -properties "*" -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: Group Report : Internal : $($_.Exception.Message)"
    }
}
function getGrpDeletedInXdays {
    # YTD
    Get-ADObject -Filter { isDeleted -eq $true -and ObjectClass -eq 'group' } -IncludeDeletedObjects -Properties $cmpProperties -ErrorAction Stop
}
function getGrpModifiedInXdays {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true )]    
        $days
    )

    try {
        $date = (Get-Date).AddDays(- $days)
        Get-ADUser -filter { Modified -ge $date } -properties "*" -ErrorAction Stop
    }
    catch {
        LogMessage "[ERROR]:: Group Report : Internal : $($_.Exception.Message)"
    }
    
}
function getGrpDirectMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $GroupName
    )

    try {
        $adGroup = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction Stop
        Get-ADGroupMember $adGroup | 
        Where-Object { $_.objectclass -eq 'group' } | 
        ForEach-Object { Get-ADGroup $_  -properties * }
    }
    catch {
        LogMessage "[ERROR]:: User Report : Internal : $($_.Exception.Message)"
    }
}
function getGrpNotProtectedDeletion {
    try {

        Get-ADGroup -Filter * -Properties $grpProperties | Where-Object { $_.ProtectedFromAccidentalDeletion -ne $true }
    }
    catch {
        LogMessage "[ERROR]:: $($_.Exception.Message)"
    }
}
function getGrpDoNotContainMember {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $memberName
    )
    Get-ADGroup -Filter { Members -notlike "*" } -Properties $grpProperties -ErrorAction Stop
}
function getGrpContainMember {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $memberName
    )
    Get-ADGroup -Filter { Members -like "*" } -Properties $grpProperties -ErrorAction Stop
}
function getGrpWithNoMembers {
    Get-ADGroup -Filter { Members -notlike "*" } -Properties $grpProperties -ErrorAction Stop
}
<# group sub routines end #>

<# will define all the GPO sub routines here #>

function getGPOAll {
    [CmdletBinding()]
    param ()
    Get-GPO -All -ErrorAction Stop
}

function getGPOWithUniqueID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true )]
        $guid
    )
    Get-GPO -Guid $guid -ErrorAction Stop
}
function getGPOCreatedInXdays {
    [CmdletBinding()]
    param (
        [Parameter()]
        $days
    )
    $date = (Get-Date).AddDays(- $days)
    Get-GPO -All | Where-Object { $_.CreationTime -gt $date }
}
function getGPOModifiedInXdays {
    [CmdletBinding()]
    param (
        [Parameter()]
        $days
    )
    $date = (Get-Date).AddDays(- $days)
    Get-GPO -All | Where-Object { $_.ModificationTime -gt $date }
    
}
function getGPOallSettingsDisabled {
    [CmdletBinding()]
    param ()
    Get-GPO -All | Where-Object { $_.GPOStatus -eq 'AllSettingsDisabled' }
}
function getGPOallSettingsEnabled {
    [CmdletBinding()]
    param ()
    Get-GPO -All | Where-Object { $_.GPOStatus -eq 'AllSettingsEnabled' }
}

function getGPOCmpSettingsDisabled {
    [CmdletBinding()]
    param ()
    Get-GPO -All | Where-Object { $_.GPOStatus -eq 'ComputerSettingsDisabled' }
    
}

function GetGPOUsrSettingsDisabled {
    [CmdletBinding()]
    param ()
    Get-GPO -All | Where-Object { $_.GPOStatus -eq 'UserSettingsDisabled' }

}

<# GPO sub routines end #>

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
                    break;
                }
    
                # 2. "Computer with specified GUID"
                2 {
                    getCmpwithGUID -guid $cmpSearchWithGuid -ErrorAction Stop
                    break;
                }
    
                # 3. "Computer with specified name"
                3 {
                    getCmpWithName -name $cmpSearchWithName -ErrorAction Stop
                    break;
                }
    
                # 4. "Computer created in last 30 days"
                4 {
                    getCmpCreatedinLastXdays -days $cmpCreatedNoOfDays -ErrorAction Stop
                    break;
                }
    
                # 5. computers deleted in last 30 days
                5 {
                    getCmpDeletedinLastXdays -ErrorAction Stop
                    break;
                }
    
                # 6. computers that are direct members of specified groups
                6 {
                    getCmpDirectMemberShip -GroupName $cmpSearchWithGroupName -ErrorAction Stop
                    break;
                }
                
                # 7. computers that are direct and indirect members of specified groups
                7 {
                    getCmpDirectIndirectMembership -GroupName $cmpSearchWithGroupName -ErrorAction Stop
                    break;
                }
    
                # 8. computers running specific operating system
                8 {
                    getCmpRunningSpecificOS -ErrorAction Stop
                    break;
                }
    
                # 9. computers that are not protected from deletion
                9 {
                    getCmpNotProtectedFromDeletion -ErrorAction Stop
                    break;
                }
    
                # 10. computers that are protected from deletion.
                10 {
                    getCmpProtectedFromDeletion -ErrorAction Stop
                    break;
                }
    
                # 11. computers that are never logged on for 60 days
                11 {
                    getCmpNvrLoggedinXdays -days $cmpNvrLoggedOnDays -ErrorAction Stop
                    break;
                }
    
                # 12. disabled computers
                12 {
                    getCmpDisabled -ErrorAction Stop
                    break;
                }
    
                # 13. enabled computers
                13 {
                    getCmpEnabled -ErrorAction Stop
                    break;
                }
    
                Default {
                    LogMessage "computer Option: invalid input received."
                    break;
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
    begin {
        $userOption = [int]$userOption
    }
    process {

        try {

            switch ($userOption) {

                1 {

                    $ResultObj = getUsrAll                     
                    break;
                }
                
                2 {

                    $ResultObj = getUsrDeleted 
                    break;
                }
                
                3 {

                    $ResultObj = getUsrEnabled 
                    break;
                }
                
                4 {

                    $ResultObj = getUsrDisabled
                    break;
                }
                
                5 {

                    $ResultObj = getUsrWithEmployeeID -EmployeeID $userSearchWithEmployeeID -ErrorAction Stop
                    break;
                }
                
                6 {

                    $ResultObj = getUsrWithGUID -guid $userSearchWithGuid -ErrorAction Stop
                    break;
                }   
                
                7 {

                    $ResultObj = getUsrWithName -Name $userSearchWithName -ErrorAction Stop
                    break;
                }
                
                8 {

                    $ResultObj = getUsrWithSID -sid $userSearchWithSID -ErrorAction Stop
                    break;
                }
                
                9 {

                    $ResultObj = getUsrCreatedInXdays -days $userCreatedNoDays -ErrorAction Stop
                    break;
                }
                
                10 {

                    $ResultObj = getUsrModifiedInXdays -days $userModifiedNoDays -ErrorAction Stop  
                    break;
                }

                11 {

                    $ResultObj = getUsrDirectMembership -GroupName $userDirectGroupMemShip -ErrorAction Stop
                    break;
                }
                
                12 {

                    $ResultObj = getUsrDirectInidrectMembership -GroupName $userInDirectGroupMemship -ErrorAction Stop
                    break;
                }
                13 {

                    $ResultObj = getUsrCantChangePwd
                    break;
                }
                
                14 {

                    $ResultObj = getUsrNotLoggedInXdays -days $userNotloggedonDays -ErrorAction Stop
                    break;
                }
                15 {

                    $ResultObj = getUsrExpireInXdays -days $userExpiryOnDays -ErrorAction Stop
                    break;
                }
                
                16 {

                    $ResultObj = getUsrLockedOutAcnts
                    break;
                }
                17 {

                    $ResultObj = getUsrPwdNvrExpires 
                    break;
                }
                
                18 {

                    $ResultObj = getUsrWithNoLogonScript 
                    break;
                }

                19 {

                    $ResultObj = getUsrWithLogonScript -ScriptName $userSearchwithLogonScriptName -ErrorAction Stop
                    break;

                }
                 
                Default {
                    LogMessage "user choice: invalid option received."
                    break;
                }
            }

        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }
    }
    end {

        if ($ResultObj) {
            GetSelectedAttributes -InputObject $ResultObj -User
        }
        else {
            LogMessage "Users Report: Nothing to Export."
        }

    }

}

function Get-ADCustomGroupReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $groupOption
    )

    begin {
        $groupOption = [int]$groupOption
    }
    process {
        try {
            switch ($groupOption) {
                1 {
                    $resultObj = getGrpAll
                    break;
                }
                2 {
                    $resultObj = getGrpSecurity
                    break;
                }
                3 {
                    $resultObj = getGrpDistribution
                    break;
                }
                4 {
                    $resultObj = getGrpGlobal
                    break;
                }
                5 {
                    $resultObj = getGrpDomainLocal
                    break;
                }
                6 {
                    $resultObj = getGrpUniversal
                    break;
                }
                7 {
                    $resultObj = getGrpWithGUID
                    break;
                }
                8 {
                    $resultObj = getGrpWithName
                    break;
                }
                9 {
                    $resultObj = getGrpWithSID
                    break;
                }
                10 {
                    $resultObj = getGrpCreatedInXdays
                    break;
                }
                11 {
                    $resultObj = getGrpDeletedInXdays
                    break;
                }
                12 {
                    $resultObj = getGrpModifiedInXdays
                    break;
                }
                13 {
                    $resultObj = getGrpDirectMembership
                    break;
                }
                14 {
                    $resultObj = getGrpNotProtectedDeletion
                    break;
                }
                15 {
                    $resultObj = getGrtProtectedDeletion
                    break;
                }
                16 {
                    $resultObj = getGrpDoNotContainMember
                    break;
                }
                17 {
                    $resultObj = getGrpContainMember
                    break;
                }
                18 {
                    $resultObj = getGrpWithNoMembers
                    break;
                }
                Default {
                    LogMessage "Group Option: invalid option received."
                    break;
                }
            }
        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }
    }
    end {

        if ($ResultObj) {
            GetSelectedAttributes -InputObject $ResultObj -Group
        }
        else {
            LogMessage "Group Report: Nothing to Export."
        }

    }

}

function Get-ADCustomGPOReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $gpoOption
    )

    begin {
        $gpoOption = [int]$gpoOption
    }
    process {
        try {
            switch ($gpoOption) {
                1 {
                    $ResultObj = getGPOAll -ErrorAction Stop
                    break; 
                }
                2 {
                    $ResultObj = getGPOWithUniqueID -ErrorAction Stop
                    break; 
                }
                3 {
                    $ResultObj = getGPOCreatedInXdays -ErrorAction Stop
                    break; 
                }
                4 {
                    $ResultObj = getGPOModifiedInXdays -ErrorAction Stop
                    break; 
                }
                5 {
                    $ResultObj = getGPOallSettingsDisabled -ErrorAction Stop
                    break; 
                }
                6 {
                    $ResultObj = getGPOallSettingsEnabled -ErrorAction Stop
                    break; 
                }
                7 {
                    $ResultObj = getGPOCmpSettingsDisabled -ErrorAction Stop
                    break; 
                }
                8 {
                    $ResultObj = GetGPOUsrSettingsDisabled -ErrorAction Stop
                    break; 
                }
                Default {
                    LogMessage "GPO Option: invalid option received."
                    break;
                }
            }
        }
        catch {
            LogMessage "[ERROR]:: $($_.Exception.Message)"
        }
    }
    end {
        if ($ResultObj) {
            GetSelectedAttributes -InputObject $ResultObj -GPO
        }
        else {
            LogMessage "GPO Report: Nothing to Export."
        }
    }

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

$Global:LogMsgVar = ''
$stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

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

try {
    $ExportPath = 'C:\Custom_AD_Report.csv'
    $report = Get-ADCustomReport -reportType $reportType -ErrorAction Stop
    if ($report) {
        $report | Export-Csv $Exportpath -NoTypeInformation -Force
        LogMessage "report generated and exported to '$Exportpath'."
        $report # testing purpose
    }

}
catch {
    LogMessage "[ERROR]:: $($_.Exception.Message)"
}


# Step 12: Email the report feature

<# ---  To be tested and implemented. --- #>



# StopWatch terminate

if ($stopWatch.IsRunning) {
    $stopWatch.Stop()
}

LogMessage "Elapsed Time : $($stopWatch.Elapsed.Hours) h $($stopWatch.Elapsed.Minutes) m $($stopWatch.Elapsed.Seconds) s."



# Display any log message to the technician
if ($Global:LogMsgVar) {
    Write-Output $Global:LogMsgVar
}