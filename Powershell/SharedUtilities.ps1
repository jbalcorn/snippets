<#
    Subroutines and Functions for Active Directory Utility Scripts
#>

##
$script:DOMS = @{}

foreach ($d in 'DOM1','DOM2') {
    $script:DOMS[$d] = New-Object -TypeName PSObject -Property @{
            maxlen = 12
            order = 'FL'
    }
}
$script:DOMS['DOM3'] = New-Object -TypeName PSObject -Property @{
    maxlen = 8
    order = 'LF'
}
## Active Directory Utilities

Function Get-ActiveDirectoryArray {
    <# 
   .SYNOPSIS 
    Returns an array of Domain Controllers and SearchBase Distinguished Name for the current forest.  Will attempt to get the most efficient DC based on your site.
   .PARAMETER site
    valid site in the forest. If provided, will return the most efficient array for that site.  
   .Example 
    $Conns = Get-ActiveDirectoryArray 
    
    Get-ADUser -Filter { attribute eq value } -server $Conns["domain"].DC -searchbase $C["domain"].DN
#Requires -Version 2.0 
#> 
    [CmdletBinding()]Param(
        [string]$site
    )
    $C = @{}

    $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
    $gchosts = [array]($Forest.GlobalCatalogs | Where-Object {$_.Domain.Name -eq $Forest.RootDomain.Name } ).Name
    $GC = "$($gchosts[0]):3268"
    $RootDSE = [ADSI]"LDAP://RootDSE"
    $ConfigNC = $RootDSE.Get("configurationNamingContext")
    
    if (-Not $site) {
        $site = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
    }
    $mySiteServers = @()
    $siteSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]("LDAP://CN=Servers,CN=$($site),CN=Sites," + $configNC), '(objectclass=server)', ('dnshostname'), 'subtree')
    try {
        $siteSearch.FindAll() | ForEach-Object { $mySiteServers += $_.Properties["dnshostname"] }
    }
    catch {
        Throw "Site $($site) is not valid in Forest"
    }

    # Get the site that contains the NamingRoleOwner, this should usually be the core site for the Forest.  Servers will be picked from here if they aren't local to my site
    $rootSite = (nltest /server:$($Forest.NamingRoleOwner) /dsgetsite)[0]
    $rootSiteServers = @()
    $siteSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]("LDAP://CN=Servers,CN=$($rootsite),CN=Sites," + $configNC), '(objectclass=server)', ('dnshostname'), 'subtree')
    $siteSearch.FindAll() | ForEach-Object { $rootSiteServers += $_.Properties["dnshostname"] }

    # Use ADSI Searcher object to determine NetBIOS names of domains. 
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher 
    $Searcher.SearchScope = "subtree" 
    $Searcher.PropertiesToLoad.Add("nETBIOSName") > $Null 
    # Base of search is Partitions container in the configuration container. 
    $Searcher.SearchRoot = "LDAP://cn=Partitions,$ConfigNC"

    ForEach ($Domain In $Forest.Domains) {
        if ($Domain.Name -eq $Forest.RootDomain.Name) {
            $DomGC = $GC
        }
        else {
            $DomGC = $null
        }
        # Find the corresponding partition and retrieve the NetBIOS name. 
        $DN = "dc=" + $Domain.Name.Replace(".", ",dc=")
        $Searcher.Filter = "(nCName=$DN)" 
        $NetBIOSName = ($Searcher.FindOne()).Properties.Item("nETBIOSName")[0]
        $PreferredDC = $mysiteDC = $rootSiteDC = $null
        # Add a hash of all the domain controllers. We'l mark them '0' if they're unreachable so we only time out once per run.
        $dcs = @{}
        ForEach ($DC in $Domain.DomainControllers) {
            $dcs[$DC.Name] = 1
            if ($mySiteServers -contains $DC.Name) {
                $mysiteDC = $DC.Name
            }
            elseif ($rootSiteServers -contains $DC.Name) {
                $rootSiteDC = $DC.Name
            }
        }
        $PreferredDC = ($mySiteDC, $rootSiteDC)[!$mySiteDC]
        $DCName = ($PreferredDC, $($Domain.PdcRoleOwner.name))[!$PreferredDC]
        $domcfg = New-Object -Typename PSObject -Property @{
            DC  = $DCName
            DN  = $DN
            UPN = $Domain.Name
            GC  = $DomGC
            DCS = $dcs
        }
        $C.Add($NetBIOSName, $domcfg)
    }

    $C
}

Function isExistingUsername {
    <# 
.SYNOPSIS 
    Does a given username exist?
.DESCRIPTION 
    Returns TRUE if a given username exists, otherwise FALSE
.PARAMETER uname
    
#>
    Param([string]$uname)
    if (-Not $uname) {return $false}
    try {
        if (Get-ADUser -Identity $uname -Server $script:ADINFO[$script:GCDOM].GC) { return $true; }
    }
    catch {
        if ($Error[0].Exception.Message -match "Cannot find an object with identity") {
            return $false
        }
        elseif ($Error[0].Exception.Message -match "Multiple objects were found") {
            LogEvent WARNING -message "$($uname) Multiple instances of username were found"
            return $true
        }
        LogEvent WARNING -message "$($uname) isExistingUsername Error: $($Error[0])"
        throw
    }
    return $false
}

function asciiClean {
    <# 
.SYNOPSIS 
    Removes characters that aren't 7-bit clean and lowercases
.DESCRIPTION 
    Removes any characters that don't exist in the range 0-9, a-z,A-Z. Tries to find reasonable replacements when it can. 
.PARAMETER in
    
#>
    Param([string]$in)

    $in = $in.Tolower()

    $characterMap = @{ 
        "$([char]228)" = 'a'
        "$([char]246)" = 'o'
        "$([char]252)" = 'u'
        "$([char]223)" = 'ss'
        "$([char]225)" = 'a'
        "$([char]231)" = 'c'
        "$([char]241)" = 'n'
        "$([char]224)" = 'a'
        "$([char]226)" = 'a'
        "$([char]227)" = 'a'
        "$([char]229)" = 'a'
        "$([char]230)" = 'ae'
        "$([char]232)" = 'e'
        "$([char]233)" = 'e'
        "$([char]234)" = 'e'
        "$([char]235)" = 'e'
        "$([char]236)" = 'i'
        "$([char]237)" = 'i'
        "$([char]238)" = 'i'
        "$([char]239)" = 'i'
        "$([char]240)" = 'i'
        "$([char]242)" = 'o'
        "$([char]243)" = 'o'
        "$([char]244)" = 'o'
        "$([char]245)" = 'o'
        "$([char]249)" = 'u'
        "$([char]250)" = 'u'
        "$([char]251)" = 'u'
        "$([char]253)" = 'y'
        "$([char]254)" = 'p'
        "$([char]255)" = 'y'
        "$([char]257)" = 'a'
        "$([char]259)" = 'a'
        "$([char]261)" = 'a'
        "$([char]263)" = 'c'
        "$([char]265)" = 'c'
        "$([char]267)" = 'c'
        "$([char]269)" = 'c'
        "$([char]271)" = 'd'
        "$([char]273)" = 'd'
        "$([char]275)" = 'e'
        "$([char]277)" = 'e'
        "$([char]279)" = 'e'
        "$([char]281)" = 'e'
        "$([char]283)" = 'e'
        "$([char]285)" = 'g'
        "$([char]287)" = 'g'
        "$([char]289)" = 'g'
        "$([char]291)" = 'g'
        "$([char]293)" = 'h'
        "$([char]295)" = 'h'
        "$([char]297)" = 'i'
        "$([char]299)" = 'i'
    }

    foreach ($key in $characterMap.Keys) {
        $in = $in.replace($key, $characterMap[$key])
    } 

    $in = $in -replace "[^ -~]", ""

    $in
}

Function domUserName {
    <# 
.SYNOPSIS 
    Generates a domain-specific username
.DESCRIPTION 
    Generates a username using domain specific rules. The parameter representing first name 
    be used whole and so should be procesed by the calling function. The last name will be truncated as needed. 
    This is intended to be used by other functions that have higher-level processing.
.PARAMETER dom
.PARAMETER first
.PARAMETER last
.PARAMETER digit
    Used for recursively increasing uniqueness digit if needed
    
#>
    Param(
        [parameter(Mandatory = $true)][string]$dom,
        [parameter(Mandatory = $true)][string]$first,
        [parameter(Mandatory = $true)][string]$last,
        [int]$digit
    )
    if ($digit) {
        if ($digit -lt 10) { $diglen = 1 }
        elseif ($digit -lt 100) { $diglen = 2 }
        else { $diglen = 3 }
        $dig = [string]$digit
    }
    else {
        $diglen = 0
        $dig = "";
    }
    if ($script:DOMS[$dom].maxlen) {
        $max = $script:DOMS[$dom].maxlen
    }
    else {
        $max = 12 - $diglen;
    }
    try {
        $f = $first.Substring(0, $max - 1)
    }
    catch {
        $f = $first
    }
    try {
        $l = $last.Substring(0, $max - ($($first).Length))
    }
    catch {
        $l = $last
    }
    if ($script:DOMS[$dom].order -eq "LF") {
        return "${l}${f}${dig}"
    }
    else {
        return "${f}${l}${dig}"
    }
}

Function GenUsername {
    <# 
.SYNOPSIS 
    Generates a domain-specific username from name elements
.DESCRIPTION 
    Generates a username by trying different compbinations. 
.PARAMETER dom
.PARAMETER lname
.PARAMETER fname
.PARAMETER mname
.PARAMETER kan
 Known-As Name
    
#>
    Param(
        [parameter(Mandatory = $true)][string]$dom,
        [parameter(Mandatory = $true)][string]$lname,
        [parameter(Mandatory = $true)][string]$fname,
        [string]$mname,
        [string]$kan
    )
    if (([string]::IsNullOrEmpty($kan))) {
        $kan = $fname
    }
    $lname = asciiClean $lname.Trim()
    $fname = asciiClean $fname.Trim()
    $mname = asciiClean $mname.Trim()
    $kan = asciiClean $kan.Trim()
    if ($lname.IndexOf(" ", 0) -gt 3) {
        $lname_second = $lname.Substring($lname.IndexOf(" ", 0) + 1, 1)
        $lname = $lname.Substring(0, $lname.IndexOf(" ", 0))
    }
    else {
        $lname_second = ""
    }
    if ($lname.IndexOf("-", 0) -gt 3) {
        $lname_second = $lname.Substring($lname.IndexOf("-", 0) + 1, 1)
        $lname = $lname.Substring(0, $lname.IndexOf("-", 0))
    }
    $lname = $lname -replace "[\'\-,\. ]", ""
    if ($fname.IndexOf(" ") -gt -1) {
        $fname = $fname.Substring(0, $fname.IndexOf(" "))
    }
    $fname = $fname -replace "[\'\-,\. ]", ""
    if ($kan.IndexOf(" ") -gt -1) {
        $kan = $kan.Substring(0, $kan.IndexOf(" "))
    }
    $kan = $kan -replace "[\'\-,\. ]", ""
    ##
    # Handle Indian Last names that are only 1 letter by using whole first name.  Otherwise, we'll use at most 2 letters.
    if ($lname.length -eq 1) {
        $fnamelen = $fname.length
    }
    else {
        $fnamelen = 1
    }
    # standard
    try {
        $uname = domUsername $dom $kan.Substring(0, [Math]::Min($kan.Length, $fnamelen)) $lname 
    }
    catch {
        $uname = $null
    }
    if ($uname -and -Not (isExistingUsername $uname)) { return $uname; }
    try {
        $uname = domUsername $dom $fname.Substring(0, $fnamelen) $lname
    }
    catch {
        $uname = $null
    }
    if ($uname -and -Not (isExistingUsername $uname)) { return $uname; }
    try {
        $uname = domUsername $dom $fname.Substring(0, $fnamelen) "$($lname)$($lname_second)"
    }
    catch {
        $uname = $null
    }
    #Begin Extra
    if ($uname -and -Not (isExistingUsername $uname)) { return $uname; }
    try {
        $uname = domUsername $dom "$($fname.Substring(0,1))$($mname.Substring(0,1))" $lname
    }
    catch {
        $uname = $null
    }
    if ($uname -and -Not (isExistingUsername $uname)) { return $uname; }
    try {
        $uname = domUsername $dom $kan.substring(0, 2) $lname
    }
    catch {
        $uname = $null
    }
    if ($uname -and -Not (isExistingUsername $uname)) { return $uname; }
    try {
        $uname = domUsername $dom $fname.substring(0, 2) $lname
    }
    catch {
        $uname = $null
    }
    if ($uname -and -Not (isExistingUsername $uname)) { return $uname; }
    # End Extra

    # if we get here, we need to append a number to the username.
    # get the first initial, 10 characters of the last name, and replace the
    # last characters of the last name with a number until we find a unique match.
    # this WILL eventually find a unique name, unless we have more than
    # 9,999,999,999 entries in the directory.
    $a = 1;
    $f = $kan.Substring(0, [Math]::Min($kan.Length, $fnamelen))
    while ($a -lt 99) {
        try {
            $uname = domUsername $dom $f $lname $a
        }
        catch {
            $uname = $null
        }
        if ($uname -and -Not (isExistingUsername $uname)) { return $uname; }
        $a++;
    }
    throw "Could not generate Username"
}

Function Read-ADUserPropertiesFile {
    <# 
   .SYNOPSIS 
    Read-ADUserPropertiesFile  
   .PARAMETER file
    The parameter 
   .OUTPUT

    A Hash of properties to change and information about how to generate them
#>
    param(
        [Parameter(Mandatory = $true)][string]$file
    )
    $a = @{}
    if (Test-Path $file) {
        Import-csv $file | ForEach-Object {
            $a[$_.attribute] = new-object -TypeName PSObject -Property @{
                ADName         = $_.adname
                transform      = $_.transform
            }
        }
    }
    else {
        throw "AD User Attribute File $($file) not found"
    }
    $a
}

$script:ADATTRIBUTES = Read-ADUserPropertiesFile adattributes.csv

Function Get-CurrentAttributeValues {
    Param(
        $adentry
    )
    $chg = @{}
    $attr = $script:ADATTRIBUTES.keys
    foreach ($a in $attr) {
        $chg[($script:ADATTRIBUTES[$a].ADName)] = $adentry.($script:ADATTRIBUTES[$a].ADNAME)
    }
    return $chg
}

Function Compare-ADUserProperties {
    <# 
   .SYNOPSIS 
    Compares 2 ADUser objects, returns any attribute differences  
   .Example 
    Compare-ADUserProperties -ReferenceObject $oldObj -DifferenceObject $newObj
   .PARAMETER ReferenceObject
   .PARAMETER DifferenceObject
   .OUTPUT
    Array of PSCustomobjects that represent differences: PropertyName, RefValue, DiffValue
#> 
    Param(
        [PSObject]$ReferenceObject,
        [Hashtable]$DifferenceObject 
    )
    $objprops = ($ReferenceObject | Get-Member -MemberType Property, NoteProperty | ForEach-Object Name).ToLower()
    $objprops += ($DifferenceObject.keys).ToLower()
    $objprops = $objprops | Sort-Object | Select-Object -Unique | Where-Object { $script:USERATTR -contains $_ }
    $diffs = @()
    foreach ($objprop in $objprops) {
        if ([string]::IsNullOrEmpty($DifferenceObject[$objprop])) {
            $DifferenceObject[$objprop] = $null
        }
        if ((($ReferenceObject.($objprop) -and $DifferenceObject[$objprop]) -and $ReferenceObject.($objprop) -ne $DifferenceObject[$objprop]) -or ($ReferenceObject.($objprop).count -eq 0 -and $null -ne $DifferenceObject[$objprop]) -or ($ReferenceObject.($objprop).count -gt 0 -and $null -eq $DifferenceObject[$objprop] ) -or ($ReferenceObject.($objprop) -xor $DifferenceObject[$objprop])) {            
            $diffprops = @{
                PropertyName = $objprop
                RefValue     = $ReferenceObject.($objprop)
                DiffValue    = $DifferenceObject[$objprop]
            }
            $diffs += New-Object PSObject -Property $diffprops
        }
    }
    [array]$diffs
}


Function Get-Domain {
    <# 
.SYNOPSIS 
    Gets the domain associated with an Active Directory object
.DESCRIPTION 
    Given a Account Name, DistinguishedName or AD object returns the domain containing the object

    It will throw an error if the input object is not recognized.

.PARAMETER in
    The object.
.PARAMETER short
    for backwards compatibility
.INPUTS
    This function does not accept pipeline input
.OUTPUTS
    Returns the short version of the canonical name
    
#>
    Param
    ([parameter(Mandatory = $true)]$in,
    [switch]$short
    )
    if (-Not $in) {
        throw "Required Parameter missing"
    }
    elseif (($in.GetType()).Name -eq "String") {
        $u = Get-ADObject -Filter { SamAccountName -eq $in -or DistinguishedName -eq $in -or name -eq $in } -Server "$($script:ADINFO[$script:GCDOM].DC):3268" -SearchBase "$($script:ADINFO[$script:GCDOM].DN)" -Credential $script:ADMIN
        if (-Not $u) {
            throw "Cannot find object for $in "
        }
        if ($u.count) {
            throw "More than one object found for $in "
        }
    }
    elseif (($in.GetType()).Name -eq "ADUser") {
        $u = $in
    }
    elseif (($in.GetType()).Name -eq "ADGroup") {
        $u = $in
    }
    elseif (($in.GetType()).Name -eq "ADAccount") {
        $u = $in
    }
    elseif (($in.GetType()).Name -eq "ADObject") {
        $u = $in
    }
    elseif (($in.GetType()).Name -eq "ADComputer") {
        $u = $in
    }
    elseif ($in.distinguishedName) {
        $u = $in
    }
    else {
        throw "Cant find domain, No DistinguishedName, unknown type " + $in.GetType()
    }
    
    $domain = ""
    $start = 0
    $end = 0
    if (($u.DistinguishedName).count -gt 1) {
        $dn = (($u.DistinguishedName)[0]).ToLower()
    }
    else {
        $dn = ($u.Distinguishedname).ToLower()
    }

    while ($end -gt -1) {
        $start = $dn.IndexOf("dc=", $end) + 3
        $end = $dn.IndexOf(",", $start)
        if ($end -gt -1) {
            $domain += $dn.Substring($start, $end - $start)
            $domain += "."
        }
        else {
            $domain += $dn.Substring($start)
        }
        
    }
    return ($domain.Substring(0, $domain.IndexOf("."))).ToUpper()
}

Function fromTimeZoneToEastern {
    <# 
   .SYNOPSIS 
    Converts a time in a timezone to Eastern Time (Used to be UTC, But Employee Central changed to Eastern Time)  
   .PARAMETER timeZone
    TimeZone of the startDate
   .PARAMETER startDate
    A Date or Date/Time in any format accepted by Get-Date
   .OUTPUTS
    DateTime object 
#> 
    Param(
        $timeZone, 
        $startDate
    ) 
    try {
        $startDate = Get-Date($startDate)
    }
    catch {
        throw "Error in fromTimeZoneToEastern: Bad Start Date '$($startDate)': $($Error[0])"
    }
    $toTimeZone = "Eastern Standard Time"
    $oFromTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($timeZone)
    $oToTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($toTimeZone)
    try {
        $utc = [System.TimeZoneInfo]::ConvertTimeToUtc($startDate, $oFromTimeZone)
    }
    catch {
        if ($Error[0].exception.message -match 'time in the period that is skipped is invalid') {
            LogEvent INFO -message "fromTimeZoneToEastern: DateTime $($startDate) may be too close to DST boundary. Returning original date"
            $utc = $startDate
        }
        else {
            throw "Error on ConvertTimeToUtc $($startDate) $($oFromTimeZone): $($Error[0])"
        }
    }
    try {
        $newTime = [System.TimeZoneInfo]::ConvertTime($utc, $oToTimeZone)
    }
    catch {
        if ($Error[0].exception.message -match 'time in the period that is skipped is invalid') {
            LogEvent INFO -message "fromTimeZoneToEastern: DateTime $($startDate) may be too close to DST boundary. Returning original date"
            $newTime = $utc
        }
        else {
            throw "Error on ConvertTime $($utc) $($oToTimeZone): $($Error[0])"
        }
    }
    return $newTime
}

function Update-ADEntry {
    Param(
        $adentry,
        $diff
    )
    if (-Not $script:ADMIN) {
        LogEvent WARNING -message "Need `$script:ADMIN account.  Please input credentials"
        $script:ADMIN = Get-Credential
    }
    if (-Not $script:ADMIN) {
        LogEvent ERROR -message "Need `$script:ADMIN account to run. Returning with no changes"
        return
    }

    $empid = $adentry.employeeid
    try {
        $dom = Get-Domain $adentry
    }
    catch {
        LogEvent ERROR -message "$($empid) Update-ADEntry Error returning from Get-Domaain: $($Error[0])"
    }
    $output = @("$($empid) Changes to be made to $($adentry.DistinguishedName):")
    $add = @{}
    $replace = @{}
    $remove = @()
    if ($diff.count) {
        foreach ($d in $diff) {
            if ($d.PropertyName -eq "enabled") {
                $value = $d.DiffValue
                if ($d.RefValue) {
                    $output += "$($d.Propertyname) : TRUE => FALSE"
                }
                else {
                    $output += "$($d.Propertyname) : FALSE => TRUE"
                }
                if (-Not $script:TESTONLY) {
                    try {
                        Set-ADUser $adentry -Enabled:$value -Server $script:ADINFO[$dom].DC -Confirm:$false -Credential $script:ADMIN -Whatif:$script:TESTONLY
                    }
                    catch {
                        LogEvent INFO -message $($output -join "`r`n`t")
                        LogEvent ERROR -message "$($empid) Error setting Enabled:$($value)"
                    }
                }
            }
            elseif ([string]$d.DiffValue -and [string]$d.RefValue) {
                $replace[$d.PropertyName] = $d.diffValue
                $output += "$($d.PropertyName) : $($d.RefValue) => $($d.DiffValue)"
            }
            elseif ([string]$d.diffvalue) {
                $add[$d.PropertyName] = $d.DiffValue
                $output += "$($d.PropertyName) : NULL => $($d.DiffValue)"
            }
            else {
                $remove += $d.PropertyName
                $output += "$($d.PropertyName) : $($d.RefValue) => NULL"
            }
        }
        LogEvent INFO -message ($output -join "`r`n`t")
        if (-Not $script:TESTONLY) {
            try {
                if ($remove.count -gt 0) {
                    Set-ADUser $adentry -Clear $remove -Server $script:ADINFO[$dom].DC -Confirm:$false -Credential $script:ADMIN -Whatif:$script:TESTONLY
                }
                if (($Replace.keys).count -gt 0) {
                    Set-ADUser $adentry -Replace $Replace -Server $script:ADINFO[$dom].DC -Confirm:$false -Credential $script:ADMIN -Whatif:$script:TESTONLY
                }
                if (($add.keys).count -gt 0) {
                    Set-ADUser $adentry -Add $add -Server $script:ADINFO[$dom].DC -Confirm:$false -Credential $script:ADMIN -Whatif:$script:TESTONLY
                }
            }
            catch [Microsoft.ActiveDirectory.Management.ADException] {
                if ($Error[0].exception.ServerErrorMessage -match "INSUFF_ACCESS_RIGHTS") {
                    Logevent ERROR -message "$($empid) Insufficient Access Rights to update $($adentry.DistinguishedName)"
                }
                else {
                    LogEvent ERROR -message "$($empid) Error ADException on Update: $($Error[0])"
                    Write-Debug "HRRECORD: $($hrrecord | Out-String)"
                    Write-Debug "NEW: $($new | Out-String)"
                    Write-Debug "DIFF: $($diff | Out-String)"
                    Write-Debug "REMOVE: $($remove | Out-STring)"
                    Write-Debug "REPLACE: $($replace | Out-String)"
                    Write-Debug "ADD: $($add | Out-String)"
                }
            }
            catch {
                LogEvent ERROR -message "$($empid) Error on Update: $($Error[0])"
                Write-Debug "HRRECORD: $($hrrecord | Out-String)"
                Write-Debug "NEW: $($new | Out-String)"
                Write-Debug "DIFF: $($diff | Out-String)"
                Write-Debug "REMOVE: $($remove | Out-STring)"
                Write-Debug "REPLACE: $($replace | Out-String)"
                Write-Debug "ADD: $($add | Out-String)"
            }
            $adentry = Get-ADUser $adentry -Server $script:ADINFO[$dom].DC -properties * -Credential $script:ADMIN
        }
    }
    return $adentry
} 

function Get-ADUserLastLogon {
    <# 
.SYNOPSIS 
    Returns actual last logon date for an AD User by searching all available domain controllers
.DESCRIPTION 
    Given a Account Name, DistinguishedName or AD object searches all domain controllers in the domain for the actual last logon date recorded.

    Will update $script:ADINFO[$domain]DCS hash if a server is down for efficiency.

    FOR NOW: Because of the number of accounts, use the LastLogonDate information.  But when we start acting on the accounts, use the 
    more robust process

.PARAMETER u
    
#>
    Param
    ([parameter(Mandatory = $true)][Object]$u
    )
    # Temp Process for speed
    if ($u.LastLogonDate) {
        return $u.LastLogonDate
    }
    else {
        return $null
    }
    if ($domain = Get-Domain($u)) {
        $time = 0
        foreach ($hostname in (($script:ADINFO[$domain].DCS).keys | Where-Object {($script:ADINFO[$domain].DCS)[$_] -eq 1})) { 
            try {
                $user = Get-ADUser $u -Server $hostname | Get-ADObject -Properties lastLogon
            }
            catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                LogEvent INFO -message "$hostname $($_.Exception.message). Marking Down"
                # Mark the server unreachable
                ($script:ADINFO[$domain].DCS)[$hostname] = 0
            } 
            if ($user.LastLogon -gt $time) {
                $time = $user.LastLogon
            }
        }
        if ($time) {
            return [DateTime]::FromFileTime($time)
        }
        return $null
    }
    else {
        throw "$u was not found"
    }
}

Function Get-OpenFileName
{
    param([string]$initialDirectory,[string]$Filter)

    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.initialDirectory = $initialDirectory
    #$dialog.filter = "CSV (*.csv)| *.csv"
    $dialog.filter = $Filter
    $dialog.ShowDialog() | Out-Null
    $dialog.filename
    
}

Function Get-SaveFileName
{
    param([string]$initialDirectory,[string]$Filter)

    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.initialDirectory = $initialDirectory
    #$dialog.filter = "CSV (*.csv)| *.csv"
    $dialog.filter = $Filter
    $dialog.ShowDialog() | Out-Null
    $dialog.filename
    
}
