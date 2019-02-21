
$startingUser = "theceo"

Function Get-DomUser
{
    param([string]$in)
    if (-Not $in) {
        return $null
    } elseif ($in -match "^[\d]+$") {
        $empid = ([int]$in).ToString("00000000")
        $u = Get-ADUser -Filter { employeeid -eq $empid -or SamAccountName -eq $in } -Server $script:ADINFO[$script:GCDOM].GC -SearchBase $script:ADINFO[$script:GCDOM].DN -Properties employeetype
        if (-Not $u) {
            return $null
        }
    } elseif (($in.GetType()).Name -eq "String") {
        $u = Get-ADUser -Filter { SamAccountName -eq $in -or DistinguishedName -eq $in -or name -eq $in -or mail -eq $in } -Server $script:ADINFO[$script:GCDOM].GC -SearchBase $script:ADINFO[$script:GCDOM].DN -Properties employeetype
        if (-Not $u) {
            return $null
        }
    } elseif (($in.GetType()).Name -eq "ADUser") {
        $u = $in
    } else {
        Write-Host "Not a string or a user"
        return $null
    }
    if ($u.count) {
        $u = $u | ? { $_.Employeetype -match "Active|Terminated|Deleted|Unknown|Consultant|Contractor" }
    }
    $dom = Get-Domain $u -short

    Get-ADUser $u -Server $script:ADINFO[$dom].DC -properties *
}

Function Get-AllDirectReports {
    param([Microsoft.ActiveDirectory.Management.ADUser] $u, [int]$l)


    $Tree = @()

    if ($u.employeetype -eq "Active") {
        $region = $u."le-region"
        $Tree += New-Object -TypeName PSObject -Property @{
            Employee = $u.DisplayName
            Manager = $null
            Title = $u.title
            CoCd = $u."le-cocd"
            Email = $u.mail
            Department = $u.department
            Company = $u.company
            Division = $u.Division
            Region = $u."le-region"[0]
            Country = $u.co
            UPN = $u.UserPrincipalName
        }
        $lead = "- " * ($l-1)
        Write-Host "$($lead)$($u.Description)"
        if ($l) {
            #Write-Host "Level $l DR $($u.DirectReports.Count)"
            $l++
        }
        foreach ($d in $u.DirectReports) {
            $drs = Get-AllDirectReports (Get-LEUser $d) $l
            foreach ($dr in $drs) {
                if ( $dr.manager -eq $null) {
                    $dr.Manager = $u.DisplayName
                }
                $Tree += $dr
            }
        }
    } else {
        #Write-host "$($u) is not Active"
    }
    return $Tree
}

$start = Get-DomUser $startingUser

$Output = Get-AllDirectReports $start 1

$Output | Select Employee,Email,Title,Manager,CoCd,Department,Company,Division,Region,Country,UPN | Export-csv -NoTypeInformation fullOrgTree.csv
