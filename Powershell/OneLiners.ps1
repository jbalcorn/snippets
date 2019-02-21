import-module ActiveDirectory

# Don't actually run this file....
return

# [CmdletBinding( SupportsShouldProcess = $true )]

# All Inactive Excluding EXT, Disabled, Service and Training Accounts
Search-ADAccount -AccountInactive -Server $script:ADINFO[$script:GCDOM].GC -SearchBase "" -UsersOnly -TimeSpan "30" | Where {$_.Enabled -and (-Not ($_  -imatch "dc=ext|ou=ess|ou=_ess|ou=_new")) } | Get-ADUser -Prop DistinguishedName,DisplayName,UserPrincipalName,LastLogonTimestamp,EmployeeType,Enabled | Where {-Not ($_.employeeType -imatch "Service Accounts|Training Accounts")} | Select DistinguishedName,UserPrincipalName,EmployeeType,LastLogonTimestamp,Enabled | Export-CSV -noType UsersOver30.csv
Search-ADAccount -AccountInactive -Server $script:ADINFO[$script:GCDOM].GC -SearchBase "" -UsersOnly -TimeSpan "180" | Where {$_.Enabled -and (-Not ($_  -imatch "ou=Webapps|CN=ASPNET|CN=IUSR_|CN=IWAM_|CN=.*\$,CN=Users|CN=Administrator,|HealthMailbox")) } | Get-ADUser -Prop DistinguishedName,DisplayName,Description,UserPrincipalName,LastLogonTimestamp,EmployeeType,Enabled,employeeid | Where {-Not ($_.employeeType -imatch "Unknown|Active|Training Accounts")} | Select DistinguishedName,UserPrincipalName,EmployeeType,@{N="LastLogon";E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},@{N="Domain";E={Get-Domain $_.DistinguishedName -short}},EmployeeID,DisplayName,Description | Export-CSV -NoType InactiveUsers.csv

# Inactive Computers
Search-ADAccount -AccountInactive -Server $script:ADINFO[$script:GCDOM].GC -SearchBase "" -ComputersOnly -TimeSpan "180" | Where {$_.Enabled -and ( -Not ($_.distinguishedName -imatch "mobile" ))} | Get-ADComputer -Prop DistinguishedName,DNSHostName,LastLogon,LastLogonTimestamp | Select DistinguishedName,DNSHostName,@{ N = "Last Logon"; E={[DateTime]::FromFileTime($_.LastLogontimestamp)}} | Export-CSV -noType ComputersOver30.csv
Get-ADComputer -filter { LastLogon -lt $90daysago -and LastLogonTimestamp -lt $90daysago } -property name,lastlogon,lastlogontimestamp,OperatingSystem | Select Name,@{ N = "Last Logon"; E={[DateTime]::FromFileTime($_.LastLogon)}},@{ N = "Last Logon Timestamp"; E={[DateTime]::FromFileTime($_.LastLogontimestamp)}},OperatingSystem

# Password Never Expires, Excludes ESS and _New users
Search-ADAccount -PasswordNEverExpires -Server $script:ADINFO[$script:GCDOM].GC -SearchBase "" -UsersOnly  | Where {$_.Enabled  -and  (-Not ($_  -imatch "CN=Microsoft Exchange System Objects|ou=ess|ou=_ess|ou=_new|dc=ext|CN=Sophos"))} | Get-ADUser -Prop DistinguishedName,DisplayName,UserPrincipalName,LastLogonDate,EmployeeType,Enabled,PasswordLastSet,PrimaryGroupID | Where {(-Not ($_.employeeType -imatch "Service Accounts|Training Accounts") ) -and ( $_.PrimaryGroupID -ne "9103") } | Select DistinguishedName,UserPrincipalName,EmployeeType,LastLogonDate,@{N="Domain";E={(Get-Domain $_)}} | Export-CSV -noType UsersPwdNeverExpires.csv

#Terminated users that are enabled
Get-ADUser -ldapfilter '((|(employeetype=Terminated)(employeetype=Deleted))' -Server $script:ADINFO[$script:GCDOM].GC -SearchBase $script:ADINFO[$GCDOM].GC | where {$_.Enabled} | Get-ADUser -properties description,lastlogontimestamp | FT DistinguishedName,Description,LastLogontimestamp

# Enabled Not Normal Users
Get-ADUser -ldapfilter '(!(|(employeetype=active)(employeetype=terminated)(employeetype=deleted)(employeetype=admin accounts)(employeetype=expat accounts)(employeetype=training accounts)))' -Server $script:ADINFO[$script:GCDOM].GC -SearchBase "dc=corp,dc=le" | where {($_.Enabled -and (-Not ($_ -imatch "dc=ext")))} | Get-ADUser -properties description,lastlogontimestamp,employeetype,department,title,passwordlastset | Select DistinguishedName,Description,EmployeeType,@{N='LastLogon'; E={[DateTime]::FromFileTime($_.LastLogontimestamp)}} | Export-CSV -noType NotNormalUsers.csv

# Enabled Users not in HR
Get-ADUser -ldapfilter '(employeetype=unknown)' -Server $script:ADINFO[$dom].DC -searchbase $script:ADINFO[$dom].DN -properties Description,LastLogonTimestamp,AccountExpires,WhenCreated,manager| where {$_.Enabled} | Select DistinguishedName, Description, @{N='Manager'; E={$_.manager -replace '^CN=([^,]*),.*$','$1'}}, @{N='LastLogon'; E={[DateTime]::FromFileTime($_.LastLogontimestamp)}},@{N='AccountExpires'; E={[DateTime]::FromFileTime($_.AccountExpires)}},WhenCreated | Export-CSV -noType NotInHRAndEnabled.csv

# All Enabled Users without an employee type (not in EXT or MS Exch
Get-ADUser -ldapfilter  '(&(objectcategory=person)(objectclass=user)(!(employeeType=*)))' -server $script:ADINFO[$script:GCDOM].GC -searchbase $script:ADINFO[$script:GCDOM].DN | Where {$_.Enabled -and (-Not ($_  -imatch "dc=ext|CN=Microsoft Exchange System Objects"))} 

# Accounts that don't have an employee type
Get-ADUser -ldapfilter  '(&(objectcategory=person)(objectclass=user)(!(employeeType=*)))' -server $script:ADINFO[$dom].DC -searchbase $script:ADINFO[$dom].DN -properties IsCriticalSystemObject,Description,LastLogonTimestamp,AccountExpires,WhenCreated,manager | Where {$_.Enabled -and (-Not $_.IsCriticalSystemObject) -and  (-Not ($_  -imatch "dc=ext|CN=Microsoft Exchange System Objects"))} | Select DistinguishedName, Description, @{N='Manager'; E={$_.manager -replace '^CN=([^,]*),.*$','$1'}}, @{N='LastLogon'; E={[DateTime]::FromFileTime($_.LastLogontimestamp)}},@{N='AccountExpires'; E={[DateTime]::FromFileTime($_.AccountExpires)}},WhenCreated | Export-CSV -noType NoEmpType.csv

# Get all the possibe OU attributes
Get-ADUser -ldapfilter '(employeetype=active)' -server $script:ADINFO[$dom].DC -searchbase $script:ADINFO[$dom].DN -properties * | select Division,Company,Department,@{n="PositionCountry";e={[string]$_.postaladdress}},L,St,@{n="Region";e={[string]$_."LE-Region"}},LE-Cocd,Co,C,@{n="Function";e={[string]$_."LE-Function"}} | Export-CSV -notype MX.csv

# Mail enabled users. 1=Mailbox 128=mail-enabled
Get-ADUser -ldapfilter '(employeetype=*)' -properties msExchRecipientTypeDetails | where { $_.msExchRecipientTypeDetails -gt 0 }

# Report of all email users
Get-ADUser -ldapfilter '(&(objectclass=user)(objectcategory=Person)(mail=*))' -SearchBase $script:ADINFO[$script:GCDOM].DN -Server $script:ADINFO[$script:GCDOM].GC  -properties mail,sn,givenname | Where { ( -Not ( $_  -imatch "dc=ext")) } |  Select @{N="emailAddress";E={$_.mail}},@{N="firstName";E={$_.givenName}},@{N="lastName";E={$_.sn}} | export-csv -notype "AllEmailUsers.csv"

Get-ADUser -ldapfilter '(|(legacyExchangeDN=*)(mailnickname=*)(proxyaddresses=*)(showinaddressbook=*)(targetaddress=*))' -Server $dom -SearchBase $Connections[$dom] -properties legacyExchangeDN,mailnickname,proxyaddresses,showinaddressbook,targetaddress | Select samaccountname,legacyExchangeDN,mailnickname,proxyaddresses,showinaddressbook,targetaddress 

#All Computers in AD
Get-ADComputer -Filter * -prop CN,DNSHostName,LastLogonTimestamp,DistinguishedName,OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,WhenCreated  | Select CN,DNSHostName,DistinguishedName,@{ N = "Last Logon"; E={[DateTime]::FromFileTime($_.LastLogontimestamp)}},WhenCreated,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion | Export-csv -notype AlldomComputers.csv

# All departments in dom
Get-ADUser -ldapfilter '(&(department=*)(employeetype=active))' -properties department | Select department | sort-object department | Get-Unique -asstring

# Get expiration date
$r = Get-ADUser username -properties accountexpires | Select @{N="Expires";E={[DateTime]::FromFileTime($_.accountexpires)}}
Set-ADUser $r -AccountExpirationDate (Get-Date -Hour 0 -minute 00 -Second 00).AddDays(-1)

Get-ADUser username -properties AccountExpirationDate | Set-ADUser -AccountExpirationDate (Get-Date).AddDays(60)

Get-ADUser -ldapfilter '(employeetype=*)' -properties employeetype -server $script:ADINFO[$script:GCDOM].GC -searchbase "dc=corp,dc=le" | Select Employeetype | Sort-Object -property employeetype | Get-Unique -AsString

# Get a user's SID
[wmi] "win32_userAccount.domain='mx',name='username'"

# or
$AdObj = New-Object System.Security.Principal.NTAccount("Administrators")
$strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
$strSID.Value

# Find a user by SID
$strSID="S-1-5-21-2665622878-705676962-3208142745-500"
[ADSI]"LDAP://<SID=$strSID>"

# Password Expiry Time Computed!
$newgls | Select Name,@{N="Password Expires";E={[DateTime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}

# Get all the subdirectories
$dirs = GEt-ChildItem L:\Automation -Recurse | ?{$_.PSIsContain}


foreach ($f  in $findirs) {
    $acl = Get-Acl $f.Fullname

    foreach ($access in $acl.Access) {
        $acls += New-Object -TypeName PSObject -Property @{
            Path = $f.fullName
            Owner = $acl.Owner
            FileSystemRights = $access.FileSystemRights
            AccessControlType = $access.AccessControlType
            IdentityReference = $access.IdentityReference
            IsInherited = $access.IsInherited
            InheritanceFlahs = $access.InheritanceFlags
            PropagationFlags = $access.PropagationFlags
        }
    }
}


$acls | Select Path,Owner,IdentityReference,AccessControlType,FileSystemRights,IsInherited

#[System.Windows.Forms.MessageBox]::Show(
    #                [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")  | Out-Null
    #                if ( ([Microsoft.VisualBasic.Interaction]::MsgBox("Send Email to Manager?",'YesNoCancel,Question', "Query")) -eq "Yes" ) {

# Find a live computer
while ( -Not ($c = try { Test-Connection (get-content C:\temp\LocalAdminScans\apworkstations.txt | Get-Random) -Count 1 -TimeToLive 10 } catch {} ))  {  }

#Store a passsword securely
$pass = 'P@ssw0rd'
$pass | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | out-File 'password.txt'
# Read that password into a credential
$credentials = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList 'username',(Get-Content 'password.txt' | ConvertTo-SecureString )

# Make sure Powershell uses TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

