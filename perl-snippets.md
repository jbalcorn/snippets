Code to pick up all AD entries using pages
````perl
#!/usr/bin/perl
use strict;
$|=1;

##########################################################
# Perl Modules
##########################################################
use DBI;
use Time::Local;
use Data::Dumper;
use Net::LDAP;
use Net::LDAP::Entry;
use Net::LDAP::Util qw( ldap_explode_dn );
use Unicode::Map8;
use Unicode::String qw(utf16);
use Term::Prompt;
use Digest::MD5  qw(md5 md5_hex md5_base64);
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED LDAP_NO_SUCH_OBJECT);
use POSIX qw(strftime);
use DateTime::Format::Strptime;
use Mail::Sendmail;
use Encode;
use DateTime;

#########################################################
# Variables Changed for Testing
#########################################################
use constant GCBASE => "dc=corp";
use constant ADBASE => "dc=mydom,".GCBASE;
use constant GCDN => 'admin@corp';
use constant ROOTDN => "cn=Administrator,cn=Users,".ADBASE;
use constant ROOTDNPW => "password";
use constant GCHOST => "corp:3269";
use constant ADHOST => "dom.corp";

##########################################################
# AD Constants
##########################################################
use constant ADS_UF_SCRIPT => 0x0001;                          # The logon script will be executed
use constant ADS_UF_ACCOUNTDISABLE => 0x0002;                  # Disable user account
use constant ADS_UF_HOMEDIR_REQUIRED => 0x0008;                # Requires a root directory
use constant ADS_UF_LOCKOUT => 0x0010;                         # Account is locked out
use constant ADS_UF_PASSWD_NOTREQD => 0x0020;                  # No password is required
use constant ADS_UF_PASSWD_CANT_CHANGE => 0x0040;              # The user cannot change the password
use constant ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED => 0x0080; # Encrypted password allowed
use constant ADS_UF_TEMP_DUPLICATE_ACCOUNT => 0x0100;          # Local user account
use constant ADS_UF_NORMAL_ACCOUNT => 0x0200;                  # Typical user account
use constant ADS_UF_PASSWORD_NEVER_EXPIRES => 0x10000;
use constant INITIAL_ADS_ACCOUNT => ADS_UF_ACCOUNTDISABLE + ADS_UF_NORMAL_ACCOUNT ;
use constant FINAL_ADS_ACCOUNT => INITIAL_ADS_ACCOUNT + ADS_UF_PASSWORD_NEVER_EXPIRES;
use constant DISABLED_USER => ADS_UF_NORMAL_ACCOUNT + ADS_UF_ACCOUNTDISABLE;

my %adinfo = (
        'CORP' => {
                host => "ldaps://host1.corp",
                upn => '@corp',
                base => "dc=corp"
        },
        'dom' => {
                host => "ldaps://host1.dom.corp",
                upn => '@dom.corp',
                base => "dc=dom,dc=corp"
        },
);

select STDERR;
my $adpw = &prompt("p","Password for ".GCDN.":","","");
print "\n";
select STDOUT;

foreach my $dom (keys %adinfo) {
    $conn{$dom} = Net::LDAP->new($adinfo{$dom}{host},verify=>'none')  or  die "Failed to connect to ".$adinfo{$dom}{host}.": $@";
    my $mesg = $conn{$dom}->bind(GCDN,
                         password => $adpw);
$mesg->code && die $mesg->error;
}

$gc = Net::LDAP->new('ldaps://'.GCHOST,verify=>'none')  or  die GCHOST.": $@";
$mesg = $gc->bind(GCDN,
             password => $adpw);
$mesg->code && die $mesg->error;


sub updateExistingAccount {
        my ($ldap,$adentry,$a) = @_;
        my $changes = 0;
        my $dn = $adentry->dn();
        my $empid = $adentry->get_value('employeeid');
        my $dom = getDomFromDN($dn);
        my $output = "Changes to be made to $empid $dn:\n";
        foreach my $attr (keys %{$a}) {
                if (my $attrval =  $adentry->get_value($attr) || $attr eq "countrycode") {
                        if ($a->{$attr} eq "NULL") {
                                $adentry->delete($attr);
                                $output .= "\t$attr: $attrval => REMOVED\n";
                                $changes++;
#                       } elsif ($a->{$attr} && Encode::decode("utf8",$attrval) ne Encode::decode("utf8",$a->{$attr})) {
                        } elsif ($a->{$attr} && $attrval ne $a->{$attr}) {
                                $adentry->replace($attr => $a->{$attr});
                                $output .= "\t$attr: $attrval => $a->{$attr}\n";
                                $changes++;
                        }
                } elsif ($a->{$attr} && $a->{$attr} ne "NULL") {
                        $adentry->add($attr => $a->{$attr});
                        $output .= "\t$attr: NULL => $a->{$attr}\n";
                        $changes++;
                }
        }
        if ($changes) {
                log_info $output;
                if (!$testonly) {
                        my $result = $adentry->update($ldap);
                        $result->code && die "failed to update entry $dn: ", $result->error ;
                }
                return 1;
        }
        return 0;
}

my $genTimeFormat = DateTime::Format::Strptime->new(
    pattern  => "%Y%m%d%H%M%S.0Z",
    time_zone => "UTC"
);
my $page = Net::LDAP::Control::Paged->new( size => 100 );
my $cookie;
my $count = 0;
my $filter = '(employeeType=Active)';
while (1) {
        my $mesg = $gc->search(
                base => "dc=corp,dc=le",
                filter => $filter,
                control => [ $page ]
                );
        $mesg->code && die  "Error on search: $@ : ".$mesg->error;

        while (my $gce = $mesg->pop_entry()) {
                my $dn = $gce->dn();
        }
     my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
    $cookie    = $resp->cookie or last;

    # Paging Control
    $page->cookie($cookie);
}
if ($cookie) {
    print "abnormal exit\n";
   # We had an abnormal exit, so let the server know we do not want any more
   $page->cookie($cookie);
   $page->size(0);
   $ldap->search( control => [ $page ] );
}
````
 Sub to determine if a date attribute in AD has passed a certain date
 ````perl
 sub pastStartDate {
	my ($adentry,$startdt) = @_;
	if (! $startdt) {
		$startdt = $adentry->get_value('le-startDate');
	}
	if ($startdt) {
		my $tomorrow = time()+(60*60*24);
		my $year = substr($startdt,0,4);
		my $mon = substr($startdt,4,2);
		my $day = substr($startdt,6,2);
		if (my $stdt = DateTime->new(
			year       => $year,
			month      => $mon,
			day        => $day,
			hour       => 12,
			minute     => 00,
			second     => 00,
			nanosecond => 0,
			time_zone  => 'UTC',
			)) {
			my $stdtepoch = $stdt->epoch;
			if ($stdtepoch > $tomorrow) {
				return 0;
			} else {
				return 1;
			}
		}
	} else {
		return 1;
	}
	return 1;
}
````
Set up a password (possibly random) for Active Directory. Yes I know its weak. Just an example of the right way to create the string
````perl
sub create_initial_pw {
	my ($part1,$part2,$part3) = @_;
	if (!($part1) ) {
		$part1=rand(10000);
		$part2 = rand(100);
		$part3 = rand(100);
	} 
	my $pw = $charmap->tou('"'.sprintf("RANDOM%04d%02d%02d",$part1,$part2,$part3).'"')->byteswap()->utf16();
	return $pw;
}
````

Group Membership
````perl
# Is DN a direct member of group?
# Usage: <bool> = IsMemberOf(<DN of object>, <DN of group>)
sub isMemberOf($$) {
	my ($object, $groupDN) = @_;
	return if ($groupDN eq "");
	return if ($object eq "");

	$groupDN = lc($groupDN);
	my $objectDN = $object->dn();
	my $userDom = getDomFromDN($objectDN);
	 
	my @MCgroups = $object->get_value("memberOf");
	my @groups = map { lc } @MCgroups;
	my @matches = grep { $_ eq $groupDN } @groups;
 
	@matches > 0;
}
 
# Is DN a member of security groupi, either directly or as a member of a member group?
# Usage: <bool> = IsMemberOfSecurity(<DN of object>, <DN of group>)
sub isMemberOfSecurity($$) {
	my ($objectDN, $groupDN) = @_;
	return if ($groupDN eq "");

	my $groupDom = getDomFromDN($groupDN);
	my $userDom = getDomFromDN($objectDN);
	 
	my $groupSid = GetSidByDN($conn{$groupDom}, $groupDN);
	return if ($groupSid eq "");
 
	my @matches = grep { $_ eq $groupSid } GetTokenGroups($conn{$userDom}, $objectDN);
 
	@matches > 0;
}

# Gets tokenGroups attribute from the provided DN
# Usage: <Array of tokens> = GetTokenGroups(<LDAP ref>, <DN of object>)
sub GetTokenGroups($$) {
	my ($ldap, $objectDN) = @_;
 
	my $results = $ldap->search(
	   base => $objectDN,
	   scope => 'base',
	   filter => '(objectCategory=*)',
	   attrs => ['tokenGroups']
	);
 
	if ($results->count) {
	   return $results->entry(0)->get_value('tokenGroups');
	}
}
 
# Get object's SID by DN
# Usage: <SID> = GetSidByDN(<LDAP ref>, <DN>)
sub GetSidByDN($$) {
	my ($ldap, $objectDN) = @_;
 
	my $results = $ldap->search(
	   base => $objectDN,
	   scope => 'base',
	   filter => '(objectclass=*)',
	   attrs => ['objectSid']
	);
 
	if ($results->count) {
	   return $results->entry(0)->get_value('objectSid');
	}
}
 
# Get object's SID by sAMAccountName
# Usage: <SID> = GetSidByID(<LDAP ref>, <sAMAccountName>)
sub GetSidByID($$) {
	my ($ldap, $ID) = @_;
 
	my $results = $ldap->search(
	   base => GetRootDN($ldap),
	   filter => "(&(objectclass=user)(sAMAccountName=$ID))",
	   attrs => ['objectSid']
	);
 
	if ($results->count) {
	   return $results->entry(0)->get_value('objectSid');
	}
}
 
# Get DN by sAMAccountName
# Usage: <DN> = GetDNByID(<LDAP ref>, <ID>)
sub GetDNByID($$) {
	my ($ldap, $ID) = @_;
 
	my $results = $ldap->search(
	   base => GetRootDN($ldap),
	   filter => "(&(objectclass=user)(sAMAccountName=$ID))",
	   attrs => ['distinguishedName']
	);
 
	if ($results->count) {
	   return $results->entry(0)->get_value('distinguishedName');
	}
}
 
# Get sAMAccountName by object's SID
# Usage: <ID> = GetIDBySid(<LDAP ref>, <SID>)
sub GetIDBySid($$) {
	my ($ldap, $objectSid) = @_;
 
	my $results = $ldap->search(
	   base => '<SID=' . unpack('H*', $objectSid) . '>',
	   scope => 'base',
	   filter => '(objectclass=*)',
	   attrs => ['sAMAccountName']
	);
 
	if ($results->count) {
	   return $results->entry(0)->get_value('sAMAccountName');
	}
}

 

````

Set a password
````perl
$mesg = $conn{$coDom}->modify($dn,
  changes => [
	  replace	=> [ 
		  unicodePwd => $newUniPW,
			primaryGroupID => $primaryGroupToken,
			userAccountControl => FINAL_ADS_ACCOUNT,
	  ] 
  ]
);
$mesg->code && log_error "At ".__FILE__." line ".__LINE__.":$dn:".$mesg->error;
````
