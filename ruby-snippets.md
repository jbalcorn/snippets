Convert your OLD and NEW passwords into some goofy kind of unicode.
Create a two element array (1. delete old password element, 2. Add new
password element) that modifies the unicodePwd attribute (represented as
:unicodePwd). Run an ldap modify on the proper dn for the user passing
it both operations from the array (if you need to know how to get the
user dn let me know but there are lots of examples out there.). If it
succeeds it will update the password!
````ruby
def self.ct2uni(cleartextpwd)
    quotepwd = '"' + cleartextpwd + '"'
    unicodepwd = Iconv.iconv('UTF-16LE', 'UTF-8', quotepwd).first
    return unicodepwd
end
oldUniPW = ct2uni( opassword )
newUniPW = ct2uni( newpass )
ops = [
    [ :delete, :unicodePwd, [oldUniPW] ],
    [ :add, :unicodePwd, [newUniPW] ]
]
unless( ldap_con.modify :dn => dn, :operations => ops )
    ret[ :status ] = false
    ret[ :message ] = "bad:!:Error changing password for user #{login}."
    return( ret )
end
````
From <https://www.ruby-forum.com/topic/184880> 

````ruby


    def microsoft_encode_password(pwd)
      ret = ""
      pwd = "\"" + pwd + "\""
      pwd.length.times{|i| ret+= "#{pwd[i..i]}\000" }
      ret
    end
````
From <https://www.ruby-forum.com/topic/184880> 
