---
tags:
title: BreachBlocker Unlocker - Hard (THM)
permalink: /BreachBlocker-Unlocker-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.66.165.34
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-19 18:45 -0400
Initiating Ping Scan at 18:45
Scanning 10.66.165.34 [4 ports]
Completed Ping Scan at 18:45, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:45
Completed Parallel DNS resolution of 1 host. at 18:45, 0.50s elapsed
Initiating SYN Stealth Scan at 18:45
Scanning 10.66.165.34 [65535 ports]
Discovered open port 22/tcp on 10.66.165.34
Discovered open port 25/tcp on 10.66.165.34
Discovered open port 8443/tcp on 10.66.165.34
Completed SYN Stealth Scan at 18:45, 10.61s elapsed (65535 total ports)
Nmap scan report for 10.66.165.34
Host is up, received echo-reply ttl 62 (0.17s latency).
Scanned at 2026-03-19 18:45:29 EDT for 10s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE   REASON
22/tcp   open  ssh       syn-ack ttl 62
25/tcp   open  smtp      syn-ack ttl 61
8443/tcp open  https-alt syn-ack ttl 61

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.46 seconds
           Raw packets sent: 102729 (4.520MB) | Rcvd: 65549 (2.622MB)
-e [*] IP: 10.66.165.34
[*] Puertos abiertos: 22,25,8443
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,25,8443 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-19 18:45 -0400
Nmap scan report for 10.66.165.34
Host is up (0.17s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e9:72:ac:df:7b:61:c4:c9:a0:07:48:d0:d7:86:f6:b3 (ECDSA)
|_  256 25:20:4b:e5:12:dd:4a:f9:79:fd:97:b4:d3:1e:4a:2a (ED25519)
25/tcp   open  smtp     Postfix smtpd
| smtp-commands: hostname, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
|_ 2.0.0 Commands: AUTH BDAT DATA EHLO ETRN HELO HELP MAIL NOOP QUIT RCPT RSET STARTTLS VRFY XCLIENT XFORWARD
8443/tcp open  ssl/http nginx 1.29.3
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: Mobile Portal
|_http-server-header: nginx/1.29.3
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2025-12-11T05:00:31
|_Not valid after:  2026-12-11T05:00:31
Service Info: Host:  hostname; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.11 seconds
```

## Website

![[Pasted image 20260319194701.png]]

![[Pasted image 20260319200405.png]]

![[Pasted image 20260319200809.png]]

![[Pasted image 20260319202553.png]]

![[Pasted image 20260319203123.png]]

```bash
zs1n@ptw ~> aiosmtpd -n -l 0.0.0.0:25
---------- MESSAGE FOLLOWS ----------
Received: from [172.18.0.2] (sq5_app-v2_1.sq5_default [172.18.0.2])
	by hostname (Postfix) with ESMTP id 5C2F0100561
	for <zsln@[192.168.210.140]>; Thu, 19 Mar 2026 23:30:43 +0000 (UTC)
X-Peer: ('10.66.165.34', 54460)

    Subject: Your OTP for HopsecBank

    Dear you,
    The OTP to access your banking app is 632142.

    Thanks for trusting Hopsec Bank!
------------ END MESSAGE ------------
```

![[Pasted image 20260319203607.png]]

![[Pasted image 20260319203627.png]]