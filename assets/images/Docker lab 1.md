
---

---

Algunas de las secciones más comunes en un archivo Dockerfile son:

- **FROM**: se utiliza para especificar la imagen base desde la cual se construirá la nueva imagen.
- **RUN**: se utiliza para ejecutar comandos en el interior del contenedor, como la instalación de paquetes o la configuración del entorno.
- **COPY**: se utiliza para copiar archivos desde el sistema host al interior del contenedor.
- **CMD**: se utiliza para especificar el comando que se ejecutará cuando se arranque el contenedor

docker pull se permite instalar una imagen de docker de un registro que haya de docker 


Algunas de las instrucciones que vemos en esta clase son:

- **docker build**: es el comando que se utiliza para construir una imagen de Docker a partir de un Dockerfile.

La sintaxis básica es la siguiente:

➜ `docker build [opciones] ruta_al_Dockerfile`

El parámetro “**-t**” se utiliza para etiquetar la imagen con un nombre y una etiqueta. Por ejemplo, si se desea etiquetar la imagen con el nombre “**mi_imagen**” y la etiqueta “**v1**“, se puede usar la siguiente sintaxis:

➜ `docker build -t mi_imagen:v1 ruta_al_Dockerfile`

El punto (“**.**“) al final de la ruta al Dockerfile se utiliza para indicar al comando que busque el Dockerfile en el directorio actual. Si el Dockerfile no se encuentra en el directorio actual, se puede especificar la ruta completa al Dockerfile en su lugar. Por ejemplo, si el Dockerfile se encuentra en “**/home/usuario/proyecto/**“, se puede usar la siguiente sintaxis:

➜ `docker build -t mi_imagen:v1 /home/usuario/proyecto/`

- **docker pull**: es el comando que se utiliza para descargar una imagen de Docker desde un registro de imágenes.

La sintaxis básica es la siguiente:

➜ `docker pull nombre_de_la_imagen:etiqueta`

Por ejemplo, si se desea descargar la imagen “ubuntu” con la etiqueta “latest”, se puede usar la siguiente sintaxis:

➜ `docker pull ubuntu:latest`

- **docker images**: es el comando que se utiliza para listar las imágenes de Docker que están disponibles en el sistema.

La sintaxis básica es la siguiente:

➜ `docker images [opciones]`


docker -d para que corra en segundo plano 
-i para consola interactica 
-t para juntar todo 


El comando “**docker run**” se utiliza para crear y arrancar un contenedor a partir de una imagen. Algunas de las opciones más comunes para el comando “docker run” son:

- “**-d**” o “**–detach**“: se utiliza para arrancar el contenedor en segundo plano, en lugar de en primer plano.
- “**-i**” o “**–interactive**“: se utiliza para permitir la entrada interactiva al contenedor.
- “**-t**” o “**–tty**“: se utiliza para asignar un seudoterminal al contenedor.
- “**–name**“: se utiliza para asignar un nombre al contenedor.

Para arrancar un contenedor a partir de una imagen, se utiliza el siguiente comando:

➜ `docker run [opciones] nombre_de_la_imagen`

Por ejemplo, si se desea arrancar un contenedor a partir de la imagen “**mi_imagen**“, en segundo plano y con un seudoterminal asignado, se puede utilizar la siguiente sintaxis:

➜  `docker run -dit mi_imagen`

Una vez que el contenedor está en ejecución, se puede utilizar el comando “**docker ps**” para listar los contenedores que están en ejecución en el sistema. Algunas de las opciones más comunes son:

- “**-a**” o “**–all**“: se utiliza para listar todos los contenedores, incluyendo los contenedores detenidos.
- “**-q**” o “**–quiet**“: se utiliza para mostrar sólo los identificadores numéricos de los contenedores.

Por ejemplo, si se desea listar todos los contenedores que están en ejecución en el sistema, se puede utilizar la siguiente sintaxis:

➜  `docker ps -a`

Para ejecutar comandos en un contenedor que ya está en ejecución, se utiliza el comando “**docker exec**” con diferentes opciones. Algunas de las opciones más comunes son:

- “**-i**” o “**–interactive**“: se utiliza para permitir la entrada interactiva al contenedor.
- “**-t**” o “**–tty**“: se utiliza para asignar un seudoterminal al contenedor.

Por ejemplo, si se desea ejecutar el comando “**bash**” en el contenedor con el identificador “**123456789**“, se puede utilizar la siguiente sintaxis:

➜ `docker exec -it 123456789 bash`

Para utilizar el port forwarding, se utiliza la opción “**-p**” o “**–publish**” en el comando “**docker run**“. Esta opción se utiliza para especificar la redirección de puertos y se puede utilizar de varias maneras. Por ejemplo, si se desea redirigir el puerto 80 del host al puerto 8080 del contenedor, se puede utilizar la siguiente sintaxis:

➜ `docker run -p 80:8080 mi_imagen`

Esto redirigirá cualquier tráfico entrante en el puerto 80 del host al puerto 8080 del contenedor. Si se desea especificar un protocolo diferente al protocolo TCP predeterminado, se puede utilizar la opción “**-p**” con un formato diferente. Por ejemplo, si se desea redirigir el puerto 53 del host al puerto 53 del contenedor utilizando el protocolo UDP, se puede utilizar la siguiente sintaxis:

➜ `docker run -p 53:53/udp mi_imagen`

Para utilizar las monturas, se utiliza la opción “**-v**” o “**–volume**” en el comando “**docker run**“. Esta opción se utiliza para especificar la montura y se puede utilizar de varias maneras. Por ejemplo, si se desea montar el directorio “**/home/usuario/datos**” del host en el directorio “**/datos**” del contenedor, se puede utilizar la siguiente sintaxis:

➜ `docker run -v /home/usuario/datos:/datos mi_imagen`

