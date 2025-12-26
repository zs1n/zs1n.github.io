---
tags:
title: Scrambled - Medium (HTB)
permalink: /Scrambled-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

Primero realizamos un escaneo de puerto en toda la red 

```ruby 
nmap -sS -p- --open --min-rate 5000 -n -vvv 10.10.10.43
```

Hacemos un chequeo de que recursos hay a nivel de red compartidos en la red 

```python
smbclient -L 10.10.10.43 -N #Para hacer uso de un NULLSESSION
```

Podemos ver una respuesta como esta donde no da a entender que no se realizar o no esta habilitado la Autenticacion NTLM, pero para asegurarnos comprobamos con herramientas distintas\

```python 
smbmap -H 10.10.10.43 -N
```

```
crackmapexec smb 10.10.10.43 #Donde podemos no podemos ver los dominios correspondientes a la maquina 
```


## Puerto 1433 - MsSQL Service

```bash 
mssqlclient dominio/user:password@10.10.10.43
```