# Meshcentral 2 router - Electron JS version

An ElectronJS + Photonkit application to ease certain application tunneling via [Meshcentral 2](https://github.com/Ylianst/MeshCentral). 
## Dependencies
ElectronJS should be installed.
```
npm i -g electron@latest
```
Next, install the dependencies.
```
npm install
```

## Configuration

Create config.json file to store your configuration.

```javascript
{
    "mesh_url": "https://meshcentral.com/",    
	"mesh_username": "username",
	"mesh_passwordb64": "password encoded in base64",
	"ssh": "C:\\Program Files\\PuTTY\\putty.exe",
	"sftp": "C:\\Program Files\\FileZilla FTP Client\\filezilla.exe",
	"rdp": "C:\\Windows\\System32\\mstsc.exe",
	"use_proxy": false,
	"proxy_type": "socks",
	"proxy_host": "proxy.company.com",
	"proxy_port": "1080"
}

```

## How to run
```
> electron .
```

## Custom application tunnelling

For more custom application tunneling, new command list JSON is added to add multiple list of application tunneling configurations.

```json
{
    "cmds" :
    [ 
		{ "id": 1, "label": "VNC to port 5901", "cmdexec": "C:\\Program Files\\TightVNC\\tvnviewer.exe", "cmdargs" : "127.0.0.1::lport","cmdport":"5901"},
		{ "id": 2, "label": "VNC to port 5902", "cmdexec": "C:\\Program Files\\TightVNC\\tvnviewer.exe", "cmdargs" : "127.0.0.1::lport","cmdport":"5902"},
		{ "id": 3, "label": "VNC to port 5903", "cmdexec": "C:\\Program Files\\TightVNC\\tvnviewer.exe", "cmdargs" : "127.0.0.1::lport","cmdport":"5903"},
		{ "id": 4, "label": "SSH port 22", "cmdexec": "C:\\Program Files\\PuTTY\\putty.exe", "cmdargs" : "-ssh 127.0.0.1 -P lport","cmdport":"22"}
    ]
}
```
Each entry need to have:
* label: This will be used as the title
* cmdexec: The path to binary/script to execute
* cmdargs: Commandline argument, please specify the target port of the application as string 'lport'
* cmdport: Target port at the destination device

## Credit
* Ylian St Hilaire
* Piero Fioravanti
* Shafin Jadavji
* Rico Cantrell
* Luca Levati

## Todo
* Add command list editor