## Requirements

Tested for Ubuntu 20.04, go version 1.20.4

- (for Windows builds) `go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo`
- (for MacOS builds) download and install Platypus app (https://sveinbjorn.org/platypus)

## Build process

- (if go.mod and go.sum are not present) Run `go mod init freebrowser` and `go mod tidy`
- Copy compiled `fbproxy.exe`/`fbproxy`/`fbproxy_mac` from `cmd` to `freebrowser/desktop/files` folder
- (if certificate was updated) Copy your `proxy.pem` certificate from config folder to `freebrowser/desktop/files/chrome` folder
- (if certificate was updated, only for Linux builds) Create NSS database in `freebrowser/desktop/files/chrome/.pki/nssdb` and import certificate to it (see 'How to create NSS database and import certificate' below)
- (only for Windows builds) Modify manifest-windows.xml and versioninfo-windows.json accordingly
- Run `build-browser.sh --os=windows` (`linux`, `macos`), it will archive corresponding files from the `files` folder to `files.zip` and compile `freebrowser.exe`/`freebrowser_linux`/`freebrowser_mac` executable, embedding this archive

## How to create NSS database and import certificate (on Ubuntu)

- `sudo apt install libnss3-tools`
- `mkdir -p freebrowser/desktop/files/chrome/.pki/nssdb`
- `cd freebrowser/desktop/files/chrome/.pki/nssdb`
- `certutil -N -d sql:.` (leave empty password)
- `certutil -A -d sql:. -t "C,," -n "FreeBrowser" -i ../../proxy.pem`

## How to create MacOS .app package

- To create a MacOS .app package, use Platypus app
- Set an icon (`package-macos/icon_macos.icns`), app name, identifier, author, and version
- Set the script type to AppleScript and use `package-macos/fbapprun.scpt` as a script
- Add compiled `freebrowser_mac` executable to the bundled files
- Click Create App

## Running FreeBrowser Desktop

- On Linux, add permissions to run the executable: `chmod +x freebrowser_linux`, then run it: `./freebrowser_linux`
- On Windows, run `freebrowser.exe` (it will run as Administrator by default, but might ask for firewall access)
- On MacOS, run .app package as usual, and give required permissions