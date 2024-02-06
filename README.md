## GENERAL INFORMATION

This repository contains code for the fbproxy-based FreeBrowser, which consists of the following components:

- localhost proxy ('fbproxy') which is running on port 8888 and applies request modifications to circumvent censorship
- (for Desktop) latest Chrome browser, which is downloaded if not installed, and run together with fbproxy (proxying all traffic through it)
- (for Android) patches and instructions for Chromium to be compiled together with fbproxy

Uses several methods of circumvention, whichever succeeds first:

- DNS-over-HTTPs + No request modifications
- DNS-over-HTTPs + Empty SNI
- DNS-over-HTTPs + Fake SNI
- Domain fronting via CDN

DNS-over-HTTPs has three flavors:
- standard DNS-over-HTTPs
- HTTPs API for DNS resolution
- DNS-over-HTTPs-over-CDN (domain fronted DOH request)

## SUPPORTED OS

- Linux: Debian (Ubuntu, Debian, Mint) and Redhat (Fedora, CentOS)
- Windows (7, 8, 10, 11)
- MacOS
- Android

## LIST OF THIRD-PARTY DEPENDENCIES

- https://github.com/elazarl/goproxy (HTTP proxy library for Go, BSD-3-Clause license)
- https://github.com/refraction-networking/utls (Fork of the Go standard TLS library, providing low-level access to the ClientHello for mimicry purposes, BSD-3-Clause license)
- https://github.com/gorilla/websocket (WebSocket implementation for Go, BSD-3-Clause license)
- https://github.com/uber-go/zap (Blazing fast, structured, leveled logging in Go, MIT license)
- https://pkg.go.dev/golang.org/x/net/publicsuffix (Public suffix list based on data from https://publicsuffix.org/, BSD-3-Clause license)
- https://github.com/miekg/dns (DNS library in Go, BSD-3-Clause license)

## PROJECT STRUCTURE

- cmd/ - main package for standalone fbproxy executable
- freebrowser/android - patches and instructions for Chromium to be compiled together with the proxy
- freebrowser/desktop - scripts and files for building FreeBrowser Desktop
- pkg/ - fbproxy package for compiling fbproxy as a library

## COMPILE AND INSTALL

Tested for Ubuntu 20.04, go version 1.20.4

For Android target, you also have to download Android NDK from https://dl.google.com/android/repository/android-ndk-r25c-linux.zip, and unzip it to /opt/android-ndk-r25c/

Build standalone proxy executable:

```
install go (https://go.dev/doc/install)
go mod init fb-proxy
go mod tidy
cd cmd
./build-proxy.sh --os=[windows,linux,macos,android]
(use optional --dev flag for development build)
```

Running proxy in standalone mode on Linux:

- `./fbproxy`
- in background with logs: `./fbproxy --loglevel=debug > log.out 2>&1 &`

Running proxy in standalone mode on Android:

- `adb shell /data/local/tmp/fbproxy.arm64`
- with logging: `adb shell /data/local/tmp/fbproxy.arm64 --loglevel=debug > log.out`

Building packaged version with Chrome for Desktop: see freebrowser/desktop/README.md

Building packaged version with Chromium for Android (see freebrowser/android/README.md):

- fetch Chromium source code
- copy android/chromium/src/gfapp folder to Chromium's src/ directory
- rename "fbproxy.arm64" executable to "libfbproxy.so" and copy to src/gfapp/
- patch and build Chromium

## CONFIGURE DOMAIN FRONTING

First, configure your backend proxy (see our `fbnginx` repo). Record the IP address and verify that the backend service is working, for example by checking URLs like:
* `curl 'https://www.example.com' --resolve www.example.com:443:<your-backend-ip> -v -k` should return a standard nginx welcome page
* `curl 'https://www.example.com/df/random-hash' --resolve www.example.com:443:<your-backend-ip> -H 'X-Original-URL: https://duckduckgo.com' -v -k` should return a DuckDuckGo page

Then, create a CDN configuration. The process is different for each CDN provider but the general steps involved are as follows (though not necessarily in this exact order):

1. Create a CDN origin. You may be able to use the backend IP directly or you may have to create a subdomain that points at this IP (like origin.yourdomain.com).
2. If CDN has cache settings select the ones that are respecting the origin headers (and cache configuration). If configurable, make sure that query strings are included as part of the cache key and not ignored.
3. Make sure that SSL is enabled and use the CDN shared certificate (if this is configurable).
4. Check that all headers are forwarded to the origin.
5. Configure the domain that you intend to use. This could be the same domain as was optionally used in step 1. When setup has been completed, the service should be accessible using URLs like
* `curl https://yourdomain.com` should return a standard nginx welcome page
* `curl 'https://www.example.com/df/random-hash' --resolve www.example.com:443:<cdn-server-ip> -H 'Host: yourdomain.com' -H 'X-Original-URL: https://duckduckgo.com' -v -k` should return a DuckDuckGo page

Lastly, you have to add CDN details to the fbproxy configuration file `pkg/config/fb.config`. The format is as follows:

```
CDN-CIDRS<TAB><TAB><TAB><your-cdn-domain><TAB><cdn-server-ip-1>,<cdn-server-ip-2>,<cdn-server-ip-3>
CDN-CIDRS<TAB><TAB><TAB><your-second-cdn-domain><TAB><cdn-server-ip-4>,<cdn-server-ip-5>,<cdn-server-ip-6>

CDN-CERTS<TAB><yourdomain.com><TAB><allowed-cert-1>,<allowed-cert-2>,<allowed-cert-3>
CDN-CERTS<TAB><your-second-domain.com><TAB><allowed-cert-4>,<allowed-cert-5>,<allowed-cert-6>
```

For example,

```
CDN-CIDRS			yourdomain.com	192.168.1.1,192.168.1.2

CDN-CERTS	yourdomain.com	*.host.com,www.host.net
```

where `yourdomain.com` is the domain configured on the CDN and placed in the `Host` header, `192.168.1.1,192.168.1.2` is a comma-separated list of CDN server IP addresses, and `*.host.com,www.host.net` is a comma-separated list of domain names allowed in CDN server certificates (DNSNames/Subject Alternative Names)