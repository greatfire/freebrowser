#!/bin/bash
###
# Path: build-browser.sh
# Builds FreeBrowser Desktop executable for Windows, Linux and Mac OS
# Usage: ./build-browser.sh --os=windows
###

# exit on error
set -e

# check for --os argument
for arg in "$@"
do
    case $arg in
        --os=*)
        argOS="${arg#*=}"
        case $argOS in
            "windows")
                echo "Windows OS selected"
                os="windows"
                ;;
            "linux")
                echo "Linux OS selected"
                os="linux"
                ;;
            "macos")
                echo "Mac OS selected"
                os="macos"
                ;;
            *)
                echo "Invalid OS option. Valid options are windows, linux and macos"
                exit 1
                ;;
        esac
        shift
        ;;

        --dev)
        echo "Development build selected"
        dev="true"
        shift
        ;;

        --help)
        echo "Usage: ./build-browser.sh --os=windows"
        echo "Valid options for --os are windows, linux and macos"
        exit 0
        ;;

    esac
done

# first archive files directory
# if OS is Windows, archive with zip fbproxy.exe binary and chrome folder from files directory
# if OS is Linux, archive with zip fbproxy binary and chrome folder from files directory
# if OS is MacOS, archive with zip fbproxy_mac binary and chrome folder from files directory
echo "Creating files.zip"
cd files
if [[ ! -e chrome ]]; then
    echo "Error: chrome does not exist"
    exit 1
fi
if [[ $os == "windows" ]]; then
    if [[ ! -e fbproxy.exe ]]; then
        echo "Error: fbproxy.exe does not exist"
        exit 1
    fi
    zip -r files.zip fbproxy.exe chrome
elif [[ $os == "linux" ]]; then
    if [[ ! -e fbproxy ]]; then
        echo "Error: fbproxy does not exist"
        exit 1
    fi
    zip -r files.zip fbproxy chrome
elif [[ $os == "macos" ]]; then
    if [[ ! -e fbproxy_mac ]]; then
        echo "Error: fbproxy_mac does not exist"
        exit 1
    fi
    zip -r files.zip fbproxy_mac chrome
else
    echo "Invalid OS option. Valid options are windows, linux or macos"
    exit 1
fi
cd ..
mv files/files.zip .

# then build executable
if [[ $os == "windows" ]]; then
    echo "Creating .syso file"
    goversioninfo -o=versioninfo-windows.syso versioninfo-windows.json
    echo "Building Windows executable"
    if [[ $dev == "true" ]]; then
        echo "Building development version"
        GOOS=windows GOARCH=amd64 go build -tags=dev -o freebrowser.exe
    else
        echo "Building production version"
        GOOS=windows GOARCH=amd64 go build -tags=prod -o freebrowser.exe
    fi
elif [[ $os == "linux" ]]; then
    echo "Building Linux executable"
    if [[ $dev == "true" ]]; then
        echo "Building development version"
        GOOS=linux GOARCH=amd64 go build -tags=dev -o freebrowser_linux freebrowser.go
    else
        echo "Building production version"
        GOOS=linux GOARCH=amd64 go build -tags=prod -o freebrowser_linux freebrowser.go
    fi
elif [[ $os == "macos" ]]; then
    echo "Building MacOS executable"
    if [[ $dev == "true" ]]; then
        echo "Building development version"
        GOOS=darwin GOARCH=amd64 go build -tags=dev -o freebrowser_mac freebrowser.go
    else
        echo "Building production version"
        GOOS=darwin GOARCH=amd64 go build -tags=prod -o freebrowser_mac freebrowser.go
    fi
else
    echo "Invalid OS option. Valid options are windows, linux and macos"
    exit 1
fi

echo done
