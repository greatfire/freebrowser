#!/bin/bash
###
# Path: build-proxy.sh
# Builds fbproxy command line executable for Windows, Linux, Mac OS and Android
# Usage: ./build-proxy.sh --os=windows --dev
###

# exit on error
set -e

# check for arguments
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
            "android")
                echo "Android OS selected"
                os="android"
                ;;
            *)
                echo "Invalid --os option. Valid options are windows, linux, macos and android"
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
        echo "Usage: ./build-proxy.sh --os=windows"
        echo "Valid options for --os are windows, linux, macos and android"
        echo "Use --dev to build a development version"
        exit 0
        ;;

    esac
done

if [[ $os == "windows" ]]; then
    echo "Building for Windows OS"
    if [[ $dev == "true" ]]; then
        echo "Building development version"
        GOOS=windows GOARCH=amd64 go build -tags=dev -o fbproxy.exe main.go
    else
        echo "Building production version"
        GOOS=windows GOARCH=amd64 go build -tags=prod -o fbproxy.exe main.go
    fi
elif [[ $os == "linux" ]]; then
    echo "Building for Linux OS"
    if [[ $dev == "true" ]]; then
        echo "Building development version"
        GOOS=linux GOARCH=amd64 go build -tags=dev -o fbproxy main.go
    else
        echo "Building production version"
        GOOS=linux GOARCH=amd64 go build -tags=prod -o fbproxy main.go
    fi
elif [[ $os == "macos" ]]; then
    echo "Building for Mac OS"
    if [[ $dev == "true" ]]; then
        echo "Building development version"
        GOOS=darwin GOARCH=amd64 go build -tags=dev -o fbproxy_mac main.go
    else
        echo "Building production version"
        GOOS=darwin GOARCH=amd64 go build -tags=prod -o fbproxy_mac main.go
    fi
elif [[ $os == "android" ]]; then
    echo "Building for Android OS"
    if [[ $dev == "true" ]]; then
        echo "Building development version"
        CC=/opt/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang CXX=/opt/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -tags=dev -o fbproxy.arm64 main.go
    else
        echo "Building production version"
        CC=/opt/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang CXX=/opt/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -tags=prod -o fbproxy.arm64 main.go
    fi
else
    echo "Invalid OS option. Valid options are windows, linux, macos or android"
    exit 1
fi