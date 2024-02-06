# Checking out and building Chromium for Android

## System requirements

* A 64-bit Intel machine running Linux with at least 8GB of RAM. More
  than 32GB is highly recommended.
* At least 100GB of free disk space.
* You must have Git and Python installed already.
* Most development is done on Ubuntu. Other distros may or may not work, Ubuntu 20.04 recommend

*Building the Android client on Windows or Mac is not supported and doesn't work*.

## Install depot\_tools

Clone the `depot_tools` repository:

```shell
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
```

Add `depot_tools` to the end of your PATH (you will probably want to put this
in your `~/.bashrc` or `~/.zshrc`). Assuming you cloned `depot_tools`
to `/path/to/depot_tools`:

```shell
export PATH="$PATH:/path/to/depot_tools"
```

## Get the code

Create a `chromium` directory for the checkout and change to it (you can call
this whatever you like and put it wherever you like, as
long as the full path has no spaces):

```shell
mkdir ~/chromium && cd ~/chromium
fetch --nohooks android
```

If you don't want the full repo history, you can save a lot of time by
adding the `--no-history` flag to `fetch`.

Expect the command to take 30 minutes on even a fast connection, and many
hours on slower ones.

If you've already installed the build dependencies on the machine (from another
checkout, for example), you can omit the `--nohooks` flag and `fetch`
will automatically execute `gclient runhooks` at the end.

When `fetch` completes, it will have created a hidden `.gclient` file and a
directory called `src` in the working directory.

## Checkout chromium source for for FreeBrowser

Checkout tags/117.0.5938.83

```shell
cd ~/chromium/src
git checkout -b tags/117.0.5938.83 tags/117.0.5938.83
```

Sync with branch heads
```shell
cd ..
gclient sync --with_branch_heads
```


(This is the only difference between `fetch android` and `fetch chromium`.)


## Setup extra patch for FreeBrowser

Checkout fb-proxy source code 
```shell
cd /opt
git clone <repo URL>
```

Build and copy compiled proxy executable to gfapp folder as "libfbproxy.so"
```shell
cd /opt/fb-proxy/cmd
./build-proxy.sh --os=android
cp /opt/fb-proxy/cmd/fbproxy.arm64 /opt/fb-proxy/freebrowser/android/chromium/src/gfapp/libfbproxy.so
```

Copy gfapp folder to chromium source code
```shell
cp -r /opt/fb-proxy/freebrowser/android/chromium/src/gfapp ~/chromium/src/
```

Patch patch for chromium code base
```shell
cd ~/chromium/src
patch -p1 < /opt/fb-proxy/freebrowser/android/chromium/src/001.patch
```

## Generate Android keystore

From the `~/chromium/src/gfapp` folder, run following command to generate keystore file:

```
keytool -genkey -v -keystore gf.keystore -alias <keystore name> -keyalg RSA -sigalg SHA1withRSA -keysize 2048 -validity 10000
```

Note down the keystore alias name and password, you will need it later.

## Setting up the build

Chromium uses [Ninja](https://ninja-build.org) as its main build tool along with
a tool called [GN](https://gn.googlesource.com/gn/+/main/docs/quick_start.md)
to generate `.ninja` files. You can create any number of *build directories*
with different configurations. To create a build directory which builds Chrome
for Android, run `gn args out/arm64` and edit the file according to 
`/opt/fb-proxy/freebrowser/android/chromium/src/args.gn`

* You only have to run this once for each new build directory, Ninja will
  update the build files as needed.
* You can replace `arm64` with another name, but
  it should be a subdirectory of `out`.
* For other build arguments, including release settings, see [GN build
  configuration](https://www.chromium.org/developers/gn-build-configuration).
  The default will be a debug component build.
* For more info on GN, run `gn help` on the command line or read the
  [quick start guide](https://gn.googlesource.com/gn/+/main/docs/quick_start.md).

Also be aware that some scripts (e.g. `tombstones.py`, `adb_gdb.py`)
require you to set `CHROMIUM_OUTPUT_DIR=out/arm64`.


## Build Chromium

Build Chromium android apk with Ninja using the command:

```shell
autoninja -C out/arm64 chrome_public_apk
```
(`autoninja` is a wrapper that automatically provides optimal values for the
arguments passed to `ninja`.)

You will find the apk in the following directory:

```shell
out/arm64/apks/ChromePublic.apk
```

## Possible build errors

* If following error message occurs during building, just run build command again:

```
During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "../../build/android/gyp/compile_java.py", line 789, in <module>
    sys.exit(main(sys.argv[1:]))
  File "../../build/android/gyp/compile_java.py", line 778, in main
    md5_check.CallAndWriteDepfileIfStale(lambda changes: _OnStaleMd5(
  File "/chromium/src/build/android/gyp/util/md5_check.py", line 56, in CallAndWriteDepfileIfStale
    CallAndRecordIfStale(
  File "/chromium/src/build/android/gyp/util/md5_check.py", line 155, in CallAndRecordIfStale
    function(*args)
  File "../../build/android/gyp/compile_java.py", line 778, in <lambda>
    md5_check.CallAndWriteDepfileIfStale(lambda changes: _OnStaleMd5(
  File "../../build/android/gyp/compile_java.py", line 429, in _OnStaleMd5
    _RunCompiler(changes,
  File "../../build/android/gyp/compile_java.py", line 580, in _RunCompiler
    shutil.rmtree(temp_dir)
  File "/usr/lib/python3.8/shutil.py", line 709, in rmtree
    onerror(os.lstat, path, sys.exc_info())
  File "/usr/lib/python3.8/shutil.py", line 707, in rmtree
    orig_st = os.lstat(path)
```

* If following error message occurs during building, execute `find out/arm64/ -name *_jni.srcjar -delete` to regenerate jni relative files

```
Warning: Missing class org.chromium.base.natives.GEN_JNI (referenced from: void org.chromium.chrome.browser.keyboard_accessory.AutofillKeyboardAccessoryViewBridgeJni.deletionConfirmed(long, org.chromium.chrome.browser.keyboard_accessory.AutofillKeyboardAccessoryViewBridge) and 251 other contexts)
Warning: Discard checks failed.
The following items were not discarded
Item org.chromium.chrome.browser.keyboard_accessory.AutofillKeyboardAccessoryViewBridgeJni was not discarded.
org.chromium.chrome.browser.keyboard_accessory.AutofillKeyboardAccessoryViewBridgeJni
|- is referenced from:
|  void org.chromium.chrome.browser.keyboard_accessory.AutofillKeyboardAccessoryViewBridge.dismissed()
|- is invoked from:
|  void org.chromium.chrome.browser.keyboard_accessory.AutofillKeyboardAccessoryViewBridge.dismiss()
|- is referenced in keep rule:
|  ../../build/android/chromium_annotations.flags:30:1
```

## Install apk to Android device

You can install FreeBrowser apk from command line:

```shell
adb install -r out/arm64/apks/ChromePublic.apk
```

## Re-patching repo

To re-patch already patched Chromium repo (for example, after amending patch code), run following commands, then copy over new gfapp, patch and build apk again:

```shell
cd ~/chromium/src
git stash
rm -rf gfapp
```