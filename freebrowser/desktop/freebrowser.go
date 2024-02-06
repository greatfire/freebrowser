package main

import (
	"bytes"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	config "freebrowser/config"

	"github.com/mholt/archiver"
	"github.com/shirou/gopsutil/process"
)

const (
	chromeURLWindows        = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
	chromeURLDebian         = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
	chromeURLRedhat         = "https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm"
	chromeURLMacOS          = "https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg"
	chromeInstallerWindows  = "chrome_installer.exe"
	chromeInstallerDebian   = "google-chrome-stable_current_amd64.deb"
	chromeInstallerRedhat   = "google-chrome-stable_current_x86_64.rpm"
	chromeInstallerMacOS    = "googlechrome.dmg"
	proxyURL                = "http://localhost:" + config.ProxyPort
	proxyExeWindows         = "fbproxy.exe"
	proxyExeLinux           = "fbproxy"
	proxyExeMacOS           = "fbproxy_mac"
	prefDirBaseWindows      = "Google/Chrome/FbproxyProfile"
	prefDirBaseLinux        = ".config/google-chrome/FbproxyProfile"
	prefDirBaseMacOS        = "Library/Application Support/Google/Chrome/FbproxyProfile"
	prefFileBase            = "Default/Preferences"
	chromeExePathWindowsx64 = `C:\Program Files\Google\Chrome\Application\chrome.exe`
	chromeExePathWindowsx86 = `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`
	chromeExeLinux          = "google-chrome"
	chromeExeMacOS          = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)

var (
	proxyPath = ""
	prefDir   = ""
)

type Preferences struct {
	Session struct {
		RestoreOnStartup int      `json:"restore_on_startup"`
		StartupUrls      []string `json:"startup_urls"`
	} `json:"session"`
}

//go:embed files.zip
var EmbeddedFiles embed.FS

func installChrome(tempDir string) {
	proxyURL, _ := url.Parse(proxyURL)

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   600 * time.Second,
	}

	var chromeURL string
	var chromeInstaller string
	if runtime.GOOS == "linux" {
		if exists, _ := pathExists("/etc/debian_version"); exists {
			fmt.Println("Downloading Google Chrome for Debian/Ubuntu...")
			chromeURL = chromeURLDebian
			chromeInstaller = chromeInstallerDebian
		}
		if exists, _ := pathExists("/etc/redhat-release"); exists {
			fmt.Println("Downloading Google Chrome for Red Hat...")
			chromeURL = chromeURLRedhat
			chromeInstaller = chromeInstallerRedhat
		}
	} else if runtime.GOOS == "windows" {
		fmt.Println("Downloading Google Chrome for Windows...")
		chromeURL = chromeURLWindows
		chromeInstaller = chromeInstallerWindows
	} else if runtime.GOOS == "darwin" {
		fmt.Println("Downloading Google Chrome for MacOS...")
		chromeURL = chromeURLMacOS
		chromeInstaller = chromeInstallerMacOS
	} else {
		logAndExit("Unsupported operating system.")
	}

	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		resp, err = client.Get(chromeURL)
		if err == nil || i == 2 {
			break
		}
		fmt.Printf("Failed to download Google Chrome: %s. Retrying...\n", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to download Google Chrome: %s", err))
	}
	defer resp.Body.Close()

	chromeInstallerPath := filepath.Join(tempDir, chromeInstaller)
	out, err := os.Create(chromeInstallerPath)
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to create file: %s", err))
	}
	defer out.Close()

	fmt.Printf("Saving Google Chrome installer to %s...\n", chromeInstallerPath)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			_, err := out.Write(buf[:n])
			if err != nil {
				logAndExit(fmt.Sprintf("Failed to save file: %s", err))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to save file: %s", err))
		}
	}

	out.Close()

	if chromeInstaller == chromeInstallerWindows {
		cmd := exec.Command(chromeInstallerPath)
		err = cmd.Run()
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to install Google Chrome: %s", err))
		}
	} else if chromeInstaller == chromeInstallerDebian {
		cmd := exec.Command("sudo", "dpkg", "-i", chromeInstallerPath)
		err = cmd.Run()
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to install Google Chrome: %s", err))
		}
		cmd = exec.Command("sudo", "apt-get", "install", "-f", "-y")
		err = cmd.Run()
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to install Google Chrome: %s", err))
		}
	} else if chromeInstaller == chromeInstallerRedhat {
		cmd := exec.Command("sudo", "yum", "install", "-y", chromeInstallerPath)
		err = cmd.Run()
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to install Google Chrome: %s", err))
		}
	} else if chromeInstaller == chromeInstallerMacOS {
		err := exec.Command("hdiutil", "attach", chromeInstallerPath).Run()
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to install Google Chrome: %s", err))
		}

		chromeInstalled := make(chan bool)

		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			timeout := time.After(120 * time.Second)

			for {
				select {
				case <-ticker.C:
					if _, err := os.Stat(chromeExeMacOS); err == nil {
						chromeInstalled <- true
						return
					}
				case <-timeout:
					chromeInstalled <- false
					return
				}
			}
		}()

		installed := <-chromeInstalled
		if installed {
			time.Sleep(2 * time.Second)
		} else {
			logAndExit(fmt.Sprintln("Installation timed out. Please install Google Chrome manually."))
		}

		err = exec.Command("hdiutil", "detach", "/Volumes/Google Chrome").Run()
		if err != nil {
			fmt.Printf("Failed to unmount Google Chrome's .dmg file: %s\n", err)
		}
	}

	fmt.Println("Google Chrome installed successfully.")

	if runtime.GOOS == "windows" {
		fmt.Println("Waiting for default Chrome to be launched...")
		chromeKilled := make(chan bool)

		go func() {
			ticker := time.NewTicker(2 * time.Second) // Check every 2 seconds
			defer ticker.Stop()

			timeout := time.After(15 * time.Second) // Timeout after 15 seconds

			for {
				select {
				case <-ticker.C:
					found, err := checkAndKillChrome()
					if err != nil {
						fmt.Println("Error checking for Chrome:", err)
						continue
					}
					if found {
						fmt.Println("Default Chrome has been stopped.")
						chromeKilled <- true
						return
					}
				case <-timeout:
					fmt.Println("Timeout reached.")
					chromeKilled <- false
					return
				}
			}
		}()

		<-chromeKilled
	}

	os.Remove(chromeInstallerPath)
}

func checkAndKillChrome() (bool, error) {
	procs, err := process.Processes()
	if err != nil {
		fmt.Println("Could not obtain processes list:", err)
		return false, err
	}

	var killedAny bool = false

	for _, p := range procs {
		pName, err := p.Name()
		if err != nil {
			continue
		}

		if pName == "chrome.exe" || pName == "chrome" || pName == "Google Chrome" {
			fmt.Println("Killing process:", pName)
			err := p.Kill()
			if err != nil {
				continue
			}
			killedAny = true
		}
	}

	return killedAny, nil
}

func logAndExit(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func importCertificateWindows(certFile string) {
	powershellScript := fmt.Sprintf(`
$certFilePath = "%s"
# Read the PEM certificate file
$certContent = Get-Content -Path $certFilePath | Out-String
# Import the PEM certificate to the Windows Certificate Store
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import([System.Text.Encoding]::ASCII.GetBytes($certContent))
# Store the certificate in the appropriate certificate store (e.g., "Trusted Root Certification Authorities")
$certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "Root", "LocalMachine"
$certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$certStore.Add($cert)
$certStore.Close()
`, certFile)

	cmd := exec.Command("powershell", "-Command", powershellScript)
	err := cmd.Run()
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to import certificate: %s", err))
	}
}

func setupChrome() {
	var prefFile string
	if runtime.GOOS == "linux" {
		prefDir = filepath.Join(os.Getenv("HOME"), prefDirBaseLinux)
		prefFile = filepath.Join(prefDir, prefFileBase)
	} else if runtime.GOOS == "windows" {
		prefDir = filepath.Join(os.Getenv("LOCALAPPDATA"), prefDirBaseWindows)
		prefFile = filepath.Join(prefDir, prefFileBase)
	} else if runtime.GOOS == "darwin" {
		prefDir = filepath.Join(os.Getenv("HOME"), prefDirBaseMacOS)
		prefFile = filepath.Join(prefDir, prefFileBase)
	} else {
		logAndExit("Unsupported operating system.")
	}
	if exists, _ := pathExists(prefFile); !exists {
		err := os.MkdirAll(filepath.Dir(prefFile), 0755)
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to create preference directory: %s", err))
		}

		prefs := Preferences{}
		prefs.Session.RestoreOnStartup = 4
		prefs.Session.StartupUrls = []string{config.HomepageURL}

		data, err := json.Marshal(prefs)
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to create preference JSON: %s", err))
		}

		err = os.WriteFile(prefFile, data, 0644)
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to write preference file: %s", err))
		}
	} else {
		fmt.Println("Preferences file already exists, skipping creation.")
	}
}

func launchChrome() {
	chromeExePath := getChromeExePath()
	if chromeExePath == "" {
		logAndExit("Google Chrome is not found.")
	}

	var cmd *exec.Cmd

	var cpuBrand string = ""

	if runtime.GOOS == "darwin" {
		sysctlCmd := exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
		var sysctlOut bytes.Buffer
		sysctlCmd.Stdout = &sysctlOut
		err := sysctlCmd.Run()
		if err != nil {
			fmt.Printf("Error executing sysctl: %v", err)
		} else {
			cpuBrand = strings.TrimSpace(sysctlOut.String())
		}
	}

	if strings.Contains(cpuBrand, "Apple") {
		cmd = exec.Command("arch", "-arm64", chromeExePath,
			"--proxy-server="+proxyURL,
			"--no-first-run",
			"--no-default-browser-check",
			"--homepage="+config.HomepageURL,
			"--user-data-dir="+prefDir,
			"--profile-directory=Default",
			config.HomepageURL)
	} else {
		cmd = exec.Command(chromeExePath,
			"--proxy-server="+proxyURL,
			"--no-first-run",
			"--no-default-browser-check",
			"--homepage="+config.HomepageURL,
			"--user-data-dir="+prefDir,
			"--profile-directory=Default",
			config.HomepageURL)
	}

	err := cmd.Start()
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to start Google Chrome: %s", err))
	}

	if runtime.GOOS == "darwin" {
		go func() {
			time.Sleep(5 * time.Second)
			for {
				time.Sleep(3 * time.Second)
				scriptCmd := exec.Command("osascript", "-e", `tell application "Google Chrome" to count every window`)
				out, err := scriptCmd.Output()
				if err != nil {
					continue
				} else {
					count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
					if count == 0 {
						err := cmd.Process.Kill()
						if err != nil {
							continue
						}
						break
					}
				}
			}
		}()
	}

	err = cmd.Wait()
	if err != nil {
	}
}

func killChildProcesses() {
	currentProcess := os.Getpid()

	procs, err := process.Processes()
	if err != nil {
		fmt.Println("Could not obtain processes list:", err)
		return
	}

	for _, p := range procs {
		ppid, err := p.Ppid()
		if err != nil {
			continue
		}

		if int(ppid) == currentProcess {
			err := p.Kill()
			if err != nil {
				fmt.Println("Could not stop child process:", err)
			}
		}
	}

	time.Sleep(2 * time.Second)
}

func getChromeExePath() string {
	var chromeExePath string

	if runtime.GOOS == "windows" {
		if exists, _ := pathExists(chromeExePathWindowsx64); exists {
			chromeExePath = chromeExePathWindowsx64
		} else if exists, _ := pathExists(chromeExePathWindowsx86); exists {
			chromeExePath = chromeExePathWindowsx86
		} else {
			return ""
		}
	} else if runtime.GOOS == "linux" {
		if _, err := exec.LookPath(chromeExeLinux); err != nil {
			return ""
		} else {
			chromeExePath = chromeExeLinux
		}
	} else if runtime.GOOS == "darwin" {
		if exists, _ := pathExists(chromeExeMacOS); exists {
			chromeExePath = chromeExeMacOS
		} else {
			return ""
		}
	} else {
		logAndExit("Unsupported operating system.")
	}
	return chromeExePath
}

func cleanup(tempDir string) {
	fmt.Println("Cleaning up...")
	killChildProcesses()
	err := os.RemoveAll(tempDir)
	if err != nil {
		fmt.Printf("Failed to cleanup: %s\n", err)
	}
}

func main() {
	tempDir := filepath.Join(os.TempDir(), "freebrowser-"+randomString(5))

	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to create temporary directory: %s", err))
	}

	defer cleanup(tempDir)

	archiveBytes, err := EmbeddedFiles.ReadFile("files.zip")
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to read zip file: %s", err))
	}

	zipFilePath := filepath.Join(tempDir, "files.zip")
	err = os.WriteFile(zipFilePath, archiveBytes, 0644)
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to write zip file: %s", err))
	}

	err = archiver.Unarchive(zipFilePath, tempDir)
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to extract zip file: %s", err))
	}

	os.Remove(zipFilePath)

	if runtime.GOOS == "windows" {
		fmt.Println("Importing certificate to the Windows Certificate Store...")
		certFile := filepath.Join(tempDir, "chrome/proxy.pem")
		importCertificateWindows(certFile)
	} else if runtime.GOOS == "linux" {
		fmt.Println("Importing certificate to the Linux NSS database...")
		cmd := exec.Command("cp", "-R", filepath.Join(tempDir, "chrome/.pki/nssdb"),
			filepath.Join(os.Getenv("HOME"), ".pki"))
		err = cmd.Run()
		if err != nil {
			fmt.Printf("Failed to import certificate: %s\n", err)
		}
	} else if runtime.GOOS == "darwin" {
		cmd := exec.Command("security", "find-certificate", "-Z", "-a", "/Library/Keychains/System.keychain")
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Failed to search for certificate: %s, Error: %s\n", out, err)
		} else {
			if strings.Contains(string(out), config.CertSha1) {
				fmt.Println("Certificate already exists in keychain.")
			} else {
				fmt.Println("Importing certificate to MacOS keychain...")
				certFile := filepath.Join(tempDir, "chrome/proxy.pem")
				cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certFile)
				err := cmd.Run()
				if err != nil {
					fmt.Printf("Failed to import certificate: %s\n", err)
				}
			}
		}
	} else {
		logAndExit("Unsupported operating system.")
	}

	if runtime.GOOS == "windows" {
		proxyPath = filepath.Join(tempDir, proxyExeWindows)
	} else if runtime.GOOS == "linux" {
		proxyPath = filepath.Join(tempDir, proxyExeLinux)
	} else if runtime.GOOS == "darwin" {
		proxyPath = filepath.Join(tempDir, proxyExeMacOS)
	} else {
		logAndExit("Unsupported operating system.")
	}
	var cmd *exec.Cmd
	if !config.Production {
		cmd = exec.Command(proxyPath, "--loglevel=debug")

		logFile, err := os.OpenFile("output.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			logAndExit(fmt.Sprintf("Failed to open log file: %s", err))
		}
		defer logFile.Close()
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	} else {
		cmd = exec.Command(proxyPath)
	}
	err = cmd.Start()
	if err != nil {
		logAndExit(fmt.Sprintf("Failed to start proxy: %s", err))
	}

	time.Sleep(time.Second)

	fmt.Println("Checking if Google Chrome is installed...")
	chromeExePath := getChromeExePath()
	if chromeExePath == "" {
		fmt.Println("Google Chrome is not installed. Would you like to install it? (y/n)")
		var input string
		fmt.Scanln(&input)
		if strings.ToLower(input) == "y" {
			if true {
				fmt.Println("Installing Google Chrome...")
				installChrome(tempDir)
			} else {
				fmt.Println("Skipping Google Chrome installation.")
			}
		}
	} else {
		fmt.Println("Google Chrome is already installed.")
	}

	fmt.Println("Setting up Google Chrome...")
	setupChrome()

	fmt.Println("Launching Google Chrome...")
	launchChrome()
}
