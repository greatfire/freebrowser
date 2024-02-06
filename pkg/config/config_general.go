package config

import (
	"embed"
	"sync"
	"time"
)

const AppVersion = "0.0.1"

const ProxyPort = "8888"

const FbConfigFile string = "fb.config"

//go:embed fb.config proxy.pem proxy.key
var EmbeddedFiles embed.FS

var MethodDataFilePathAndroid string = "/data/data/com.example.gfapp/files/method_data.json"

var FbConfigFilePathAndroid string = "/data/data/com.example.gfapp/files/fb.config"

const UnreachableDOHServerChance float64 = 0.05

const MaxNodeTimeRecords = 100

const UntestedNodeChance float64 = 0.25

const SwitchNodeChance float64 = 0.05

const NodePowerCoeff float64 = 4.0

const UseExistingMethodDataChance = 0.9

const MethodDelay = 3 * time.Second

const TimeoutHTTPClient time.Duration = 30 * time.Second
const TimeoutNetDialer time.Duration = 10 * time.Second
const TimeoutTLSHandshake time.Duration = 10 * time.Second
const TimeoutResponseHeader time.Duration = 10 * time.Second
const TimeoutIdleConn time.Duration = 60 * time.Second

const ConcurrentProcessRequests = 30

const ConcurrentDOHRequests = 5

var BlockedDomains = []string{}

var DomainFrontingOnlyDomains = []string{}

var domainMutex sync.Mutex

func UpdateDomainFrontingOnlyDomains(dohDomain string) {
	domainMutex.Lock()
	defer domainMutex.Unlock()

	for _, domain := range DomainFrontingOnlyDomains {
		if domain == dohDomain {
			return
		}
	}

	DomainFrontingOnlyDomains = append(DomainFrontingOnlyDomains, dohDomain)
}

var ValidSNIs = map[string]bool{
	"www.example.com": true,
}

var DohURLlist = []string{
	"doh://1.1.1.1",                     // DNS over HTTPS
	"https://1.1.1.1/dns-query?name=%s", // DNS over HTTPS API
	"dohocdn://one.one.one.one",         // DNS over HTTPS over CDN
}

var CA_CERT, _ = EmbeddedFiles.ReadFile("proxy.pem")
var CA_KEY, _ = EmbeddedFiles.ReadFile("proxy.key")

var DomainFrontingPathPrefix = "/df/"
var DomainFrontingHashSuffix = "md5suffix"

var DomainFrontingOriginalURLHeader = "X-Original-URL"

var LimitNodeErrors = 50

var SystemUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
