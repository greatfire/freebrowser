package fbproxy

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"strconv"
	"strings"
	"sync"
	"time"

	config "fb-proxy/pkg/config"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	utls "github.com/refraction-networking/utls"
	publicsuffix "golang.org/x/net/publicsuffix"
)

const (
	ErrUnknownError                    = "UNKNOWN_ERROR"
	ErrContextCanceled                 = "CONTEXT_CANCELED"
	ErrEof                             = "EOF_ERROR"
	ErrResolveIP                       = "RESOLVE_IP_ERROR"
	ErrRetrieveNode                    = "RETRIEVE_NODE_ERROR"
	ErrTcpConnectionReset              = "TCP_CONNECTION_RESET_BY_PEER"
	ErrTcpConnectionRefused            = "TCP_CONNECTION_REFUSED"
	ErrTcpNoRouteToHost                = "TCP_NO_ROUTE_TO_HOST"
	ErrTcpIoTimeout                    = "TCP_IO_TIMEOUT"
	ErrTcpNoConnTargetRegused          = "TCP_NO_CONNECTION_TARGET_REFUSED"
	ErrTcpEstablishedConnectionAborted = "TCP_ESTABLISHED_CONNECTION_ABORTED"
	ErrTcpSocketAccessForbidden        = "TCP_SOCKET_ACCESS_FORBIDDEN"
	ErrTcpSocketUnreachableHost        = "TCP_SOCKET_UNREACHABLE_HOST"
	ErrTlsCertMismatch                 = "TLS_CERTIFICATE_MISMATCH"
	ErrTlsInternal                     = "TLS_INTERNAL_ERROR"
	ErrTlsCertVerify                   = "TLS_VERIFY_CERTIFICATE_ERROR"
	ErrTlsDoesNotLookLikeHandshake     = "TLS_DOES_NOT_LOOK_LIKE_HANDSHAKE"
	ErrTlsHandshakeFailure             = "TLS_HANDSHAKE_FAILURE"
	ErrHttpTimeoutResponseHeaders      = "HTTP_TIMEOUT_RESPONSE_HEADERS"
)

var trustedCertDomains = make(map[string]string)

func ShortenDomain(domain string) string {
	parts := strings.Split(domain, ".")
	short := ""
	for _, part := range parts {
		short += string(part[0])
	}
	short += strconv.Itoa(len(domain))
	return short
}

type DOHServer struct {
	ID           string
	URL          string
	Reachability int
	Attempts     int
	Successes    int
}

type DOHServers struct {
	dohMap map[string]DOHServer
	mutex  sync.RWMutex
}

type requestIDKeyType struct{}

var requestIDKey requestIDKeyType

type contextServerNameKeyType struct{}

var contextServerNameKey contextServerNameKeyType

type contextHostKeyType struct{}

var contextHostKey contextHostKeyType

type dnsResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type methodResult struct {
	methodIndex int
	orderIndex  int
	response    *partialResponse
	url         string
}

type partialResponse struct {
	data     []byte
	body     io.ReadCloser
	response *http.Response
}

type ReadCloserWrapper struct {
	io.Reader
	io.Closer
}

type dnsCacheEntry struct {
	ip     string
	expiry time.Time
}

type Node struct {
	ID        string
	Host      string
	IP        string
	Times     []time.Duration
	TotalTime time.Duration
	AvgTime   time.Duration
	Errors    []string

}

type Nodes struct {
	NodesMap map[string]Node
	mutex    sync.RWMutex
}

var loadOnce sync.Once

var methodData = make(map[string]int)
var methodDataMutex sync.RWMutex

var nodeData = make(map[string]string)
var nodeDataMutex sync.RWMutex

var methodDataFilePath string
var snisLock = &sync.RWMutex{}
var nodes = &Nodes{
	NodesMap: make(map[string]Node),
}
var dohServers *DOHServers

var exeDir string

func init() {
	exePath, err := os.Executable()
	if err != nil {
		zap.S().Fatal(err)
	}
	exeDir = filepath.Dir(exePath)
}

func initProxy() {
	zap.S().Debugln("Running initProxy()...")

	methodData = readMethodData()

	dohServers = initializeDOHServers(config.DohURLlist)
	zap.S().Debugf("dohServers initialized: %v", dohServers)

	loadFbConfig(config.FbConfigFile)

}

func (n *Nodes) AddNode(host, ip string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	nodeID := fmt.Sprintf("%s-%s", ShortenDomain(host), ip)
	newNode := Node{
		ID:     nodeID,
		Host:   host,
		IP:     ip,
		Times:  []time.Duration{},
		Errors: []string{},

	}
	n.NodesMap[nodeID] = newNode
}

func (n *DOHServers) AddDOHServer(dohURL string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	var ID string

	if strings.HasPrefix(dohURL, "https://") {
		ID = "https://" + strings.Split(dohURL, "/")[2]
	} else {
		ID = dohURL
	}

	newDOHServer := DOHServer{
		ID:           ID,
		URL:          dohURL,
		Reachability: 1,
		Attempts:     0,
		Successes:    0,
	}
	n.dohMap[ID] = newDOHServer
	zap.S().Debugf("Added DOH server: %s to dohMap", ID)
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func loadFbConfig(FbConfigFile string) {

	defer func() {
		if r := recover(); r != nil {
			zap.S().Errorf("Panic recovered in loadFbConfig. Error: %v", r)
		}
	}()

	var fbConfigFilePath string

	if runtime.GOOS == "android" {
		fbConfigFilePath = config.FbConfigFilePathAndroid
	} else {
		fbConfigFilePath = filepath.Join(exeDir, config.FbConfigFile)
	}

	fbConfigBytes, err := os.ReadFile(fbConfigFilePath)

	if err != nil {
		zap.S().Errorf("Error reading config data from external file: %v", err)
		fbConfigBytes, err = config.EmbeddedFiles.ReadFile(FbConfigFile)
		if err != nil {
			zap.S().Errorf("Error reading config data from embedded file: %v", err)
			return
		} else {
			zap.S().Infoln("Config data loaded from embedded file")
		}
	} else {
		zap.S().Infoln("Config data loaded from external file")
	}

	fbConfigStr := string(fbConfigBytes)

	fbConfigLines := strings.Split(fbConfigStr, "\n")

	for _, line := range fbConfigLines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")

		switch parts[0] {

		case "CDN-CIDRS":
			zap.S().Debugf("fb.config CDN-CIDRS %s: %d IPs", parts[3], len(strings.Split(parts[4], ",")))
			for _, cidr := range strings.Split(parts[4], ",") {
				if strings.Contains(cidr, "/") {
					_, ipnet, err := net.ParseCIDR(cidr)
					if err != nil {
						zap.S().Errorf("Error parsing CIDR %s: %v", cidr, err)
						continue
					}
					for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
						nodes.AddNode(parts[3], ip.String())
					}
				} else {
					nodes.AddNode(parts[3], cidr)
				}
			}

		case "CDN-CERTS":
			zap.S().Debugf("fb.config CDN-CERTS %s: %d domains", parts[1], len(strings.Split(parts[2], ",")))
			for _, cdnHostname := range strings.Split(parts[1], ",") {
				trustedCertDomains[cdnHostname] = parts[2]
			}

		}
	}

}

func initializeDOHServers(dohURLlist []string) *DOHServers {
	dohServers = &DOHServers{
		dohMap: make(map[string]DOHServer),
	}

	for _, dohURL := range dohURLlist {
		dohServers.AddDOHServer(dohURL)
	}

	return dohServers
}

func (n *Nodes) RetrieveNode(eTldPlusOne string, orderIndex int, requestID string) Node {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if len(n.NodesMap) == 0 {
		return Node{}
	}

	if orderIndex == 0 {
		nodeDataMutex.Lock()
		nodeID, nodeDataExists := nodeData[eTldPlusOne]
		nodeDataMutex.Unlock()
		if nodeDataExists && rand.Float64() > config.SwitchNodeChance {
			zap.S().With("requestID", requestID).Debugf("Using node %s for %s from nodeData", nodeID, eTldPlusOne)
			return n.NodesMap[nodeID]
		}
	}

	testedNodes := make([]Node, 0)
	untestedNodes := make([]Node, 0)

	for _, node := range n.NodesMap {
		if node.AvgTime == 0 {
			untestedNodes = append(untestedNodes, node)
		} else {
			testedNodes = append(testedNodes, node)
		}
	}
	zap.S().With("requestID", requestID).Debugf("Number of tested Nodes: %d", len(testedNodes))
	zap.S().With("requestID", requestID).Debugf("Number of untested Nodes: %d", len(untestedNodes))

	if len(testedNodes) == 0 {
		zap.S().With("requestID", requestID).Debug("Using untested node because all nodes are untested")
		return untestedNodes[rand.Intn(len(untestedNodes))]
	}

	if len(untestedNodes) > 0 && rand.Float64() < config.UntestedNodeChance {
		zap.S().With("requestID", requestID).Debug("Using untested node by chance")
		return untestedNodes[rand.Intn(len(untestedNodes))]
	}

	sort.Slice(testedNodes, func(i, j int) bool {
		return testedNodes[i].AvgTime > testedNodes[j].AvgTime
	})

	totalInverse := 0.0
	for _, node := range testedNodes {
		inverseTime := 1.0 / float64(node.AvgTime)
		totalInverse += math.Pow(inverseTime, config.NodePowerCoeff)
	}
	randomInverse := rand.Float64() * totalInverse
	zap.S().With("requestID", requestID).Debugf("Calculated totalInverse: %v, randomInverse: %v", totalInverse, randomInverse)

	cumulativeInverse := 0.0
	for _, node := range testedNodes {
		inverseTime := 1.0 / float64(node.AvgTime)
		cumulativeInverse += math.Pow(inverseTime, config.NodePowerCoeff)
		zap.S().With("requestID", requestID).Debugf("Checking node: %v, node.AvgTime: %v, inverseTime: %v, cumulativeInverse: %v, count of node.Errors: %d",
			node, node.AvgTime, inverseTime, cumulativeInverse, len(node.Errors))
		if cumulativeInverse > randomInverse && len(node.Errors) <= config.LimitNodeErrors {
			return node
		}
	}

	return Node{}
}

func (d *DOHServers) RetrieveDOHServer() DOHServer {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if len(d.dohMap) == 0 {
		return DOHServer{}
	}

	reachableDOHServers := make([]DOHServer, 0)
	unreachableDOHServers := make([]DOHServer, 0)

	for _, dohServer := range d.dohMap {
		if dohServer.Reachability == 0 {
			unreachableDOHServers = append(unreachableDOHServers, dohServer)
		} else {
			reachableDOHServers = append(reachableDOHServers, dohServer)
		}
	}

	if len(reachableDOHServers) == 0 {
		zap.S().Debug("All DOH servers are unreachable")
		if rand.Float64() < config.UnreachableDOHServerChance {
			zap.S().Debug("Attempting unreachable DOH server by chance")
			return unreachableDOHServers[rand.Intn(len(unreachableDOHServers))]
		} else {
			zap.S().Debug("Not attempting any DOH server")
			return DOHServer{}
		}
	}
	if len(unreachableDOHServers) > 0 && rand.Float64() < config.UnreachableDOHServerChance {
		zap.S().Debug("Attempting unreachable DOH server by chance")
		return unreachableDOHServers[rand.Intn(len(unreachableDOHServers))]
	}
	zap.S().Debug("Using reachable DOH server")
	return reachableDOHServers[rand.Intn(len(reachableDOHServers))]
}

func (n *Nodes) RecordNodeTime(node Node, elapsedTime time.Duration, debug bool) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	nodeMap, ok := n.NodesMap[node.ID]
	if !ok {
		zap.S().Infoln("Node with ID %s not found", node.ID)
		return
	}

	if len(nodeMap.Times) >= config.MaxNodeTimeRecords {
		nodeMap.TotalTime -= nodeMap.Times[0]
		nodeMap.Times = nodeMap.Times[1:]
	}

	nodeMap.Times = append(nodeMap.Times, elapsedTime)
	nodeMap.TotalTime += elapsedTime
	nodeMap.AvgTime = nodeMap.TotalTime / time.Duration(len(nodeMap.Times))

	n.NodesMap[node.ID] = nodeMap

	if debug {
		jsonBytes, err := json.MarshalIndent(n.NodesMap, "", "  ")
		if err != nil {
			zap.S().Infof("Error marshalling nodeMap to JSON: %v", err)
			return
		}
		err = os.WriteFile("nodeMap.json", jsonBytes, 0644)
		if err != nil {
			zap.S().Infof("Error writing nodeMap to file: %v", err)
		}
	}
}

func getErrorCode(err error) string {
	if err == nil {
		return ErrUnknownError
	}

	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "does not match expected domains"):
		return ErrTlsCertMismatch
	case strings.Contains(errStr, "connection reset by peer"):
		return ErrTcpConnectionReset
	case strings.Contains(errStr, "connection refused"):
		return ErrTcpConnectionRefused
	case strings.Contains(errStr, "no route to host"):
		return ErrTcpNoRouteToHost
	case strings.Contains(errStr, "i/o timeout"):
		return ErrTcpIoTimeout
	case strings.Contains(errStr, "No connection could be made because the target machine actively refused it"):
		return ErrTcpNoConnTargetRegused
	case strings.Contains(errStr, "tls: internal error"):
		return ErrTlsInternal
	case strings.Contains(errStr, "tls: failed to verify certificate"):
		return ErrTlsCertVerify
	case strings.Contains(errStr, "tls: first record does not look like a TLS handshake"):
		return ErrTlsDoesNotLookLikeHandshake
	case strings.Contains(errStr, "tls: handshake failure"):
		return ErrTlsHandshakeFailure
	case strings.Contains(errStr, "context canceled"):
		return ErrContextCanceled
	case strings.Contains(errStr, "EOF"):
		return ErrEof
	case strings.Contains(errStr, "Error resolving IP"):
		return ErrResolveIP
	case strings.Contains(errStr, "Error retrieving node"):
		return ErrRetrieveNode
	case strings.Contains(errStr, "wsarecv: An established connection was aborted by the software in your host machine"):
		return ErrTcpEstablishedConnectionAborted
	case strings.Contains(errStr, "connectex: An attempt was made to access a socket in a way forbidden by its access permissions"):
		return ErrTcpSocketAccessForbidden
	case strings.Contains(errStr, "connectex: A socket operation was attempted to an unreachable host"):
		return ErrTcpSocketUnreachableHost
	case strings.Contains(errStr, "timeout awaiting response headers"):
		return ErrHttpTimeoutResponseHeaders
	case strings.Contains(errStr, "Node returned HTTP status code"):
		return "HTTP_CODE_" + strings.Split(errStr, ":")[1]
	default:
		return ErrUnknownError
	}
}

func (n *Nodes) RecordError(node Node, err error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	nodeMap, ok := n.NodesMap[node.ID]
	if !ok {
		zap.S().Infof("Node with ID %s not found", node.ID)
		return
	}

	errorCode := getErrorCode(err)

	if errorCode != ErrContextCanceled {
		nodeMap.Errors = append(nodeMap.Errors, errorCode)
		n.NodesMap[node.ID] = nodeMap
	}
}

func (d *DOHServers) UpdateDOHServers(dohServer DOHServer, reachability int, debug bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	dohMap, ok := d.dohMap[dohServer.ID]
	if !ok {
		zap.S().Debugf("DOH server with ID %s not found", dohServer.ID)
		return
	}

	dohMap.Reachability = reachability

	dohMap.Attempts++

	if reachability == 1 {
		dohMap.Successes++
	}

	d.dohMap[dohServer.ID] = dohMap

	if debug {
		jsonBytes, err := json.MarshalIndent(d.dohMap, "", "  ")
		if err != nil {
			zap.S().Infof("Error marshalling dohMap to JSON: %v", err)
			return
		}
		err = os.WriteFile("dohMap.json", jsonBytes, 0644)
		if err != nil {
			zap.S().Infof("Error writing dohMap to file: %v", err)
		}
	}
}

var dnsCache = map[string]dnsCacheEntry{}
var dnsCacheLock = &sync.RWMutex{}

func resolveIPFromCache(host string) (string, error) {
	dnsCacheLock.RLock()
	if val, ok := dnsCache[host]; ok {
		if time.Now().Before(val.expiry) {
			dnsCacheLock.RUnlock()
			return val.ip, nil
		}
	}
	dnsCacheLock.RUnlock()

	return "", fmt.Errorf("No entry in cache")
}

var resolveIPsem = make(chan struct{}, config.ConcurrentDOHRequests)

var httpClientDNS = http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		Dial: (&net.Dialer{
			Timeout: config.TimeoutNetDialer / 2,
		}).Dial,
		TLSHandshakeTimeout:   config.TimeoutTLSHandshake / 2,
		ResponseHeaderTimeout: config.TimeoutResponseHeader / 2,
	},
	Timeout: config.TimeoutHTTPClient / 2,
}

func resolveIPWithAPI(httpClientDNS http.Client, dohServer DOHServer, host string, debug bool, requestID string) (string, error) {

	if dohServer.URL == "" {
		return "", fmt.Errorf("No DOH server is available")
	}

	resolveIPsem <- struct{}{}
	defer func() { <-resolveIPsem }()

	zap.S().With("requestID", requestID).Infof("Resolve IP for host %s using DOH server %s", host, dohServer.ID)

	url := fmt.Sprintf(dohServer.URL, host)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("accept", "application/dns-json")

	resp, err := httpClientDNS.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error reaching DOH server: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	dnsResp := dnsResponse{}
	err = json.Unmarshal(body, &dnsResp)
	if err != nil {
		return "", err
	}

	if debug {
		dnsRespJSON, err := json.MarshalIndent(dnsResp, "", "  ")
		if err != nil {
			zap.S().With("requestID", requestID).Debugln("Error marshalling DNS response for saving:", err)
		} else {
			err = os.WriteFile("dns_response.json", dnsRespJSON, 0644)
			if err != nil {
				zap.S().With("requestID", requestID).Debugln("Error writing DNS response to file:", err)
			} else {
				zap.S().With("requestID", requestID).Debugln("DNS response saved to dns_response.json")
			}
		}
	}

	if dnsResp.Status != 0 {
		return "", fmt.Errorf("DNS response status is not 0: %d", dnsResp.Status)
	}

	for _, answer := range dnsResp.Answer {
		if answer.Type == 1 {
			ttl := answer.TTL
			dnsCacheLock.Lock()
			dnsCache[host] = dnsCacheEntry{
				ip:     answer.Data,
				expiry: time.Now().Add(time.Duration(ttl) * time.Second),
			}
			dnsCacheLock.Unlock()
			return answer.Data, nil
		}
	}

	return "", fmt.Errorf("no A record found for %s", host)
}

func resolveIPWithCDN(httpClientDNS http.Client, dohServer DOHServer, host string, debug bool, requestID string) (string, error) {

	proxyURL, _ := url.Parse(fmt.Sprintf("http://localhost:%s", config.ProxyPort))

	var httpClientDNSWithProxy = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(proxyURL),
			Dial: (&net.Dialer{
				Timeout: config.TimeoutNetDialer,
			}).Dial,
			TLSHandshakeTimeout:   config.TimeoutTLSHandshake,
			ResponseHeaderTimeout: config.TimeoutResponseHeader,
		},
		Timeout: config.TimeoutHTTPClient,
	}

	return resolveIPWithDOH(httpClientDNSWithProxy, dohServer, host, debug, requestID)
}

func resolveIPWithDOH(httpClientDNS http.Client, dohServer DOHServer, host string, debug bool, requestID string) (string, error) {
	if dohServer.URL == "" {
		return "", fmt.Errorf("No DOH server URL provided")
	}

	resolveIPsem <- struct{}{}
	defer func() { <-resolveIPsem }()

	zap.S().With("requestID", requestID).Infof("Resolve IP for host %s using DOH server %s", host, dohServer.ID)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	wireMsg, err := m.Pack()
	if err != nil {
		return "", err
	}

	encodedMsg := base64.RawURLEncoding.EncodeToString(wireMsg)

	var dohDomain string
	if strings.HasPrefix(dohServer.URL, "doh://") {
		dohDomain = strings.TrimPrefix(dohServer.URL, "doh://")
	} else if strings.HasPrefix(dohServer.URL, "dohocdn://") {
		dohDomain = strings.TrimPrefix(dohServer.URL, "dohocdn://")
		config.UpdateDomainFrontingOnlyDomains(dohDomain)
		zap.S().Debugf("Updated config.DomainFrontingOnlyDomains: %v", config.DomainFrontingOnlyDomains)
	}

	url := "https://" + dohDomain + "/dns-query?dns=" + encodedMsg

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("User-Agent", config.SystemUserAgent)

	resp, err := httpClientDNS.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error reaching DOH server: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	in := new(dns.Msg)
	if err := in.Unpack(body); err != nil {
		return "", err
	}

	if debug {
		debugOutput, _ := json.MarshalIndent(in, "", "  ")
		_ = os.WriteFile("dns_response.json", debugOutput, 0644)
		zap.S().With("requestID", requestID).Debugln("DNS response saved to dns_response.json")
	}

	if in.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS response status is not successful: %d", in.Rcode)
	}

	for _, ans := range in.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			ttl := ans.Header().Ttl
			dnsCacheLock.Lock()
			dnsCache[host] = dnsCacheEntry{
				ip:     aRecord.A.String(),
				expiry: time.Now().Add(time.Duration(ttl) * time.Second),
			}
			dnsCacheLock.Unlock()
			return aRecord.A.String(), nil
		}
	}

	return "", fmt.Errorf("no A record found for %s", host)
}

func readPartialResponse(resp *http.Response) (*partialResponse, error) {
	p := make([]byte, 512)
	n, err := resp.Body.Read(p)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &partialResponse{
		data:     p[:n],
		body:     resp.Body,
		response: resp,
	}, nil
}

func getMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func addSNI(sni string) {
	snisLock.Lock()
	defer snisLock.Unlock()

	if !config.ValidSNIs[sni] {
		config.ValidSNIs[sni] = true
	}
}

func getSNI() string {

	snisLock.RLock()
	defer snisLock.RUnlock()

	keys := make([]string, 0, len(config.ValidSNIs))
	for k := range config.ValidSNIs {
		keys = append(keys, k)
	}

	return keys[rand.Intn(len(keys))]
}

func sliceContains[T comparable](slice []T, element T) bool {
	for _, v := range slice {
		if v == element {
			return true
		}
	}
	return false
}

func copyHeader(h http.Header) http.Header {
	copy := make(http.Header, len(h))
	for k, vv := range h {
		copy[k] = copyStringSlice(vv)
	}
	return copy
}

func copyStringSlice(slice []string) []string {
	newSlice := make([]string, len(slice))
	copy(newSlice, slice)
	return newSlice
}

var ProcessRequestsem = make(chan struct{}, config.ConcurrentProcessRequests)

func ProcessRequest(req *http.Request, debug bool) (processRequestResp *http.Response, processRequestErr error) {
	ProcessRequestsem <- struct{}{}
	defer func() { <-ProcessRequestsem }()

	startProcessRequest := time.Now()

	requestID := fmt.Sprintf("%p", req)

	defer func() {
		if r := recover(); r != nil {
			zap.S().With("requestID", requestID).Errorf("Panic recovered in ProcessRequest. Error: %v", r)
			processRequestResp = nil
			processRequestErr = fmt.Errorf("Panic recovered in ProcessRequest: %v", r)
		}
	}()

	url_ := req.URL
	method := req.Method
	header := req.Header
	body := req.Body

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	methodResults := make(chan methodResult)
	errors := make(chan error)

	methods := []func(context.Context, *url.URL, string, string, string, http.Header, io.ReadCloser, bool) (*partialResponse, error){
		func(ctx context.Context, parsedURL *url.URL, host string, ip string, httpMethod string, header http.Header, body io.ReadCloser, debug bool) (*partialResponse, error) {
			zap.S().With("requestID", requestID).Infoln("Attempt with SNI")
			if ip == "" {
				return nil, fmt.Errorf("Error resolving IP")
			}
			sni := host
			resp, err := makeRequest(ctx, parsedURL, httpMethod, header, body, host, ip, sni, debug)
			if err != nil {
				return nil, err
			}
			pr, err := readPartialResponse(resp)
			addSNI(sni)
			return pr, err
		},
		func(ctx context.Context, parsedURL *url.URL, host string, ip string, httpMethod string, header http.Header, body io.ReadCloser, debug bool) (*partialResponse, error) {
			zap.S().With("requestID", requestID).Infoln("Attempt without SNI")
			if ip == "" {
				return nil, fmt.Errorf("Error resolving IP")
			}
			resp, err := makeRequest(ctx, parsedURL, httpMethod, header, body, host, ip, "", debug)
			if err != nil {
				return nil, err
			}
			return readPartialResponse(resp)
		},
		func(ctx context.Context, parsedURL *url.URL, host string, ip string, httpMethod string, header http.Header, body io.ReadCloser, debug bool) (*partialResponse, error) {
			zap.S().With("requestID", requestID).Infoln("Attempt with fake SNI")
			if ip == "" {
				return nil, fmt.Errorf("Error resolving IP")
			}
			sni := getSNI()
			resp, err := makeRequest(ctx, parsedURL, httpMethod, header, body, host, ip, sni, debug)
			if err != nil {
				return nil, err
			}
			return readPartialResponse(resp)
		},
		func(ctx context.Context, parsedURL *url.URL, host string, ip string, httpMethod string, header http.Header, body io.ReadCloser, debug bool) (*partialResponse, error) {
			zap.S().With("requestID", requestID).Infoln("Attempt with CDN account:", host)
			if ip == "" || host == "" {
				return nil, fmt.Errorf("Error retrieving node")
			}

			originalURL := parsedURL.Scheme + "://" + parsedURL.Hostname() + parsedURL.RequestURI()
			zap.S().With("requestID", requestID).Debugf("[method3] originalURL: %s", originalURL)

			md5Hash := getMD5Hash(originalURL + config.DomainFrontingHashSuffix)
			dfURL := &url.URL{
				Scheme: "",
				Host:   "",
				Path:   config.DomainFrontingPathPrefix + md5Hash,
			}

			headerCopy := copyHeader(header)

			headerCopy.Add(config.DomainFrontingOriginalURLHeader, originalURL)

			sni := getSNI()

			zap.S().With("requestID", requestID).Debugf("[method3] updated header: %v", headerCopy)

			resp, err := makeRequest(ctx, dfURL, httpMethod, headerCopy, body, host, ip, sni, debug)

			if err != nil {
				return nil, err
			}
			return readPartialResponse(resp)
		},
	}

	methodOrder := []int{0, 1, 2, 3, 3, 3, 3, 3}

	zap.S().With("requestID", requestID).Debugf("url_.Hostname(): %s", url_.Hostname())
	zap.S().With("requestID", requestID).Debugf("url_.Host(): %s", url_.Host)

	host := url_.Hostname()

	zap.S().With("requestID", requestID).Debugf("url_: %s", url_.String())
	zap.S().With("requestID", requestID).Debugf("host: %s", host)

	hostIsIP := net.ParseIP(host) != nil
	zap.S().With("requestID", requestID).Debugf("hostIsIP: %v", hostIsIP)

	eTldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || hostIsIP {
		zap.S().With("requestID", requestID).Errorf("Error getting eTldPlusOne for host %s", host)
		eTldPlusOne = host
	}
	zap.S().With("requestID", requestID).Debugf("eTldPlusOne: %s", eTldPlusOne)

	if sliceContains(config.BlockedDomains, "*."+eTldPlusOne) || sliceContains(config.BlockedDomains, host) {
		zap.S().With("requestID", requestID).Debugln("SNI is in BlockedDomains, so we avoid methods that expose it")
		methodOrder = []int{1, 2, 3, 3, 3, 3, 3}
	}

	if sliceContains(config.DomainFrontingOnlyDomains, "*."+eTldPlusOne) || sliceContains(config.DomainFrontingOnlyDomains, host) {
		zap.S().With("requestID", requestID).Debugln("SNI is in DomainFrontingOnlyDomains, so we only try method 3")
		methodOrder = []int{3, 3, 3, 3, 3}
	}

	methodDataMutex.RLock()
	method_, methodDataExists := methodData[eTldPlusOne]
	methodDataMutex.RUnlock()

	if methodDataExists {
		if rand.Float64() < config.UseExistingMethodDataChance {
			zap.S().With("requestID", requestID).Debugln("methodData exists, moving matching elements to the front of methodOrder")
			methodOrder = moveMatchingElementsToFront(methodOrder, method_)
		} else {
			zap.S().With("requestID", requestID).Debugln("methodData exists, but using default methodOrder by chance")
		}
	}

	zap.S().With("requestID", requestID).Infoln("Method order:", methodOrder)

	errCount := 0

	cancels := make([]context.CancelFunc, len(methodOrder))

	for orderIndex, methodIndex := range methodOrder {
		go func(orderIndex int, methodIndex int) {
			defer func() {
				if r := recover(); r != nil {
					zap.S().With("requestID", requestID).Errorf("Panic recovered in method goroutine. Error: %v", r)
					errCount++
					zap.S().With("requestID", requestID).Debugln("errCount:", errCount)

					if errCount == len(methodOrder) {
						errors <- fmt.Errorf("Panic recovered in method goroutine")
					}
				}
			}()

			ctx, cancel := context.WithCancel(context.Background())
			ctx = context.WithValue(ctx, requestIDKey, requestID)

			cancels[orderIndex] = cancel

			time.Sleep(time.Duration(orderIndex) * config.MethodDelay)
			if ctx.Err() != nil {
				return
			}

			zap.S().With("requestID", requestID).Infof("Attempt (%d) method %d for URL %s", orderIndex, methodIndex, url_.String())

			var host_ string
			var ip_ string
			var node Node

			if methodIndex == 3 {
				start := time.Now()
				node = nodes.RetrieveNode(eTldPlusOne, orderIndex, requestID)
				elapsed := time.Since(start)
				if node.ID == "" {
					host_ = ""
					ip_ = ""
					zap.S().With("requestID", requestID).Errorln("No node retrieved")
				} else {
					host_ = node.Host
					ip_ = node.IP
					zap.S().With("requestID", requestID).Debugf("Node %v retrieved in %v", node.ID, elapsed)
				}
			} else if hostIsIP {
				host_ = host
				ip_ = host
			} else {

				host_ = host

				ip_, err = resolveIPFromCache(host)
				if err != nil {
					dohServer := dohServers.RetrieveDOHServer()
					if strings.HasPrefix(dohServer.URL, "https://") {
						ip_, err = resolveIPWithAPI(httpClientDNS, dohServer, host, debug, requestID)
					} else if strings.HasPrefix(dohServer.URL, "dohocdn://") {
						ip_, err = resolveIPWithCDN(httpClientDNS, dohServer, host, debug, requestID)
					} else {
						ip_, err = resolveIPWithDOH(httpClientDNS, dohServer, host, debug, requestID)
					}
					if err != nil {
						zap.S().With("requestID", requestID).Errorf("Error resolving IP for host %s: %s", host, err)
						if dohServer.ID != "" {
							if strings.Contains(err.Error(), "Error reaching DOH server") {
								dohServers.UpdateDOHServers(dohServer, 0, debug)
							} else {
								dohServers.UpdateDOHServers(dohServer, 1, debug)
							}
						}
					} else {
						zap.S().With("requestID", requestID).Infof("Resolved IP %s for host %s via DOH server %s", ip_, host, dohServer.ID)
						dohServers.UpdateDOHServers(dohServer, 1, debug)

					}
				} else {
					zap.S().With("requestID", requestID).Infoln("Resolved IP from DNS cache:", ip_)

				}
			}

			bodyCopy := io.NopCloser(bytes.NewReader(bodyBytes))

			methodStart := time.Now()
			resp, methodErr := methods[methodIndex](ctx, url_, host_, ip_, method, header, bodyCopy, debug)
			methodElapsed := time.Since(methodStart)

			if resp != nil {
				zap.S().With("requestID", requestID).Infof("Method %d for URL %s succeeded, took %s to run, response HTTP code: %d",
					methodIndex, url_.String(), methodElapsed, resp.response.StatusCode)
			} else {
				zap.S().With("requestID", requestID).Infof("Method %d for URL %s failed, took %s to run, error: %v",
					methodIndex, url_.String(), methodElapsed, methodErr)
			}

			if methodErr == nil {
				if methodIndex == 3 && (resp.response.StatusCode == 502 || resp.response.StatusCode == 421) {
					methodErr = fmt.Errorf("Node returned HTTP status code:%d", resp.response.StatusCode)
				}
			}

			if methodErr != nil {
				zap.S().With("requestID", requestID).Errorln("Error making request: ", methodErr)

				errCount++
				zap.S().With("requestID", requestID).Debugln("errCount:", errCount)

				if methodIndex == 3 && node.ID != "" {
					nodes.RecordError(node, methodErr)
				}

				if errCount == len(methodOrder) {
					errors <- methodErr
				}

				return
			}

			if methodIndex == 3 {
				nodeSuccessCodes := []int{200, 201, 204, 206, 302, 304}
				if sliceContains(nodeSuccessCodes, resp.response.StatusCode) {
					nodes.RecordNodeTime(node, methodElapsed, debug)
					zap.S().With("requestID", requestID).Debugf("Elapsed time of %v recorded for node %s", methodElapsed, node.ID)
					nodeDataMutex.Lock()
					nodeData[eTldPlusOne] = node.ID
					nodeDataMutex.Unlock()
					zap.S().With("requestID", requestID).Debugf("nodeData updated for eTLD+1 %s: %s", eTldPlusOne, node.ID)
				} else {
					nodes.RecordError(node, fmt.Errorf("Node returned HTTP status code:%d", resp.response.StatusCode))
				}
			}

			methodResults <- methodResult{methodIndex, orderIndex, resp, url_.String()}
		}(orderIndex, methodIndex)
	}

	select {
	case res := <-methodResults:
		wrapper := &ReadCloserWrapper{
			Reader: io.MultiReader(bytes.NewReader(res.response.data), res.response.body),
			Closer: res.response.body,
		}

		res.response.response.Body = wrapper

		if true {
			writeMethodData(eTldPlusOne, res.methodIndex, requestID)
		}
		zap.S().With("requestID", requestID).Infof("Success for URL %s using method %d at orderIndex: %d", res.url, res.methodIndex, res.orderIndex)

		for i, cancel := range cancels {
			if i != res.orderIndex && cancel != nil {
				cancel()
			}
		}

		elapsedProcessRequest := time.Since(startProcessRequest)
		zap.S().With("requestID", requestID).Infof("Total elapsed time in ProcessRequest(): %s", elapsedProcessRequest)

		return res.response.response, nil
	case err := <-errors:
		err = fmt.Errorf("All methods failed when making request")
		zap.S().With("requestID", requestID).Errorln(err)
		return nil, err
	}
}

func readMethodData() map[string]int {
	if runtime.GOOS == "android" {
		methodDataFilePath = config.MethodDataFilePathAndroid
	} else {
		methodDataFilePath = filepath.Join(exeDir, "method_data.json")
	}

	methodDataBytes, err := os.ReadFile(methodDataFilePath)

	if err != nil {
		zap.S().Errorf("Error reading method data from file: %v", err)
		return methodData
	}

	err = json.Unmarshal(methodDataBytes, &methodData)
	if err != nil {
		zap.S().Errorf("Error unmarshalling method data: %v", err)
	}

	zap.S().Debugf("methodData read from file: %v", methodData)

	return methodData
}

func moveMatchingElementsToFront(arr []int, match int) []int {
	var result []int

	for _, val := range arr {
		if val == match {
			result = append(result, val)
		}
	}

	for _, val := range arr {
		if val != match {
			result = append(result, val)
		}
	}

	return result
}

func writeMethodData(eTldPlusOne string, methodIndex int, requestID string) {
	methodDataMutex.Lock()
	defer methodDataMutex.Unlock()

	methodData[eTldPlusOne] = methodIndex

	methodDataBytes, err := json.Marshal(methodData)
	if err != nil {
		zap.S().With("requestID", requestID).Errorf("Error marshalling method data: %v", err)
		return
	}

	err = os.WriteFile(methodDataFilePath, methodDataBytes, 0644)
	if err != nil {
		zap.S().With("requestID", requestID).Errorf("Error writing method data to file: %v", err)
	} else {
		zap.S().With("requestID", requestID).Debugf("methodData written to file: %v", methodData)
	}
}

var httpTransportProxy = &http.Transport{
	TLSHandshakeTimeout:   config.TimeoutTLSHandshake,
	IdleConnTimeout:       config.TimeoutIdleConn,
	ResponseHeaderTimeout: config.TimeoutResponseHeader,
	DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {

		requestID := ctx.Value(requestIDKey).(string)

		contextServerName, ok := ctx.Value(contextServerNameKey).(string)
		if !ok {
			return nil, fmt.Errorf("contextServerName is not a string")
		}
		zap.S().With("requestID", requestID).Debugf("contextServerName: %s", contextServerName)

		contextHost, ok := ctx.Value(contextHostKey).(string)
		if !ok {
			return nil, fmt.Errorf("contextHost is not a string")
		}

		zap.S().With("requestID", requestID).Debugf("Dialing with network %s addr %s SNI %s", network, addr, contextServerName)

		dialConn, err := net.DialTimeout("tcp", addr, config.TimeoutNetDialer)
		if err != nil {
			return nil, fmt.Errorf("Error dialing: %v", err)
		}
		zap.S().With("requestID", requestID).Debugf("net.DialTimeout() done")

		utlsConfig := &utls.Config{
			RootCAs:            x509.NewCertPool(),
			ServerName:         contextServerName,
			InsecureSkipVerify: true,
			VerifyConnection: func(cs utls.ConnectionState) error {
				zap.S().With("requestID", requestID).Debugf("Starting certificate validation...")

				roots := x509.NewCertPool()
				intermediates := x509.NewCertPool()

				for _, cert := range cs.PeerCertificates[1:] {
					if cert.CheckSignatureFrom(cert) == nil {
						roots.AddCert(cert)
					} else {
						intermediates.AddCert(cert)
					}
				}

				opts := x509.VerifyOptions{
					Intermediates: intermediates,
				}

				if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
				}

				isValid := false

				if len(trustedCertDomains[contextHost]) == 0 {
					trustedCertDomains[contextHost] = contextHost
				}

				trusted_hostnames := strings.Split(trustedCertDomains[contextHost], ",")
				for _, h := range trusted_hostnames {
					if err := cs.PeerCertificates[0].VerifyHostname(h); err == nil {
						isValid = true
						break
					}
				}

				if !isValid {
					return fmt.Errorf("certificate with DNSNames: %v does not match expected domains for hostname: %s",
						cs.PeerCertificates[0].DNSNames, contextHost)
				} else {
					zap.S().With("requestID", requestID).Debugf("certificate with DNSNames: %v does match expected domains for hostname: %s",
						cs.PeerCertificates[0].DNSNames, contextHost)
				}

				return nil
			},
		}

		zap.S().With("requestID", requestID).Infof("utlsConfig.ServerName: [%s]", utlsConfig.ServerName)

		uTlsConn := utls.UClient(dialConn, utlsConfig, utls.HelloCustom)

		clientHelloChromeSpec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if err != nil {
			return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
		}

		for _, ext := range clientHelloChromeSpec.Extensions {
			alpnExt, ok := ext.(*utls.ALPNExtension)
			if ok {
				zap.S().With("requestID", requestID).Debugf("alpnExt.AlpnProtocols: %v", alpnExt.AlpnProtocols)
				alpnExt.AlpnProtocols = []string{"http/1.1"}
				zap.S().With("requestID", requestID).Debugf("Updated alpnExt.AlpnProtocols: %v", alpnExt.AlpnProtocols)
				break
			}
		}
		zap.S().With("requestID", requestID).Debugf("Modifying alpnExt done")

		err = uTlsConn.ApplyPreset(&clientHelloChromeSpec)
		if err != nil {
			return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
		}
		zap.S().With("requestID", requestID).Debugf("uTlsConn.ApplyPreset() done")

		err = uTlsConn.Handshake()
		if err != nil {
			return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
		}
		zap.S().With("requestID", requestID).Debugf("uTlsConn.Handshake() done")

		zap.S().With("requestID", requestID).Debugf("Negotiated ALPN: %s", uTlsConn.ConnectionState().NegotiatedProtocol)

		return uTlsConn, err
	},
}

var httpClientProxy = &http.Client{
	Transport: httpTransportProxy,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func makeRequest(ctx context.Context, url_ *url.URL, httpMethod string, header http.Header, body io.ReadCloser, host string, ip string, sni string, debug bool) (*http.Response, error) {
	requestID := ctx.Value(requestIDKey).(string)

	port := "443"
	if strings.Contains(url_.Host, ":") {
		var err error
		_, port, err = net.SplitHostPort(url_.Host)
		if err != nil {
			zap.S().With("requestID", requestID).Errorln("Error splitting host and port:", err)
		}
	}

	urlFull := fmt.Sprintf("https://%s:%s%s", ip, port, url_.RequestURI())
	zap.S().With("requestID", requestID).Infoln("HTTP method:", httpMethod, "URL:", urlFull)

	ctx = context.WithValue(ctx, contextServerNameKey, sni)

	ctx = context.WithValue(ctx, contextHostKey, host)

	req, err := http.NewRequestWithContext(ctx, httpMethod, urlFull, body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Host = host
	zap.S().With("requestID", requestID).Debugf("req.Host: %s", req.Host)
	req.Header = header
	zap.S().With("requestID", requestID).Debugf("req.Header: %s", req.Header)

	if debug {
		curlCommand := fmt.Sprintf("curl -kv '%s' -H 'Host: %s'", urlFull, host)
		for name, values := range header {
			for _, value := range values {
				curlCommand += fmt.Sprintf(" -H '%s: %s'", name, value)
			}
		}
		curlCommand += fmt.Sprintf(" --resolve '%s:443:%s'", host, ip)
		zap.S().With("requestID", requestID).Debugf("Curl equivalent command: %s", curlCommand)
	}

	zap.S().With("requestID", requestID).Debugf("Executing httpClientProxy.Do(req)...")
	resp, err := httpClientProxy.Do(req)
	zap.S().With("requestID", requestID).Debugf("Finished httpClientProxy.Do(req)")

	if debug {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			zap.S().Fatal(err)
		}

		dumpStr := string(dump)
		lines := strings.Split(dumpStr, "\r\n")

		requestLine := strings.Split(lines[0], " ")
		method_ := requestLine[0]
		url4 := requestLine[1]

		headers := make([]string, 0)
		for _, line := range lines[1:] {
			if line == "" {
				break
			}
			headers = append(headers, "-H "+strconv.Quote(line))
		}

		headersStr := strings.Join(headers, " ")
		curlCommand2 := fmt.Sprintf("curl -X %s %s https://%s%s", method_, headersStr, ip, url4)
		zap.S().With("requestID", requestID).Debugf("Curl equivalent command with httpClient headers: %s", curlCommand2)
	}

	if err != nil {
		return nil, err
	}

	return resp, nil
}
