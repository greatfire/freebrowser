package fbproxy

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	config "fb-proxy/pkg/config"

	"github.com/elazarl/goproxy"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var startTime time.Time = time.Now()

type ZapLogger struct{}

func (l *ZapLogger) Printf(format string, v ...interface{}) {
	zap.S().Infof(format, v...)
}

func isNotWebSocketUpgrade(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	isWebSocket := websocket.IsWebSocketUpgrade(req)
	if isWebSocket {
		zap.S().Debugln("proxy.OnRequest isWebSocketUpgrade")
	}
	return !isWebSocket
}

func StartProxy() {
	port := config.ProxyPort
	debug := false
	logLevel := "fatal"

	if !config.Production {
		portFlag := flag.String("port", port, "port to listen on")
		debugFlag := flag.Bool("debug", debug, "enable debug mode")
		logLevelFlag := flag.String("loglevel", logLevel, "set logging level: debug, info, warn, error, dpanic, panic, fatal")

		flag.Parse()

		port = *portFlag
		debug = *debugFlag
		logLevel = *logLevelFlag

	}

	loggerJSON := []byte(fmt.Sprintf(`{
		"level": "%s",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stderr"],
		"encoderConfig": {
		  "messageKey": "msg",
		  "levelKey": "",
		  "timeKey": "ts",
		  "timeEncoder": "iso8601"
		}
	  }`, logLevel))
	var cfg zap.Config
	if err := json.Unmarshal(loggerJSON, &cfg); err != nil {
		panic(err)
	}
	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)
	defer logger.Sync()

	proxy := goproxy.NewProxyHttpServer()

	proxy.Logger = &ZapLogger{}

	if logLevel == "debug" || logLevel == "info" {
		proxy.Verbose = true
	} else {
		proxy.Verbose = false
	}

	zap.S().Debugln("Using custom ECDSA certificate")
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&GoproxyCa)}, host
	}))

	var ReqCondition goproxy.ReqConditionFunc = isNotWebSocketUpgrade
	proxy.OnRequest(ReqCondition).DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {

		requestID := fmt.Sprintf("%p", req)

		if req == nil {
			zap.S().With("requestID", requestID).Errorln("proxy.OnRequest request is nil")
			return nil, nil
		}
		if req.URL == nil {
			zap.S().With("requestID", requestID).Errorln("proxy.OnRequest request.URL is nil")
			return nil, nil
		}
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		if req.URL.Scheme == "" {
			if req.TLS != nil {
				req.URL.Scheme = "https"
			} else {
				req.URL.Scheme = "http"
			}
		}
		zap.S().With("requestID", requestID).Infof("proxy.OnRequest URL: %s", req.URL.String())

		resp, err := ProcessRequest(req, debug)
		if err != nil {
			zap.S().With("requestID", requestID).Errorf("proxy.OnRequest error: %v", err)
			html := `<html><body>Error occurred: ` + err.Error() + `</body></html>`
			if config.Production {
				html = `<html><body>Error occurred, please try again</body></html>`
			}
			resp2 := &http.Response{
				Request:       req,
				Status:        "500 Internal Server Error",
				StatusCode:    500,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Body:          io.NopCloser(strings.NewReader(html)),
				ContentLength: int64(len(html)),
				Header:        make(http.Header),
			}
			return nil, resp2
		}

		return nil, resp
	})

	go initProxy()

	zap.S().Infof("Starting proxy on http://localhost:%s", port)
	zap.S().Fatal(http.ListenAndServe(":"+port, proxy))
}
