package fbproxy

import (
	"crypto/tls"
	"crypto/x509"

	config "fb-proxy/pkg/config"
)

func init() {
	if goproxyCaErr != nil {
		panic("Error parsing builtin CA " + goproxyCaErr.Error())
	}
	var err error
	if GoproxyCa.Leaf, err = x509.ParseCertificate(GoproxyCa.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
}

var tlsClientSkipVerify = &tls.Config{InsecureSkipVerify: true}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var GoproxyCa, goproxyCaErr = tls.X509KeyPair(config.CA_CERT, config.CA_KEY)
