package kmip

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/go-resty/resty/v2"
	infisical "github.com/infisical/go-sdk"
	infisicalErrors "github.com/infisical/go-sdk/packages/errors"
	"github.com/pkg/errors"
)

type CertificateSet struct {
	ServerKey    crypto.PrivateKey
	ServerCert   *x509.Certificate
	ServerCAPool *x509.CertPool
}

type KmipServer struct {
	certs  CertificateSet
	server Server

	listenCh chan error
}

func (s *KmipServer) loadCertificates() error {
	client := resty.New()

	payload := KmipServerRegistrationAPIRequest{
		HostnamesOrIps: s.server.HostnamesOrIps,
		CommonName:     s.server.ServerName,
		TTL:            s.server.CertificateTTL,
	}

	apiResp, err := client.R().
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.server.InfisicalAuth.GetAccessToken())).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(fmt.Sprintf("%s/v1/kmip/server-registration", s.server.InfisicalBaseAPIURL))

	if err != nil {
		s.server.Log.Printf("Error: %+v\n", err)
		return infisicalErrors.NewRequestError("ServerRegistration", err)
	}

	if apiResp.IsError() {
		return infisicalErrors.NewAPIErrorWithResponse("ServerRegistration", apiResp)
	}

	var result KmipServerRegistrationAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return errors.Wrap(err, "failed to decode response")
	}

	block, _ := pem.Decode([]byte(result.PrivateKey))
	if block == nil || block.Type != "PRIVATE KEY" {
		return errors.New("failed to decode PEM block containing server private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing server private key")
	}

	var ok bool
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		s.certs.ServerKey = key
		ok = true
	case *rsa.PrivateKey:
		s.certs.ServerKey = key
		ok = true
	default:
		ok = false
	}

	if !ok {
		return errors.New("server private key is not of a supported type (ECDSA or RSA)")
	}

	block, _ = pem.Decode([]byte(result.Certificate))
	if block == nil {
		return errors.New("failed to decode PEM block containing server certificate")
	}

	s.certs.ServerCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing server cert")
	}

	s.certs.ServerCAPool = x509.NewCertPool()
	clientChainPemBytes := []byte(result.ClientCertificateChain)
	for {
		block, rest := pem.Decode(clientChainPemBytes)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.Wrapf(err, "error parsing certificate in client chain")
		}

		s.certs.ServerCAPool.AddCert(cert)
		clientChainPemBytes = rest
	}

	log.Println("Certificates loaded successfully")
	return nil
}

type ServerConfig struct {
	Addr                 string
	InfisicalBaseAPIURL  string
	IdentityClientId     string
	IdentityClientSecret string

	ServerName     string
	CertificateTTL string
	HostnamesOrIps string
}

func StartServer(config ServerConfig) {
	kmip := &KmipServer{}
	kmip.server.Addr = config.Addr
	kmip.server.InfisicalBaseAPIURL = config.InfisicalBaseAPIURL
	kmip.server.ServerName = config.ServerName
	kmip.server.CertificateTTL = config.CertificateTTL
	kmip.server.HostnamesOrIps = config.HostnamesOrIps

	kmip.server.Log = log.New(os.Stderr, "[kmip] ", log.LstdFlags)

	infisicalClient := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl:          kmip.server.InfisicalBaseAPIURL,
		AutoTokenRefresh: true,
	})

	kmip.server.InfisicalAuth = infisicalClient.Auth()
	machineIdentityClientId := config.IdentityClientId
	machineIdentityClientSecret := config.IdentityClientSecret

	// TODO: add support for other auth methods
	_, err := kmip.server.InfisicalAuth.UniversalAuthLogin(machineIdentityClientId, machineIdentityClientSecret)
	if err != nil {
		log.Fatalf("error authenticating with Infisical. %v", err)
		return
	}

	err = kmip.loadCertificates()
	if err != nil {
		log.Fatalf("error loading certificates from Infisical. %v", err)
		return
	}

	kmip.server.SessionAuthHandler = func(conn net.Conn) (sessionAuth SessionAuth, err error) {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				clientCert := state.PeerCertificates[0]
				return SessionAuth{
					ClientCertificateSerialNumber: clientCert.SerialNumber.String(),
					ClientId:                      clientCert.Subject.CommonName,
					ProjectId:                     clientCert.Subject.OrganizationalUnit[0],
				}, nil
			} else {
				return SessionAuth{}, errors.New("no client certificate provided")
			}
		}
		return SessionAuth{}, errors.New("connection is not a TLS connection")
	}

	kmip.server.TLSConfig = &tls.Config{}
	kmip.server.TLSConfig.MinVersion = tls.VersionTLS12
	kmip.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	kmip.server.TLSConfig.ClientCAs = kmip.certs.ServerCAPool

	kmip.server.CertificatePrivateKey = kmip.certs.ServerKey
	kmip.server.CertificateSerialNumber = kmip.certs.ServerCert.SerialNumber.Text(16)

	kmip.server.TLSConfig.Certificates = []tls.Certificate{
		{
			Certificate: [][]byte{kmip.certs.ServerCert.Raw},
			PrivateKey:  kmip.certs.ServerKey,
		},
	}

	kmip.server.ReadTimeout = time.Second * 10
	kmip.server.WriteTimeout = time.Second * 10

	kmip.listenCh = make(chan error, 1)
	initializedCh := make(chan struct{})

	go func() {
		kmip.listenCh <- kmip.server.ListenAndServe(initializedCh)
	}()

	<-initializedCh
	kmip.server.Log.Println("Server initialized")
	<-kmip.listenCh
	kmip.server.Log.Println("Server closed")
}
