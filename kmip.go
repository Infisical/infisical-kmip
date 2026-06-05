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
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	infisical "github.com/infisical/go-sdk"
	infisicalErrors "github.com/infisical/go-sdk/packages/errors"
	"github.com/pkg/errors"
)

type CertificateSet struct {
	ServerKey              crypto.PrivateKey
	ServerCert             *x509.Certificate
	ServerCertificateChain string
	ServerCAPool           *x509.CertPool
}

type KmipServer struct {
	certs  CertificateSet
	server Server

	listenCh chan error
}

func (s *KmipServer) loadCertificates() error {
	client := resty.New()

	req := client.R().
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.server.getAccessToken()))

	var apiResp *resty.Response
	var err error
	var op string

	if s.server.AccessToken != "" {
		// Enrollment-based server: the cert config (SANs, TTL, common name, key algorithm) lives
		// on the server entity, so /connect takes no body — the access token identifies the server.
		// We deliberately don't set a JSON Content-Type: with no body the API rejects it.
		op = "ServerConnect"
		apiResp, err = req.Post(fmt.Sprintf("%s/v1/kmip/servers/connect", s.server.InfisicalBaseAPIURL))
	} else {
		// Legacy machine-identity server: supply the cert config in the request body.
		op = "ServerRegistration"
		apiResp, err = req.
			SetHeader("Content-Type", "application/json").
			SetBody(KmipServerRegistrationAPIRequest{
				HostnamesOrIps: s.server.HostnamesOrIps,
				CommonName:     s.server.ServerName,
				TTL:            s.server.CertificateTTL,
			}).
			Post(fmt.Sprintf("%s/v1/kmip/server-registration", s.server.InfisicalBaseAPIURL))
	}

	if err != nil {
		s.server.Log.Printf("Error: %+v\n", err)
		return infisicalErrors.NewRequestError(op, err)
	}

	if apiResp.IsError() {
		return infisicalErrors.NewAPIErrorWithResponse(op, apiResp)
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

	s.certs.ServerCertificateChain = result.CertificateChain

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

	// AccessToken is an enrollment-based KMIP server access token. When set, it is used
	// directly for Infisical API calls and the machine-identity login is skipped.
	AccessToken string

	ServerName     string
	CertificateTTL string
	HostnamesOrIps string
}

func StartServer(config ServerConfig) {
	kmip := &KmipServer{}

	var err error

	// Enrollment-based servers (AccessToken set) read their cert config from the platform at
	// /connect, so hostnames/IPs and TTL aren't supplied here — only the legacy machine-identity
	// path passes and validates them.
	if config.AccessToken == "" {
		if err = ValidateHostnamesOrIPs(config.HostnamesOrIps); err != nil {
			log.Fatalf("Validation for field HostnamesOrIps failed. %v", err)
		}
		if err = ValidateDuration(config.CertificateTTL); err != nil {
			log.Fatalf("Validation for field CertificateTTL failed. %v", err)
		}
	}

	kmip.server.Addr = config.Addr
	kmip.server.InfisicalBaseAPIURL = config.InfisicalBaseAPIURL
	kmip.server.ServerName = config.ServerName
	kmip.server.CertificateTTL = config.CertificateTTL
	kmip.server.HostnamesOrIps = config.HostnamesOrIps

	kmip.server.Log = log.New(os.Stderr, "[kmip] ", log.LstdFlags)

	if config.AccessToken != "" {
		// Enrollment-based path: the caller (CLI) already obtained a KMIP server access
		// token via token/AWS enrollment. Use it directly, no machine-identity login.
		kmip.server.AccessToken = config.AccessToken
	} else {
		// Legacy machine-identity path.
		infisicalClient := infisical.NewInfisicalClient(context.Background(), infisical.Config{
			SiteUrl:          strings.TrimSuffix(kmip.server.InfisicalBaseAPIURL, "/api"),
			AutoTokenRefresh: true,
		})

		kmip.server.InfisicalAuth = infisicalClient.Auth()
		machineIdentityClientId := config.IdentityClientId
		machineIdentityClientSecret := config.IdentityClientSecret

		_, err = kmip.server.InfisicalAuth.UniversalAuthLogin(machineIdentityClientId, machineIdentityClientSecret)
		if err != nil {
			log.Fatalf("error authenticating with Infisical. %v", err)
			return
		}
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

	// Parse the server certificate chain, excluding root certificates
	var certChain [][]byte
	certChain = append(certChain, kmip.certs.ServerCert.Raw)

	if kmip.certs.ServerCertificateChain != "" {
		chainPemBytes := []byte(kmip.certs.ServerCertificateChain)
		for {
			block, rest := pem.Decode(chainPemBytes)
			if block == nil {
				break
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				kmip.server.Log.Printf("Warning: error parsing certificate in server chain: %v", err)
				break
			}

			if cert.Issuer.String() != cert.Subject.String() {
				certChain = append(certChain, cert.Raw)
			}

			chainPemBytes = rest
		}
	}

	kmip.server.TLSConfig.Certificates = []tls.Certificate{
		{
			Certificate: certChain,
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
