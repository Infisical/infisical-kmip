package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"github.com/smira/go-kmip"
)

type CertificateSet struct {
	ServerKey    crypto.PrivateKey
	ServerCert   *x509.Certificate
	ServerCAPool *x509.CertPool
}

func (set *CertificateSet) Load() error {
	var err error

	// Read server private key from PEM file
	serverPrivateKeyPemBytes, err := os.ReadFile("../certificates/server/server-private-key.txt")
	if err != nil {
		return errors.Wrapf(err, "error reading server key PEM file")
	}

	block, _ := pem.Decode(serverPrivateKeyPemBytes)
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
		set.ServerKey = key
		ok = true
	case *rsa.PrivateKey:
		set.ServerKey = key
		ok = true
	default:
		ok = false
	}

	if !ok {
		return errors.New("server private key is not of a supported type (ECDSA or RSA)")
	}

	// Read server certificate from PEM file
	serverCertPemBytes, err := os.ReadFile("../certificates/server/server-cert.pem")
	if err != nil {
		return errors.Wrapf(err, "error reading server cert PEM file")
	}

	block, _ = pem.Decode(serverCertPemBytes)
	if block == nil {
		return errors.New("failed to decode PEM block containing server certificate")
	}

	set.ServerCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing server cert")
	}

	// Read server certificate chain from PEM file
	serverChainPemBytes, err := os.ReadFile("../certificates/server/server-chain.pem")
	if err != nil {
		return errors.Wrapf(err, "error reading server certificate chain PEM file")
	}

	// Create a new CertPool for the server and add each certificate in the chain
	set.ServerCAPool = x509.NewCertPool()
	for {
		block, rest := pem.Decode(serverChainPemBytes)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.Wrapf(err, "error parsing certificate in server chain")
		}

		set.ServerCAPool.AddCert(cert)
		serverChainPemBytes = rest
	}

	return nil

}

type KmipServer struct {
	certs  CertificateSet
	server kmip.Server

	listenCh chan error
}

func start(s *KmipServer) {
	err := s.certs.Load()
	if err != nil {
		log.Fatalf("error loading certificates: %v", err)
	}
	fmt.Println("Certificates loaded successfully")

	s.server.Addr = "localhost:5696"
	s.server.InfisicalBaseAPIURL = "http://localhost:8080"
	s.server.TLSConfig = &tls.Config{}

	s.server.SessionAuthHandler = func(conn net.Conn) (sessionAuth kmip.SessionAuth, err error) {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				clientCert := state.PeerCertificates[0]

				var signingMethod jwt.SigningMethod
				switch privKey := s.server.CertificatePrivateKey.(type) {
				case *rsa.PrivateKey:
					// Get RSA key size in bits
					keySize := privKey.Size() * 8
					switch keySize {
					case 2048:
						signingMethod = jwt.SigningMethodRS256
					case 4096:
						signingMethod = jwt.SigningMethodRS512 // Generally better to use stronger hash with larger key
					default:
						return kmip.SessionAuth{}, fmt.Errorf("unsupported RSA key size: %d", keySize)
					}
				case *ecdsa.PrivateKey:
					// Check curve type
					switch privKey.Curve.Params().Name {
					case "P-256":
						signingMethod = jwt.SigningMethodES256
					case "P-384":
						signingMethod = jwt.SigningMethodES384
					default:
						return kmip.SessionAuth{}, fmt.Errorf("unsupported elliptic curve: %s", privKey.Curve.Params().Name)
					}
				default:
					return kmip.SessionAuth{}, errors.New("unsupported private key type (only RSA or ECDSA allowed)")
				}

				claims := jwt.MapClaims{
					"clientId":  clientCert.Subject.CommonName,
					"projectId": clientCert.Subject.OrganizationalUnit[0],
					"exp":       time.Now().Add(5 * time.Minute).Unix(),
					"iat":       time.Now().Unix(),
				}

				token := jwt.NewWithClaims(signingMethod, claims)
				tokenString, err := token.SignedString(s.server.CertificatePrivateKey)
				if err != nil {
					return kmip.SessionAuth{}, err
				}

				return kmip.SessionAuth{
					ClientJwt:                     tokenString,
					ClientCertificateSerialNumber: clientCert.SerialNumber.String(),
				}, nil
			} else {
				return kmip.SessionAuth{}, errors.New("no client certificate provided")
			}
		}
		return kmip.SessionAuth{}, errors.New("connection is not a TLS connection")
	}

	s.server.TLSConfig.MinVersion = tls.VersionTLS12
	s.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

	s.server.TLSConfig.ClientCAs = s.certs.ServerCAPool

	s.server.CertificatePrivateKey = s.certs.ServerKey
	s.server.CertificateSerialNumber = s.certs.ServerCert.SerialNumber.Text(16)

	s.server.TLSConfig.Certificates = []tls.Certificate{
		{
			Certificate: [][]byte{s.certs.ServerCert.Raw},
			PrivateKey:  s.certs.ServerKey,
		},
	}

	s.server.ReadTimeout = time.Second
	s.server.WriteTimeout = time.Second

	s.server.Log = log.New(os.Stderr, "[kmip] ", log.LstdFlags)

	s.listenCh = make(chan error, 1)
	initializedCh := make(chan struct{})

	go func() {
		s.listenCh <- s.server.ListenAndServe(initializedCh)
	}()

	<-initializedCh
	fmt.Println("Server initialized")
	<-s.listenCh
	fmt.Println("Server closed")
}

func main() {
	fmt.Println("Starting KMIP server...")
	server := &KmipServer{}
	start(server)

}
