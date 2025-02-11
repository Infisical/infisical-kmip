package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"

	"github.com/pkg/errors"
)

type CertificateSet struct {
	ServerKey  *ecdsa.PrivateKey
	ServerCert *x509.Certificate

	ClientKey  *ecdsa.PrivateKey
	ClientCert *x509.Certificate

	ServerCAPool *x509.CertPool
	ClientCAPool *x509.CertPool
}

func (set *CertificateSet) Generate(hostnames []string, ips []net.IP) error {
	var err error

	// Read server private key from PEM file
	serverPrivateKeyPemBytes, err := os.ReadFile("./certificates/server/server-private-key.txt")
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
	set.ServerKey, ok = key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("server private key is not of type ECDSA")
	}

	// Read server certificate from PEM file
	serverCertPemBytes, err := os.ReadFile("./certificates/server/server-cert.pem")
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

	// Read client private key from PEM file
	clientPrivateKeyPemBytes, err := os.ReadFile("./certificates/client/client-private-key.txt")
	if err != nil {
		return errors.Wrapf(err, "error reading client key PEM file")
	}

	block, _ = pem.Decode(clientPrivateKeyPemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return errors.New("failed to decode PEM block containing client private key")
	}

	key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing client private key")
	}

	set.ClientKey, ok = key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("client private key is not of type ECDSA")
	}

	// Read client certificate from PEM file
	clientCertPemBytes, err := os.ReadFile("./certificates/client/client-cert.pem")
	if err != nil {
		return errors.Wrapf(err, "error reading client cert PEM file")
	}

	block, _ = pem.Decode(clientCertPemBytes)
	if block == nil {
		return errors.New("failed to decode PEM block containing client certificate")
	}

	set.ClientCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing client cert")
	}

	// Read server certificate chain from PEM file
	serverChainPemBytes, err := os.ReadFile("./certificates/server/server-chain.pem")
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

	// Read client certificate chain from PEM file
	clientChainPemBytes, err := os.ReadFile("./certificates/client/client-chain.pem")
	if err != nil {
		return errors.Wrapf(err, "error reading client certificate chain PEM file")
	}

	// Create a new CertPool for the client and add each certificate in the chain
	set.ClientCAPool = x509.NewCertPool()
	for {
		block, rest := pem.Decode(clientChainPemBytes)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.Wrapf(err, "error parsing certificate in client chain")
		}

		set.ClientCAPool.AddCert(cert)
		clientChainPemBytes = rest
	}

	return nil
}
