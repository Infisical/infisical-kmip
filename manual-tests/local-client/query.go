package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	kmip "github.com/infisical/infisical-kmip"
)

func main() {
	// Try to load client certificates
	var cert tls.Certificate
	var err error

	// Try to load client certificate and key
	certFile := "./certificates/client-cert.pem"
	keyFile := "./certificates/client-private-key.pem"

	if cert, err = tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		log.Printf("Warning: Could not load client certificates from %s and %s: %v", certFile, keyFile, err)
		log.Println("Continuing without client certificates (this may fail if server requires them)")
	}

	// Try to load CA certificate for server verification
	var caCertPool *x509.CertPool
	caFile := "./client-chain.pem"
	if caCert, err := ioutil.ReadFile(caFile); err == nil {
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		log.Printf("Loaded CA certificate from %s", caFile)
	} else {
		log.Printf("Warning: Could not load CA certificate from %s: %v", caFile, err)
		log.Println("Using InsecureSkipVerify for server certificate verification")
	}

	// Create TLS config for client authentication
	tlsConfig := &tls.Config{
		InsecureSkipVerify: caCertPool == nil, // Only skip if we don't have CA cert
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
	}

	// Create KMIP client
	client := &kmip.Client{
		Endpoint:  "127.0.0.1:5696",
		TLSConfig: tlsConfig,
	}

	// Connect to server
	if err := client.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	fmt.Println("Connected to KMIP server")

	// Test OPERATION_QUERY with different query functions
	queryFunctions := []kmip.Enum{
		kmip.QUERY_OPERATIONS,
		kmip.QUERY_OBJECTS,
		kmip.QUERY_SERVER_INFORMATION,
		kmip.QUERY_APPLICATION_NAMESPACES,
		kmip.QUERY_EXTENSION_LIST,
		kmip.QUERY_EXTENSION_MAP,
		kmip.QUERY_ATTESTATION_TYPES,
		kmip.QUERY_RNGS,
		kmip.QUERY_VALIDATIONS,
		kmip.QUERY_PROFILES,
		kmip.QUERY_CAPABILITIES,
		kmip.QUERY_CLIENT_REGISTRATION_METHODS,
		kmip.QUERY_DEFAULTS_INFORMATION,
		kmip.QUERY_STORAGE_PROTECTION_MASKS,
	}

	for _, queryFunc := range queryFunctions {
		fmt.Printf("\n=== Testing Query Function: %d ===\n", queryFunc)

		// Create query request
		queryReq := kmip.QueryRequest{
			QueryFunctions: []kmip.Enum{queryFunc},
		}

		// Send query request
		resp, err := client.Send(kmip.OPERATION_QUERY, queryReq)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Cast response to QueryResponse
		queryResp := resp.(kmip.QueryResponse)

		fmt.Printf("Operations: %v\n", queryResp.Operations)
		fmt.Printf("Object Types: %v\n", queryResp.ObjectTypes)
		fmt.Printf("Vendor Identification: %s\n", queryResp.VendorIdentification)
		fmt.Printf("Profile Information: %v\n", queryResp.ProfileInformation)
	}
}
