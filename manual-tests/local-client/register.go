package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	kmip "github.com/infisical/infisical-kmip"
)

func ExecuteRegister() {
	// Load client certificates and CA certificate
	var cert tls.Certificate
	var err error

	certFile := "./certificates/client-cert.pem"
	keyFile := "./certificates/client-private-key.pem"

	if cert, err = tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		log.Printf("Warning: Could not load client certificates: %v", err)
	}

	var caCertPool *x509.CertPool
	caFile := "./client-chain.pem"
	if caCert, err := ioutil.ReadFile(caFile); err == nil {
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: caCertPool == nil,
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

	// Simulating PowerScale OneFS sending symmetric key as SecretData
	symmetricKeyBytes := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}

	// Create SecretData object
	secretData := kmip.SecretData{
		SecretDataType: kmip.SECRET_DATA_TYPE_PASSWORD,
		KeyBlock: kmip.KeyBlock{
			FormatType: kmip.KEY_FORMAT_RAW,
			Value: kmip.KeyValue{
				KeyMaterial: symmetricKeyBytes,
			},
		},
	}

	// Create a name attribute
	nameAttribute := kmip.Attribute{
		Name: kmip.ATTRIBUTE_NAME_NAME,
		Value: kmip.Name{
			Value: "my-secret-key-name-z",
			Type:  kmip.NAME_TYPE_UNINTERPRETED_TEXT_STRING,
		},
	}

	// Test custom attribute with x- prefix
	customAttribute1 := kmip.Attribute{
		Name:  "x-Isilon-ClusterGUID",
		Value: "cluster-guid-12345",
	}

	// Test standard custom attribute approach
	customAttribute2 := kmip.Attribute{
		Name: kmip.ATTRIBUTE_NAME_CUSTOM_ATTRIBUTE,
		Value: kmip.CustomAttribute{
			AttributeName:  "x-my-custom-property", // This is where the x- prefix goes
			AttributeValue: "some custom value",
		},
	}

	// Application Specific Information attribute
	appSpecificInfo := kmip.Attribute{
		Name: kmip.ATTRIBUTE_NAME_APPLICATION_SPECIFIC_INFORMATION,
		Value: kmip.ApplicationSpecificInformation{
			ApplicationNamespace: "com.example.myapp",
			ApplicationData:      "custom-application-data-value",
		},
	}

	// Link attribute - links this secret to a certificate
	linkAttribute := kmip.Attribute{
		Name: kmip.ATTRIBUTE_NAME_LINK,
		Value: kmip.Link{
			LinkType:               kmip.LINK_TYPE_CERTIFICATE_LINK,
			LinkedObjectIdentifier: "cert-12345-abcde", // ID of the linked certificate
		},
	}

	// Contact Information attribute - will trigger type mismatch on decode
	contactInfo := kmip.Attribute{
		Name: kmip.ATTRIBUTE_NAME_CONTACT_INFORMATION,
		Value: kmip.ContactInformation{
			ContactInformation: "admin@example.com",
		},
	}

	// Create template attribute with all attributes
	templateAttribute := kmip.TemplateAttribute{
		Attributes: []kmip.Attribute{nameAttribute, customAttribute1, customAttribute2, appSpecificInfo, linkAttribute, contactInfo},
	}

	// Create register request
	registerReq := kmip.RegisterRequest{
		ObjectType:        kmip.OBJECT_TYPE_SECRET_DATA,
		TemplateAttribute: templateAttribute,
		SecretData:        secretData,
	}

	// Send register request
	resp, err := client.Send(kmip.OPERATION_REGISTER, registerReq)
	if err != nil {
		log.Fatalf("Failed to register secret data: %v", err)
	}

	// Cast response to RegisterResponse
	registerResp := resp.(kmip.RegisterResponse)

	fmt.Printf("Successfully registered secret data with unique identifier: %s\n", registerResp.UniqueIdentifier)
}
