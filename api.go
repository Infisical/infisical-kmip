package kmip

import "time"

type KmipGetAPIResponse struct {
	Id        string `json:"id"`
	Value     string `json:"value"`
	Algorithm string `json:"algorithm"`
}

type KmipGetAPIRequest struct {
	Id string `json:"id"`
}

type KmipCreateAPIResponse struct {
	Id string `json:"id"`
}

type KmipCreateAPIRequest struct {
	Algorithm string `json:"algorithm"`
}

type KmipDestroyAPIRequest struct {
	Id string `json:"id"`
}

type KmipDestroyAPIResponse struct {
	Id string `json:"id"`
}

type KmipGetAttributeAPIRequest struct {
	Id string `json:"id"`
}

type KmipGetAttributeAPIResponse struct {
	Id        string    `json:"id"`
	Algorithm string    `json:"algorithm"`
	IsActive  bool      `json:"isActive"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type KmipActivateAPIRequest struct {
	Id string `json:"id"`
}

type KmipActivateAPIResponse struct {
	Id       string `json:"id"`
	IsActive bool   `json:"isActive"`
}

type KmipRevokeAPIRequest struct {
	Id string `json:"id"`
}

type KmipRevokeAPIResponse struct {
	Id string `json:"id"`
}

type KmipLocateAPIResponse struct {
	Objects []struct {
		Id        string `json:"id"`
		IsActive  bool   `json:"isActive"`
		Algorithm string `json:"algorithm"`
		Name      string `json:"name"`
	} `json:"objects"`
}

type KmipRegisterAPIRequest struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	Algorithm string `json:"algorithm"`
}

type KmipRegisterAPIResponse struct {
	Id string `json:"id"`
}

type KmipServerRegistrationAPIRequest struct {
	HostnamesOrIps string `json:"hostnamesOrIps"`
	CommonName     string `json:"commonName"`
	TTL            string `json:"ttl"`
}

type KmipServerRegistrationAPIResponse struct {
	Certificate            string `json:"certificate"`
	CertificateChain       string `json:"certificateChain"`
	PrivateKey             string `json:"privateKey"`
	ClientCertificateChain string `json:"clientCertificateChain"`
}
