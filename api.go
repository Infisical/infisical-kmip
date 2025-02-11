package kmip

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
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`
}
