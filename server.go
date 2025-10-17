package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gosimple/slug"
	infisical "github.com/infisical/go-sdk"
	infisicalErrors "github.com/infisical/go-sdk/packages/errors"
	"github.com/pkg/errors"
)

// Server implements core KMIP server
type Server struct {
	// Listen address
	Addr string

	// Infisical Base API URL
	InfisicalBaseAPIURL string

	// TLS Configuration for the server
	TLSConfig *tls.Config

	// Log destination (if not set, log is discarded)
	Log *log.Logger

	// Supported version of KMIP, in the order of the preference
	//
	// If not set, defaults to DefaultSupportedVersions
	SupportedVersions []ProtocolVersion

	// Network read & write timeouts
	//
	// If set to zero, timeouts are not enforced
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// SessionAuthHandler is called after TLS handshake
	//
	// This handler might additionally verify client TLS cert or perform
	// any other kind of auth (say, by soure address)
	SessionAuthHandler func(conn net.Conn) (sessionAuth SessionAuth, err error)

	CertificatePrivateKey   crypto.PrivateKey
	CertificateSerialNumber string

	InfisicalAuth infisical.AuthInterface

	l        net.Listener
	mu       sync.Mutex
	wg       sync.WaitGroup
	doneChan chan struct{}
	handlers map[Enum]Handler

	ServerName     string
	CertificateTTL string
	HostnamesOrIps string
}

// Handler processes specific KMIP operation
type Handler func(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error)

type SessionAuth struct {
	ClientCertificateSerialNumber string
	ProjectId                     string
	ClientId                      string
}

// SessionContext is initialized for each connection
type SessionContext struct {
	// Unique session identificator
	SessionID string

	// Additional opaque data related to connection auth, as returned by Server.SessionAuthHandler
	SessionAuth SessionAuth
}

// RequestContext covers batch of requests
type RequestContext struct {
	SessionContext

	IdPlaceholder string
	// RequestAuth captures result of request authentication
	RequestAuth interface{}
}

// ListenAndServe creates TLS listening socket and calls Serve
//
// Channel initializedCh will be closed when listener is initialized
// (or fails to be initialized)
func (s *Server) ListenAndServe(initializedCh chan struct{}) error {
	addr := s.Addr
	if addr == "" {
		addr = "localhost:5696"
	}

	l, err := tls.Listen("tcp", addr, s.TLSConfig)
	s.Log.Printf("Listening on %s\n", addr)

	if err != nil {
		close(initializedCh)
		return err
	}

	return s.Serve(l, initializedCh)
}

// Serve starts accepting and serving KMIP connection on a given listener
//
// Channel initializedCh will be closed when listener is initialized
// (or fails to be initialized)
func (s *Server) Serve(l net.Listener, initializedCh chan struct{}) error {
	s.mu.Lock()
	s.l = l

	if s.Log == nil {
		s.Log = log.New(ioutil.Discard, "", log.LstdFlags)
	}

	if len(s.SupportedVersions) == 0 {
		s.SupportedVersions = append([]ProtocolVersion(nil), DefaultSupportedVersions...)
	}

	if s.handlers == nil {
		s.initHandlers()
	}
	s.mu.Unlock()

	close(initializedCh)

	defer l.Close()

	lastSession := uint32(0)

	var tempDelay time.Duration

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.getDoneChan():
				return nil
			default:
			}

			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				s.Log.Printf("[ERROR] Accept error: %s, retrying in %s", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			return err
		}

		lastSession++
		tempDelay = 0

		s.wg.Add(1)
		go s.serve(conn, fmt.Sprintf("%08x", lastSession))
	}
}

// Shutdown performs graceful shutdown of KMIP server waiting for connections to be closed
//
// Context might be used to limit time to wait for draining complete
func (s *Server) Shutdown(ctx context.Context) error {
	close(s.getDoneChan())

	s.mu.Lock()
	if s.l != nil {
		s.l.Close()
		s.l = nil
	}
	s.mu.Unlock()

	waitGroupDone := make(chan struct{})

	go func() {
		s.wg.Wait()
		close(waitGroupDone)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitGroupDone:
		return nil
	}
}

// Handle register handler for operation
//
// Server provides default handler for DISCOVER_VERSIONS operation, any other
func (s *Server) Handle(operation Enum, handler Handler) {
	if s.handlers == nil {
		s.initHandlers()
	}

	s.handlers[operation] = handler
}

func (s *Server) initHandlers() {
	s.handlers = make(map[Enum]Handler)
	s.handlers[OPERATION_DISCOVER_VERSIONS] = s.handleDiscoverVersions
	s.handlers[OPERATION_CREATE] = s.handleCreate
	s.handlers[OPERATION_GET] = s.handleGet
	s.handlers[OPERATION_DESTROY] = s.handleDestroy
	s.handlers[OPERATION_GET_ATTRIBUTES] = s.handleGetAttributes
	s.handlers[OPERATION_ACTIVATE] = s.handleActivate
	s.handlers[OPERATION_REVOKE] = s.handleRevoke
	s.handlers[OPERATION_QUERY] = s.handleQuery
	s.handlers[OPERATION_LOCATE] = s.handleLocate
	s.handlers[OPERATION_REGISTER] = s.handleRegister
}

func (s *Server) getDoneChan() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.doneChan == nil {
		s.doneChan = make(chan struct{})
	}

	return s.doneChan
}

func (s *Server) serve(conn net.Conn, session string) {
	defer s.wg.Done()
	defer func() {
		s.Log.Printf("[INFO] [%s] Closed connection from %s", session, conn.RemoteAddr().String())
		conn.Close()
	}()

	s.Log.Printf("[INFO] [%s] New connection from %s", session, conn.RemoteAddr().String())

	sessionCtx := &SessionContext{
		SessionID: session,
	}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if s.ReadTimeout != 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		if s.WriteTimeout != 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		if err := tlsConn.Handshake(); err != nil {
			s.Log.Printf("[ERROR] [%s] Error in TLS handshake: %s", session, err)
			return
		}
	}

	s.mu.Lock()
	sessionAuthHandler := s.SessionAuthHandler
	s.mu.Unlock()

	if sessionAuthHandler != nil {
		var err error

		sessionCtx.SessionAuth, err = sessionAuthHandler(conn)
		if err != nil {
			s.Log.Printf("[ERROR] [%s] Error in session auth handler: %s", session, err)
			return
		}
	}

	d := NewDecoder(conn)
	e := NewEncoder(conn)

	for {
		var req = &Request{}

		if s.ReadTimeout != 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}

		err := d.Decode(req)
		if err == io.EOF {
			break
		}

		if err != nil {
			s.Log.Printf("[ERROR] [%s] Error decoding KMIP message: %s", session, err)
			break
		}

		var resp *Response
		resp, err = s.handleBatch(sessionCtx, req)
		if err != nil {
			s.Log.Printf("[ERROR] [%s] Fatal error handling batch: %s", session, err)
			break
		}

		if s.WriteTimeout != 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		err = e.Encode(resp)
		if err != nil {
			s.Log.Printf("[ERROR] [%s] Error encoding KMIP response: %s", session, err)
		}
	}
}

func (s *Server) handleBatch(session *SessionContext, req *Request) (resp *Response, err error) {
	if int(req.Header.BatchCount) != len(req.BatchItems) {
		err = errors.Errorf("request batch count doesn't match number of batch items: %d != %d", req.Header.BatchCount, len(req.BatchItems))
		return
	}

	if req.Header.AsynchronousIndicator {
		err = errors.New("asynchnronous requests are not supported")
		return
	}

	resp = &Response{
		Header: ResponseHeader{
			Version:    req.Header.Version,
			TimeStamp:  time.Now(),
			BatchCount: req.Header.BatchCount,
		},
		BatchItems: make([]ResponseBatchItem, req.Header.BatchCount),
	}

	if req.Header.Version.Major == 1 && req.Header.Version.Minor == 4 {
		resp.Header.ClientCorrelationValue = req.Header.ClientCorrelationValue
	}

	requestCtx := &RequestContext{
		SessionContext: *session,
	}

	for i := range req.BatchItems {
		resp.BatchItems[i].Operation = req.BatchItems[i].Operation
		resp.BatchItems[i].UniqueID = append([]byte(nil), req.BatchItems[i].UniqueID...)

		var (
			batchResp interface{}
			batchErr  error
		)

		batchResp, batchErr = s.handleWrapped(requestCtx, &req.BatchItems[i])
		if batchErr != nil {
			s.Log.Printf("[WARN] [%s] Request failed, operation %v: %s", requestCtx.SessionID, operationMap[req.BatchItems[i].Operation], batchErr)

			resp.BatchItems[i].ResultStatus = RESULT_STATUS_OPERATION_FAILED
			resp.BatchItems[i].ResultMessage = batchErr.Error()
			if protoErr, ok := batchErr.(Error); ok {
				resp.BatchItems[i].ResultReason = protoErr.ResultReason()
			} else {
				resp.BatchItems[i].ResultReason = RESULT_REASON_GENERAL_FAILURE
			}
		} else {
			s.Log.Printf("[INFO] [%s] Request processed, operation %v", requestCtx.SessionID, operationMap[req.BatchItems[i].Operation])
			resp.BatchItems[i].ResultStatus = RESULT_STATUS_SUCCESS
			resp.BatchItems[i].ResponsePayload = batchResp
		}
	}

	return
}

func (s *Server) handleWrapped(request *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errors.Errorf("panic: %s", p)

			buf := make([]byte, 8192)

			n := runtime.Stack(buf, false)
			s.Log.Printf("[ERROR] [%s] Panic in request handler, operation %s: %s", request.SessionID, operationMap[item.Operation], string(buf[:n]))
		}
	}()

	handler := s.handlers[item.Operation]

	if handler == nil {
		s.Log.Printf("[WARN] [%s] Operation not supported: %s", request.SessionID, operationMap[item.Operation])
		err = wrapError(errors.New("operation not supported"), RESULT_REASON_OPERATION_NOT_SUPPORTED)
		return
	}

	resp, err = handler(request, item)
	return
}

func (s *Server) handleDiscoverVersions(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := DiscoverVersionsResponse{}

	request, ok := item.RequestPayload.(DiscoverVersionsRequest)
	if !ok {
		err = wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
		return
	}

	if len(request.ProtocolVersions) == 0 {
		// return all the versions
		response.ProtocolVersions = append([]ProtocolVersion(nil), s.SupportedVersions...)
	} else {
		// find matching versions
		for _, version := range request.ProtocolVersions {
			for _, v := range s.SupportedVersions {
				if version == v {
					response.ProtocolVersions = append(response.ProtocolVersions, v)
					break
				}
			}
		}
	}

	resp = response
	return
}

// TODO: add handling of dates and other attributes
func (s *Server) handleLocate(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := LocateResponse{}

	request, ok := item.RequestPayload.(LocateRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	s.Log.Printf("[DEBUG] Locate request attributes: %+v\n", request.Attributes)
	s.Log.Printf("[DEBUG] Locate request MaximumItems: %d, OffsetItems: %d\n", request.MaximumItems, request.OffsetItems)

	client := resty.New()

	apiResp, err := client.R().
		SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
		SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
		SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
		Post(fmt.Sprintf("%s/v1/kmip/spec/locate", s.InfisicalBaseAPIURL))

	if err != nil {
		s.Log.Printf("Error: %+v\n", err)
		return nil, infisicalErrors.NewRequestError("KmipLocateOperation", err)
	}

	if apiResp.IsError() {
		return nil, infisicalErrors.NewAPIErrorWithResponse("KmipLocateOperation", apiResp)
	}

	var result KmipLocateAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	supportedAttributes := []string{
		ATTRIBUTE_NAME_UNIQUE_IDENTIFIER,
		ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
		ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
		ATTRIBUTE_NAME_STATE,
		ATTRIBUTE_NAME_NAME,
		ATTRIBUTE_NAME_OBJECT_TYPE,
		ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
	}

	unsupportedAttributes := []string{}

	var matchingIds []string

	for _, object := range result.Objects {
		s.Log.Printf("[DEBUG] Processing object: ID=%s, Name=%s, Algorithm=%s, IsActive=%v", object.Id, object.Name, object.Algorithm, object.IsActive)

		var algorithm Enum
		var cryptographicLength int32

		if object.Algorithm == "aes-256-gcm" {
			algorithm = CRYPTO_AES
			cryptographicLength = 256
		} else if object.Algorithm == "aes-128-gcm" {
			algorithm = CRYPTO_AES
			cryptographicLength = 128
		}

		var state Enum
		if object.IsActive {
			state = STATE_ACTIVE
		} else {
			state = STATE_DEACTIVATED
		}

		shouldMatch := true
		for _, attribute := range request.Attributes {
			if !ContainsString(supportedAttributes, attribute.Name) {
				if !ContainsString(unsupportedAttributes, attribute.Name) {
					unsupportedAttributes = append(unsupportedAttributes, attribute.Name)
				}
				shouldMatch = false
				break
			}

			if attribute.Name == ATTRIBUTE_NAME_OBJECT_TYPE {
				if attribute.Value != OBJECT_TYPE_SYMMETRIC_KEY {
					shouldMatch = false
					break
				}
			}

			if attribute.Name == ATTRIBUTE_NAME_UNIQUE_IDENTIFIER {
				if attribute.Value != object.Id {
					shouldMatch = false
					break
				}
			}

			if attribute.Name == ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM {
				if attribute.Value != algorithm {
					shouldMatch = false
					break
				}
			}

			if attribute.Name == ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH {
				if attribute.Value != cryptographicLength {
					shouldMatch = false
					break
				}
			}

			if attribute.Name == ATTRIBUTE_NAME_STATE {
				if attribute.Value != state {
					shouldMatch = false
					break
				}
			}

			if attribute.Name == ATTRIBUTE_NAME_NAME {
				if nameValue, ok := attribute.Value.(Name); ok {
					slug.CustomSub = map[string]string{"_": "-"}
					slugifiedName := slug.Make(nameValue.Value)
					s.Log.Printf("[DEBUG] Name matching - Requested name: '%s', Slugified: '%s', Object name: '%s', Object ID: '%s'", nameValue.Value, slugifiedName, object.Name, object.Id)
					if slugifiedName != object.Name && nameValue.Value != object.Id {
						s.Log.Printf("[DEBUG] Name mismatch - continuing to next object")
						shouldMatch = false
						break
					}
				} else {
					return nil, wrapError(errors.New("name attribute is not of type Name"), RESULT_REASON_INVALID_FIELD)
				}
			}

			if attribute.Name == ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK {
				// intentionally left blank as we do not have cryptographic usage mask yet!
				continue
			}
		}

		s.Log.Printf("[DEBUG] Object %s (name: %s) - shouldMatch: %v", object.Id, object.Name, shouldMatch)
		if shouldMatch {
			matchingIds = append(matchingIds, object.Id)
		}
	}

	if len(unsupportedAttributes) > 0 {
		s.Log.Printf("Unsupported Attributes: %+v\n", unsupportedAttributes)
	}

	offset := 0
	maximum := len(matchingIds)

	if request.MaximumItems > 0 {
		maximum = int(request.MaximumItems)
		if maximum > len(matchingIds) {
			maximum = len(matchingIds)
		}
	}

	if request.OffsetItems > 0 {
		offset = int(request.OffsetItems)
		if offset > len(matchingIds) {
			offset = len(matchingIds)
		}
	}

	end := offset + maximum
	if end > len(matchingIds) {
		end = len(matchingIds)
	}

	if len(matchingIds) == 1 {
		req.IdPlaceholder = matchingIds[0]
	}

	// response.LocatedItems = int32(len(matchingIds))
	response.UniqueIdentifiers = append(response.UniqueIdentifiers, matchingIds[offset:end]...)

	s.Log.Printf("[DEBUG] Final results - Total matching IDs: %d, Returning IDs: %v", len(matchingIds), matchingIds[offset:end])

	return response, nil
}

func (s *Server) handleRegister(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := RegisterResponse{}

	request, ok := item.RequestPayload.(RegisterRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	var payload KmipRegisterAPIRequest
	var keyData []byte
	var algorithm string

	// Handle different object types
	switch request.ObjectType {
	case OBJECT_TYPE_SYMMETRIC_KEY:
		if request.SymmetricKey.KeyBlock.FormatType != KEY_FORMAT_RAW {
			return nil, wrapError(errors.New("unsupported key format"), RESULT_REASON_INVALID_FIELD)
		}

		if request.SymmetricKey.KeyBlock.CryptographicAlgorithm != CRYPTO_AES {
			return nil, wrapError(errors.New("unsupported algorithm"), RESULT_REASON_INVALID_FIELD)
		}

		if request.SymmetricKey.KeyBlock.CryptographicLength != 128 && request.SymmetricKey.KeyBlock.CryptographicLength != 256 {
			return nil, wrapError(errors.New("unsupported cryptographic length"), RESULT_REASON_INVALID_FIELD)
		}

		if request.SymmetricKey.KeyBlock.WrappingData.WrappingMethod != 0 {
			return nil, wrapError(errors.New("unsupported wrapping method"), RESULT_REASON_INVALID_FIELD)
		}

		keyData = request.SymmetricKey.KeyBlock.Value.KeyMaterial
		if request.SymmetricKey.KeyBlock.CryptographicLength == 128 {
			algorithm = "aes-128-gcm"
		} else {
			algorithm = "aes-256-gcm"
		}

	case OBJECT_TYPE_SECRET_DATA:
		keyData = request.SecretData.KeyBlock.Value.KeyMaterial

		if len(keyData) == 0 {
			return nil, wrapError(errors.New("secret data is empty"), RESULT_REASON_INVALID_FIELD)
		}

		dataLength := len(keyData) * 8 // Convert bytes to bits
		if dataLength == 128 {
			algorithm = "aes-128-gcm"
		} else if dataLength == 256 {
			algorithm = "aes-256-gcm"
		} else {
			algorithm = "aes-256-gcm"
		}

		if request.SecretData.KeyBlock.WrappingData.WrappingMethod != 0 {
			return nil, wrapError(errors.New("unsupported wrapping method for secret data"), RESULT_REASON_INVALID_FIELD)
		}

	case OBJECT_TYPE_TEMPLATE:
		// Template objects don't contain cryptographic material, they contain attributes
		// We'll handle Template objects separately without calling the register API
		// Generate a unique identifier for the template
		templateId := fmt.Sprintf("template-%d", time.Now().UnixNano())

		// For Template objects, we don't need to call the external API
		// Just return the template identifier
		response.UniqueIdentifier = templateId
		req.IdPlaceholder = templateId

		response.TemplateAttribute = request.TemplateAttribute

		return response, nil

	default:
		return nil, wrapError(errors.New("unsupported object type"), RESULT_REASON_INVALID_FIELD)
	}

	// Extract KMIP metadata for SecretData
	var kmipMetadata = KmipMetadata{}
	if request.ObjectType == OBJECT_TYPE_SECRET_DATA {
		kmipMetadata.SecretDataType = int(request.SecretData.SecretDataType)
		kmipMetadata.SecretDataFormatType = int(request.SecretData.KeyBlock.FormatType)
	}

	kmipMetadata.ObjectType = int(request.ObjectType)

	payload = KmipRegisterAPIRequest{
		Key:          base64.StdEncoding.EncodeToString(keyData),
		Algorithm:    algorithm,
		KmipMetadata: kmipMetadata,
	}

	for _, attribute := range request.TemplateAttribute.Attributes {
		if attribute.Name == ATTRIBUTE_NAME_NAME {
			if nameValue, ok := attribute.Value.(Name); ok {
				payload.Name = nameValue.Value
			} else {
				return nil, wrapError(errors.New("name attribute is not of type Name"), RESULT_REASON_INVALID_FIELD)
			}
		}
	}

	client := resty.New()

	apiResp, err := client.R().
		SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
		SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
		SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
		SetBody(payload).
		Post(fmt.Sprintf("%s/v1/kmip/spec/register", s.InfisicalBaseAPIURL))

	if err != nil {
		s.Log.Printf("Error: %+v\n", err)
		return nil, infisicalErrors.NewRequestError("KmipRegisterOperation", err)
	}

	if apiResp.IsError() {
		return nil, infisicalErrors.NewAPIErrorWithResponse("KmipRegisterOperation", apiResp)
	}

	var result KmipRegisterAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	req.IdPlaceholder = result.Id
	response.UniqueIdentifier = result.Id

	return response, nil
}

func (s *Server) handleActivate(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := ActivateResponse{}

	request, ok := item.RequestPayload.(ActivateRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	uniqueId := req.IdPlaceholder
	if request.UniqueIdentifier != "" {
		uniqueId = request.UniqueIdentifier
	}

	payload := KmipActivateAPIRequest{
		Id: uniqueId,
	}

	client := resty.New()

	apiResp, err := client.R().
		SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
		SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
		SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
		SetBody(payload).
		Post(fmt.Sprintf("%s/v1/kmip/spec/activate", s.InfisicalBaseAPIURL))

	if err != nil {
		s.Log.Printf("Error: %+v\n", err)
		return nil, infisicalErrors.NewRequestError("KmipActivateOperation", err)
	}

	if apiResp.IsError() {
		return nil, infisicalErrors.NewAPIErrorWithResponse("KmipActivateOperation", apiResp)
	}

	var result KmipActivateAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	if !result.IsActive {
		return nil, wrapError(errors.New("deactivated key cannot be enabled"), RESULT_REASON_ILLEGAL_OPERATION)
	}

	response.UniqueIdentifier = result.Id

	return response, nil
}

func (s *Server) handleRevoke(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := RevokeResponse{}

	request, ok := item.RequestPayload.(RevokeRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	uniqueId := req.IdPlaceholder
	if request.UniqueIdentifier != "" {
		uniqueId = request.UniqueIdentifier
	}

	payload := KmipRevokeAPIRequest{
		Id: uniqueId,
	}

	client := resty.New()

	apiResp, err := client.R().
		SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
		SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
		SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
		SetBody(payload).
		Post(fmt.Sprintf("%s/v1/kmip/spec/revoke", s.InfisicalBaseAPIURL))

	if err != nil {
		s.Log.Printf("Error: %+v\n", err)
		return nil, infisicalErrors.NewRequestError("KmipRevokeOperation", err)
	}

	if apiResp.IsError() {
		return nil, infisicalErrors.NewAPIErrorWithResponse("KmipRevokeOperation", apiResp)
	}

	var result KmipRevokeAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	response.UniqueIdentifier = result.Id

	return response, nil
}

/* We currently only support getting symmetric keys */
// TODO: add support for key wrapping
func (s *Server) handleGet(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := GetResponse{}

	request, ok := item.RequestPayload.(GetRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	uniqueId := req.IdPlaceholder
	if request.UniqueIdentifier != "" {
		uniqueId = request.UniqueIdentifier
	}

	// Check if this is a Template object (starts with "template-")
	if len(uniqueId) > 9 && uniqueId[:9] == "template-" {
		// Handle Template objects without calling external API
		response.ObjectType = OBJECT_TYPE_TEMPLATE
		response.UniqueIdentifier = uniqueId
		// Template objects don't have cryptographic material, just attributes
		// You might store/retrieve template attributes here
		return response, nil
	}

	if request.KeyCompressionType != 0 {
		return nil, wrapError(errors.New("key compression is not supported"), RESULT_REASON_INVALID_FIELD)
	}

	payload := KmipGetAPIRequest{
		Id: uniqueId,
	}

	client := resty.New()

	apiResp, err := client.R().
		SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
		SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
		SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(fmt.Sprintf("%s/v1/kmip/spec/get", s.InfisicalBaseAPIURL))

	if err != nil {
		s.Log.Printf("Error: %+v\n", err)
		return nil, infisicalErrors.NewRequestError("KmipGetOperation", err)
	}

	if apiResp.IsError() {
		return nil, infisicalErrors.NewAPIErrorWithResponse("KmipGetOperation", apiResp)
	}

	var result KmipGetAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	response.UniqueIdentifier = result.Id

	decodedValue, err := base64.StdEncoding.DecodeString(result.Value)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64 value")
	}

	// Use stored metadata from API response
	if result.KmipMetadata.SecretDataType != 0 {
		// This is a SecretData object
		response.ObjectType = OBJECT_TYPE_SECRET_DATA
		response.SecretData.KeyBlock.Value.KeyMaterial = []byte(decodedValue)
		response.SecretData.KeyBlock.FormatType = Enum(result.KmipMetadata.SecretDataFormatType)
		response.SecretData.SecretDataType = Enum(result.KmipMetadata.SecretDataType)
	} else {
		// This is a SymmetricKey object (default behavior)
		response.ObjectType = OBJECT_TYPE_SYMMETRIC_KEY
		response.SymmetricKey.KeyBlock.Value.KeyMaterial = []byte(decodedValue)
		response.SymmetricKey.KeyBlock.FormatType = KEY_FORMAT_RAW

		// Set cryptographic parameters for SymmetricKey objects
		if result.Algorithm == "aes-256-gcm" {
			response.SymmetricKey.KeyBlock.CryptographicAlgorithm = CRYPTO_AES
			response.SymmetricKey.KeyBlock.CryptographicLength = 256
		} else if result.Algorithm == "aes-128-gcm" {
			response.SymmetricKey.KeyBlock.CryptographicAlgorithm = CRYPTO_AES
			response.SymmetricKey.KeyBlock.CryptographicLength = 128
		} else {
			return nil, errors.New("unsupported algorithm")
		}
	}

	// Key wrapping is only supported for SymmetricKey objects
	if request.KeyWrappingSpec.WrappingMethod != 0 && response.ObjectType == OBJECT_TYPE_SYMMETRIC_KEY {
		if request.KeyWrappingSpec.WrappingMethod != WRAPPING_METHOD_ENCRYPT {
			return nil, wrapError(errors.New("selected key wrapping method is not supported"), RESULT_REASON_INVALID_FIELD)
		}
		if request.KeyWrappingSpec.EncryptionKeyInformation.CryptoParams.BlockCipherMode != BLOCK_MODE_NISTKeyWrap {
			return nil, wrapError(errors.New("selected block cipher mode is not supported"), RESULT_REASON_INVALID_FIELD)
		}
		if request.KeyWrappingSpec.EncodingOption != ENCODING_OPTION_NO_ENCODING {
			return nil, wrapError(errors.New("encoding option is not supported"), RESULT_REASON_INVALID_FIELD)
		}

		payload := KmipGetAPIRequest{
			Id: request.KeyWrappingSpec.EncryptionKeyInformation.UniqueIdentifier,
		}

		client := resty.New()

		keyWrapperApiResp, err := client.R().
			SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
			SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
			SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
			SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
			SetHeader("Content-Type", "application/json").
			SetBody(payload).
			Post(fmt.Sprintf("%s/v1/kmip/spec/get", s.InfisicalBaseAPIURL))

		if err != nil {
			s.Log.Printf("Error: %+v\n", err)
			return nil, infisicalErrors.NewRequestError("KmipGetOperation", err)
		}

		if apiResp.IsError() {
			return nil, infisicalErrors.NewAPIErrorWithResponse("KmipGetOperation", apiResp)
		}

		var keyWrapperResult KmipGetAPIResponse
		if err := json.Unmarshal(keyWrapperApiResp.Body(), &keyWrapperResult); err != nil {
			return nil, errors.Wrap(err, "failed to decode response")
		}

		decodedKeyWrapper, err := base64.StdEncoding.DecodeString(keyWrapperResult.Value)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode base64 value")
		}

		wrappedKey, err := AesWrap([]byte(decodedKeyWrapper), []byte(decodedValue))
		if err != nil {
			return nil, errors.Wrap(err, "failed to wrap key")
		}

		response.SymmetricKey.KeyBlock.Value.KeyMaterial = wrappedKey
		response.SymmetricKey.KeyBlock.WrappingData = KeyWrappingData{
			WrappingMethod: WRAPPING_METHOD_ENCRYPT,
			EncryptionKeyInformation: EncryptionKeyInformation{
				UniqueIdentifier: request.KeyWrappingSpec.EncryptionKeyInformation.UniqueIdentifier,
				CryptoParams: CryptoParams{
					BlockCipherMode: BLOCK_MODE_NISTKeyWrap,
				},
			},
		}
	}

	return response, nil
}

func (s *Server) handleDestroy(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := DestroyResponse{}

	request, ok := item.RequestPayload.(DestroyRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	uniqueId := req.IdPlaceholder
	if request.UniqueIdentifier != "" {
		uniqueId = request.UniqueIdentifier
	}

	payload := KmipDestroyAPIRequest{
		Id: uniqueId,
	}

	client := resty.New()

	apiResp, err := client.R().
		SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
		SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
		SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(fmt.Sprintf("%s/v1/kmip/spec/destroy", s.InfisicalBaseAPIURL))

	if err != nil {
		s.Log.Printf("Error: %+v\n", err)
		return nil, infisicalErrors.NewRequestError("KmipDestroyOperation", err)
	}

	if apiResp.IsError() {
		return nil, infisicalErrors.NewAPIErrorWithResponse("KmipDestroyOperation", apiResp)
	}

	var result KmipDestroyAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	response.UniqueIdentifier = result.Id
	return response, nil
}

/*
TODO: missing the following required attributes in KMIP 1.4:
- digest
- sensitive
- always sensitive
- extractable
- never extractable
*/
func (s *Server) handleGetAttributes(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := GetAttributesResponse{}

	request, ok := item.RequestPayload.(GetAttributesRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	uniqueId := req.IdPlaceholder
	if request.UniqueIdentifier != "" {
		uniqueId = request.UniqueIdentifier
	}

	payload := KmipGetAttributeAPIRequest{
		Id: uniqueId,
	}

	client := resty.New()

	apiResp, err := client.R().
		SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
		SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
		SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(fmt.Sprintf("%s/v1/kmip/spec/get-attributes", s.InfisicalBaseAPIURL))

	if err != nil {
		s.Log.Printf("Error: %+v\n", err)
		return nil, infisicalErrors.NewRequestError("KmipGetAttributesOperation", err)
	}

	if apiResp.IsError() {
		return nil, infisicalErrors.NewAPIErrorWithResponse("KmipGetAttributesOperation", apiResp)
	}

	var result KmipGetAttributeAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	response.UniqueIdentifier = result.Id

	var cryptographicLength int32
	if result.Algorithm == "aes-256-gcm" {
		cryptographicLength = 256
	} else if result.Algorithm == "aes-128-gcm" {
		cryptographicLength = 128
	} else {
		return nil, errors.New("unsupported algorithm")
	}

	var stateValue Enum
	if result.IsActive {
		stateValue = STATE_ACTIVE
	} else {
		stateValue = STATE_DEACTIVATED
	}

	response.UniqueIdentifier = result.Id
	attributes := []Attribute{
		{
			Name:  ATTRIBUTE_NAME_UNIQUE_IDENTIFIER,
			Value: result.Id,
		},
		{
			Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
			Value: CRYPTO_AES,
		},
		{
			Name:  ATTRIBUTE_NAME_OBJECT_TYPE,
			Value: OBJECT_TYPE_SYMMETRIC_KEY,
		},
		{
			Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
			Value: cryptographicLength,
		},
		{
			Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
			Value: int32(CRYPTO_USAGE_MASK_ENCRYPT | CRYPTO_USAGE_MASK_DECRYPT | CRYPTO_USAGE_MASK_WRAP_KEY | CRYPTO_USAGE_MASK_UNWRAP_KEY | CRYPTO_USAGE_MASK_MAC_GENERATE | CRYPTO_USAGE_MASK_MAC_VERIFY),
		},
		{
			Name:  ATTRIBUTE_NAME_STATE,
			Value: stateValue,
		},
		{
			Name:  ATTRIBUTE_NAME_INITIAL_DATE,
			Value: result.CreatedAt,
		},
		{
			Name:  ATTRIBUTE_NAME_ACTIVATION_DATE,
			Value: result.CreatedAt,
		},
		{
			Name:  ATTRIBUTE_NAME_LAST_CHANGE_DATE,
			Value: result.UpdatedAt,
		},
	}

	if len(request.AttributeNames) == 0 {
		response.Attributes = attributes
	} else {
		for _, requestedAttribute := range request.AttributeNames {
			for _, attribute := range attributes {
				if requestedAttribute == attribute.Name {
					response.Attributes = append(response.Attributes, attribute)
				}
			}
		}
	}

	if len(response.Attributes) == 0 {
		response.Attributes = []Attribute{
			{
				Name:  ATTRIBUTE_NAME_UNIQUE_IDENTIFIER,
				Value: result.Id,
			},
		}
	}

	return response, nil
}

// Based on the 1.4 spec, this is missing RNG Parameters, Profile Information, and Attestation Types
func (s *Server) handleQuery(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := QueryResponse{}

	request, ok := item.RequestPayload.(QueryRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	if ContainsEnum(request.QueryFunctions, QUERY_OPERATIONS) {
		response.Operations = []Enum{
			OPERATION_CREATE,
			OPERATION_REGISTER,
			OPERATION_LOCATE,
			OPERATION_GET,
			OPERATION_GET_ATTRIBUTES,
			OPERATION_ACTIVATE,
			OPERATION_REVOKE,
			OPERATION_DESTROY,
			OPERATION_QUERY,
			OPERATION_DISCOVER_VERSIONS,
		}
	}

	if ContainsEnum(request.QueryFunctions, QUERY_OBJECTS) {
		response.ObjectTypes = []Enum{
			OBJECT_TYPE_SYMMETRIC_KEY,
			OBJECT_TYPE_SECRET_DATA,
			OBJECT_TYPE_TEMPLATE,
		}
	}

	if ContainsEnum(request.QueryFunctions, QUERY_SERVER_INFORMATION) {
		response.VendorIdentification = "Infisical KMIP Server"
	}

	if ContainsEnum(request.QueryFunctions, QUERY_PROFILES) {
		response.ProfileInformation = []ProfileInformation{
			{
				ProfileName: PROFILE_NAME_BASELINE_SERVER_BASIC_KMIP_V1_2,
			},
			{
				ProfileName: PROFILE_NAME_BASELINE_SERVER_TLS_V1_2_KMIP_V1_2,
			},
			{
				ProfileName: PROFILE_NAME_STORAGE_ARRAY_SELF_ENCRYPTING_DRIVE_SERVER_KMIP_V1_0,
			},
			{
				ProfileName: PROFILE_NAME_STORAGE_ARRAY_SELF_ENCRYPTING_DRIVE_SERVER_KMIP_V1_1,
			},
			{
				ProfileName: PROFILE_NAME_STORAGE_ARRAY_SELF_ENCRYPTING_DRIVE_SERVER_KMIP_V1_2,
			},
			{
				ProfileName: PROFILE_NAME_BASELINE_SERVER_BASIC_KMIP_V1_3,
			},
		}
	}

	return response, nil
}

/* We currently only support creating symmetric keys */
func (s *Server) handleCreate(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error) {
	response := CreateResponse{}

	request, ok := item.RequestPayload.(CreateRequest)
	if !ok {
		return nil, wrapError(errors.New("wrong request body"), RESULT_REASON_INVALID_MESSAGE)
	}

	if request.ObjectType != OBJECT_TYPE_SYMMETRIC_KEY {
		return nil, wrapError(errors.New(fmt.Sprintf("cannot create object type %v with the Create operation", request.ObjectType)),
			RESULT_REASON_INVALID_FIELD)
	}

	cryptoAlgorithm := request.TemplateAttribute.Attributes.Get(ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM)
	if cryptoAlgorithm == nil {
		return nil, wrapError(errors.New("cryptographic algorithm is required"), RESULT_REASON_INVALID_FIELD)
	}

	if cryptoAlgorithm != CRYPTO_AES {
		return nil, wrapError(errors.New("only AES is supported"), RESULT_REASON_INVALID_FIELD)
	}

	algorithm := "aes-256-gcm"
	length := request.TemplateAttribute.Attributes.Get(ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH)
	if length != nil {
		if lengthValue, ok := length.(int32); ok {
			algorithm = fmt.Sprintf("aes-%d-gcm", lengthValue)
		} else {
			return nil, wrapError(errors.New("invalid cryptographic length type"), RESULT_REASON_INVALID_FIELD)
		}
	}

	payload := KmipCreateAPIRequest{
		Algorithm: algorithm,
	}

	client := resty.New()

	apiResp, err := client.R().
		SetHeader("X-Kmip-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("X-Kmip-Client-Certificate-Serial-Number", req.SessionAuth.ClientCertificateSerialNumber).
		SetHeader("X-Kmip-Project-Id", req.SessionAuth.ProjectId).
		SetHeader("X-Kmip-Client-Id", req.SessionAuth.ClientId).
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.InfisicalAuth.GetAccessToken())).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(fmt.Sprintf("%s/v1/kmip/spec/create", s.InfisicalBaseAPIURL))

	if err != nil {
		s.Log.Printf("Error: %+v\n", err)
		return nil, infisicalErrors.NewRequestError("KmipCreateOperation", err)
	}

	if apiResp.IsError() {
		return nil, infisicalErrors.NewAPIErrorWithResponse("KmipCreateOperation", apiResp)
	}

	var result KmipCreateAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	response.ObjectType = OBJECT_TYPE_SYMMETRIC_KEY
	response.UniqueIdentifier = result.Id
	req.IdPlaceholder = result.Id

	return response, nil
}

// DefaultSupportedVersions is a default list of supported KMIP versions
var DefaultSupportedVersions = []ProtocolVersion{
	{Major: 1, Minor: 4},
	{Major: 1, Minor: 3},
	{Major: 1, Minor: 2},
	{Major: 1, Minor: 1},
	{Major: 1, Minor: 0},
}
