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
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
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

	l        net.Listener
	mu       sync.Mutex
	wg       sync.WaitGroup
	doneChan chan struct{}
	handlers map[Enum]Handler
}

// Handler processes specific KMIP operation
type Handler func(req *RequestContext, item *RequestBatchItem) (resp interface{}, err error)

type SessionAuth struct {
	ClientJwt                     string
	ClientCertificateSerialNumber string
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
		addr = ":5696"
	}

	l, err := tls.Listen("tcp", addr, s.TLSConfig)
	fmt.Printf("Listening on %s\n", addr)

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
// operation should be specifically enabled via Handle
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
			Version:                req.Header.Version,
			TimeStamp:              time.Now(),
			ClientCorrelationValue: req.Header.ClientCorrelationValue,
			BatchCount:             req.Header.BatchCount,
		},
		BatchItems: make([]ResponseBatchItem, req.Header.BatchCount),
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
			// TODO: should we skip returning error message? or return it only for specific errors?
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

	if request.KeyCompressionType != 0 {
		return nil, wrapError(errors.New("key compression is not supported"), RESULT_REASON_INVALID_FIELD)
	}

	payload := KmipGetAPIRequest{
		Id: uniqueId,
	}

	client := resty.New()

	// Send the request using resty
	apiResp, err := client.R().
		SetHeader("X-Kmip-Jwt", req.SessionAuth.ClientJwt).
		SetHeader("X-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(fmt.Sprintf("%s/api/v1/kmip-operations/get", s.InfisicalBaseAPIURL))

	if err != nil {
		fmt.Printf("Error: %+v\n", err)
		return nil, errors.Wrap(err, "failed to make POST request")
	}

	if apiResp.StatusCode() != http.StatusOK {
		return nil, errors.Errorf("unexpected status code: %d", apiResp.StatusCode())
	}

	var result KmipGetAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	response.ObjectType = OBJECT_TYPE_SYMMETRIC_KEY
	response.UniqueIdentifier = result.Id

	decodedValue, err := base64.StdEncoding.DecodeString(result.Value)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64 value")
	}
	response.SymmetricKey.KeyBlock.Value.KeyMaterial = []byte(decodedValue)
	response.SymmetricKey.KeyBlock.FormatType = KEY_FORMAT_RAW

	if result.Algorithm == "aes-256-gcm" {
		response.SymmetricKey.KeyBlock.CryptographicAlgorithm = CRYPTO_AES
		response.SymmetricKey.KeyBlock.CryptographicLength = 256
	} else if result.Algorithm == "aes-128-gcm" {
		response.SymmetricKey.KeyBlock.CryptographicAlgorithm = CRYPTO_AES
		response.SymmetricKey.KeyBlock.CryptographicLength = 128
	} else {
		return nil, errors.New("unsupported algorithm")
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

	// Send the request using resty
	apiResp, err := client.R().
		SetHeader("X-Kmip-Jwt", req.SessionAuth.ClientJwt).
		SetHeader("X-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(fmt.Sprintf("%s/api/v1/kmip-operations/delete", s.InfisicalBaseAPIURL))

	if err != nil {
		fmt.Printf("Error: %+v\n", err)
		return nil, errors.Wrap(err, "failed to make POST request")
	}

	if apiResp.StatusCode() != http.StatusOK {
		return nil, errors.Errorf("unexpected status code: %d", apiResp.StatusCode())
	}

	var result KmipDestroyAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	response.UniqueIdentifier = result.Id
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
		SetHeader("X-Kmip-Jwt", req.SessionAuth.ClientJwt).
		SetHeader("X-Server-Certificate-Serial-Number", s.CertificateSerialNumber).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(fmt.Sprintf("%s/api/v1/kmip-operations/create", s.InfisicalBaseAPIURL))

	if err != nil {
		fmt.Printf("Error: %+v\n", err)
		return nil, errors.Wrap(err, "failed to make POST request")
	}

	if apiResp.StatusCode() != http.StatusOK {
		return nil, errors.Errorf("unexpected status code: %d", apiResp.StatusCode())
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
}
