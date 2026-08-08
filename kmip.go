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
	stderrors "errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	infisical "github.com/infisical/go-sdk"
	infisicalErrors "github.com/infisical/go-sdk/packages/errors"
	"github.com/pkg/errors"
)

const (
	// Certificates are renewed once 2/3 of their lifetime has elapsed, leaving a third of the
	// validity window to retry through transient failures before the old certificate expires.
	renewAtLifetimeFraction = 2.0 / 3.0

	renewRetryInitialBackoff = 30 * time.Second
	renewRetryMaxBackoff     = 15 * time.Minute

	// minRenewInterval floors the wait between renewals so a certificate whose renewal
	// point is already in the past (tiny TTL, clock skew) cannot trigger a tight loop
	// of back-to-back issuance requests.
	minRenewInterval = time.Minute

	// fetchTimeout bounds the certificate fetch; without it a hung API call would stall
	// the renewal loop indefinitely while the served certificate quietly expires.
	fetchTimeout = 60 * time.Second
)

// certState is an immutable snapshot of the server's certificate material. It is swapped
// atomically on renewal so in-flight connections and handlers never see a partial update.
type certState struct {
	tlsCert      tls.Certificate
	serverCert   *x509.Certificate
	serialNumber string
	clientCAPool *x509.CertPool
}

// authError marks an Infisical API failure caused by a rejected access token (401/403),
// so the renewal loop can attempt a token refresh instead of blind retries.
type authError struct {
	err error
}

func (e *authError) Error() string { return e.err.Error() }
func (e *authError) Unwrap() error { return e.err }

type KmipServer struct {
	server Server

	listenCh chan error
}

func (s *KmipServer) fetchCertificates() (*certState, error) {
	client := resty.New().SetTimeout(fetchTimeout)

	req := client.R().
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", s.server.getAccessToken()))

	var apiResp *resty.Response
	var err error
	var op string

	if s.server.isEnrollmentBased() {
		// Enrollment-based server: the cert config (SANs, TTL, common name, key algorithm) lives
		// on the server entity, so /connect takes no body, the access token identifies the server.
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
		return nil, infisicalErrors.NewRequestError(op, err)
	}

	if apiResp.IsError() {
		apiErr := infisicalErrors.NewAPIErrorWithResponse(op, apiResp)
		if apiResp.StatusCode() == http.StatusUnauthorized || apiResp.StatusCode() == http.StatusForbidden {
			return nil, &authError{err: apiErr}
		}
		return nil, apiErr
	}

	var result KmipServerRegistrationAPIResponse
	if err := json.Unmarshal(apiResp.Body(), &result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	block, _ := pem.Decode([]byte(result.PrivateKey))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing server private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing server private key")
	}

	var signer crypto.Signer
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		signer = k
	case *rsa.PrivateKey:
		signer = k
	default:
		return nil, errors.New("server private key is not of a supported type (ECDSA or RSA)")
	}

	block, _ = pem.Decode([]byte(result.Certificate))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing server certificate")
	}

	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing server cert")
	}

	// A mismatched key/cert pair would replace a working certificate with one that fails
	// every handshake; reject it so the previous snapshot keeps being served.
	pub, ok := serverCert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return nil, errors.New("server private key does not match the server certificate")
	}

	clientCAPool := x509.NewCertPool()
	clientChainPemBytes := []byte(result.ClientCertificateChain)
	for {
		block, rest := pem.Decode(clientChainPemBytes)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing certificate in client chain")
		}

		clientCAPool.AddCert(cert)
		clientChainPemBytes = rest
	}

	// Build the served certificate chain, excluding root certificates
	certChain := [][]byte{serverCert.Raw}
	if result.CertificateChain != "" {
		chainPemBytes := []byte(result.CertificateChain)
		for {
			block, rest := pem.Decode(chainPemBytes)
			if block == nil {
				break
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				s.server.Log.Printf("Warning: error parsing certificate in server chain: %v", err)
				break
			}

			if cert.Issuer.String() != cert.Subject.String() {
				certChain = append(certChain, cert.Raw)
			}

			chainPemBytes = rest
		}
	}

	return &certState{
		tlsCert: tls.Certificate{
			Certificate: certChain,
			PrivateKey:  key,
		},
		serverCert:   serverCert,
		serialNumber: serverCert.SerialNumber.Text(16),
		clientCAPool: clientCAPool,
	}, nil
}

func (s *KmipServer) loadCertificates() error {
	state, err := s.fetchCertificates()
	if err != nil {
		return err
	}

	s.server.certState.Store(state)
	log.Println("Certificates loaded successfully")
	return nil
}

// renewalTime returns when the certificate should be renewed: 2/3 into its lifetime,
// with a small jitter so a fleet of servers doesn't renew in lockstep.
func renewalTime(cert *x509.Certificate) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	renewAt := cert.NotBefore.Add(time.Duration(float64(lifetime) * renewAtLifetimeFraction))
	jitter := time.Duration((rand.Float64() - 0.5) * 0.04 * float64(lifetime))
	return renewAt.Add(jitter)
}

// certRenewalLoop renews the server certificate in the background for the lifetime of
// the server, so new certificates are picked up without a restart.
func (s *KmipServer) certRenewalLoop() {
	done := s.server.getDoneChan()

	for {
		state := s.server.certState.Load()
		if state == nil {
			return
		}

		wait := time.Until(renewalTime(state.serverCert))
		if wait < minRenewInterval {
			wait = minRenewInterval
		}

		s.server.Log.Printf("[INFO] Next certificate renewal scheduled in %s (certificate expires %s)",
			wait.Round(time.Second), state.serverCert.NotAfter.Format(time.RFC3339))

		timer := time.NewTimer(wait)
		select {
		case <-done:
			timer.Stop()
			return
		case <-timer.C:
		}

		if !s.renewCertificates(done, state) {
			return
		}
	}
}

// renewCertificates attempts renewal with backoff until it succeeds. The old certificate keeps
// being served throughout; a failing renewal must never take down a working server. Returns
// false only when the server is shutting down.
func (s *KmipServer) renewCertificates(done chan struct{}, oldState *certState) bool {
	backoff := renewRetryInitialBackoff

	for {
		err := s.loadCertificates()
		if err == nil {
			newState := s.server.certState.Load()
			s.server.Log.Printf("[INFO] Server certificate renewed (serial %s, expires %s)",
				newState.serialNumber, newState.serverCert.NotAfter.Format(time.RFC3339))
			return true
		}

		retriedWithFreshToken := false
		var aErr *authError
		if stderrors.As(err, &aErr) {
			if s.server.RefreshAccessToken != nil {
				newToken, refreshErr := s.server.RefreshAccessToken()
				if refreshErr == nil {
					s.server.setAccessToken(newToken)
					s.server.Log.Printf("[INFO] Access token refreshed, retrying certificate renewal")
					retriedWithFreshToken = true
				} else {
					s.server.Log.Printf("[ERROR] Certificate renewal failed with an auth error and refreshing the access token also failed: %s", refreshErr)
				}
			} else if s.server.isEnrollmentBased() {
				s.server.Log.Printf("[ERROR] Certificate renewal was rejected because the access token is invalid or expired, and no refresh mechanism is available. Re-enroll this server (restart it with a new enrollment token) before the current certificate expires.")
			} else {
				s.server.Log.Printf("[ERROR] Certificate renewal was rejected because authentication failed. Verify the machine identity credentials this server was started with before the current certificate expires.")
			}
		}

		if retriedWithFreshToken {
			// One immediate retry with the fresh token; if that also fails we fall back to backoff.
			if err := s.loadCertificates(); err == nil {
				newState := s.server.certState.Load()
				s.server.Log.Printf("[INFO] Server certificate renewed (serial %s, expires %s)",
					newState.serialNumber, newState.serverCert.NotAfter.Format(time.RFC3339))
				return true
			}
		}

		remaining := time.Until(oldState.serverCert.NotAfter)
		sleep := backoff
		if remaining > 0 && sleep > remaining/4 {
			sleep = remaining / 4
			if sleep < 10*time.Second {
				sleep = 10 * time.Second
			}
		}
		// Once the certificate has expired, clients can't connect anyway, so back off no
		// further than a minute to recover as soon as the platform is reachable again.
		if remaining <= 0 && sleep > time.Minute {
			sleep = time.Minute
		}

		switch {
		case remaining < 0:
			s.server.Log.Printf("[ERROR] Certificate renewal failed and the server certificate has EXPIRED, clients cannot connect. Retrying in %s: %s", sleep.Round(time.Second), err)
		case remaining < 24*time.Hour:
			s.server.Log.Printf("[ERROR] Certificate renewal failed, certificate expires in %s. Retrying in %s: %s", remaining.Round(time.Second), sleep.Round(time.Second), err)
		default:
			s.server.Log.Printf("[WARN] Certificate renewal failed, retrying in %s: %s", sleep.Round(time.Second), err)
		}

		select {
		case <-done:
			return false
		case <-time.After(sleep):
		}

		backoff *= 2
		if backoff > renewRetryMaxBackoff {
			backoff = renewRetryMaxBackoff
		}
	}
}

type ServerConfig struct {
	Addr                 string
	InfisicalBaseAPIURL  string
	IdentityClientId     string
	IdentityClientSecret string

	// AccessToken is an enrollment-based KMIP server access token. When set, it is used
	// directly for Infisical API calls and the machine-identity login is skipped.
	AccessToken string

	// RefreshAccessToken, when set, is called if certificate renewal fails because the
	// access token was rejected. It should return a fresh access token (e.g. by re-running
	// AWS auth). Not needed for the legacy machine-identity path, which auto-refreshes.
	RefreshAccessToken func() (string, error)

	ServerName     string
	CertificateTTL string
	HostnamesOrIps string
}

func StartServer(config ServerConfig) {
	kmip := &KmipServer{}

	var err error

	// Enrollment-based servers (AccessToken set) read their cert config from the platform at
	// /connect, so hostnames/IPs and TTL aren't supplied here, only the legacy machine-identity
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
	kmip.server.RefreshAccessToken = config.RefreshAccessToken

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

	// Certificate material is resolved per handshake so renewals apply to new connections
	// without a restart; established sessions keep the certificate they handshook with.
	kmip.server.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			state := kmip.server.certState.Load()
			if state == nil {
				return nil, errors.New("no server certificate loaded")
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{state.tlsCert},
				ClientCAs:    state.clientCAPool,
			}, nil
		},
	}

	kmip.server.ReadTimeout = time.Second * 10
	kmip.server.WriteTimeout = time.Second * 10

	go kmip.certRenewalLoop()

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
