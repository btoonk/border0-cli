package border0

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/api"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/cenkalti/backoff/v4"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	defaultTunnelHost = "tunnel.border0.com"
	defaultTunnelPort = 22
	defaultSSHTimeout = 5 * time.Second
	tunnelHostEnvVar  = "BORDER0_TUNNEL"
	// tunnelHostKey                         = "AAAAC3NzaC1lZDI1NTE5AAAAIIyCjIut7ZxhiFj5HEnY8GQP2vSI9DJDcnUzVyUipCgP"
	connectorAuthenticationHeader         = "BORDER0-CLIENT-CONNECTOR-AUTHENTICATED"
	connectorAuthenticationShutdownTime   = 200 * time.Millisecond
	connectorAuthenticationCertificateOrg = "Border0 Connector"
	connectorAuthenticationCertificateTTL = 24 * 365 * 10 * time.Hour
	proxyHostRegex                        = "^http(s)?://"
)

type Socket struct {
	SocketID                         string
	SocketType                       string
	UpstreamType                     string
	ConnectorAuthenticationEnabled   bool
	ConnectorAuthenticationTLSConfig *tls.Config
	border0API                       api.API
	keyPair                          sshKeyPair
	sshSigner                        ssh.Signer
	tunnelHost                       string
	errChan                          chan error
	readyChan                        chan bool
	stopChan                         chan bool
	listener                         net.Listener
	Organization                     *models.Organization
	proxyHost                        *url.URL
	closed                           bool
	version                          string
}

type sshKeyPair struct {
	privateKey []byte
	publicKey  []byte
}

func NewSocket(ctx context.Context, border0API api.API, nameOrID string) (*Socket, error) {
	socketFromApi, err := border0API.GetSocket(ctx, nameOrID)
	if err != nil {
		return nil, err
	}

	org, err := border0API.GetOrganizationInfo(ctx)
	if err != nil {
		return nil, err
	}

	return &Socket{
		SocketID:                       socketFromApi.SocketID,
		SocketType:                     socketFromApi.SocketType,
		UpstreamType:                   socketFromApi.UpstreamType,
		ConnectorAuthenticationEnabled: socketFromApi.ConnectorAuthenticationEnabled,
		border0API:                     border0API,
		tunnelHost:                     getTunnelHost(),
		errChan:                        make(chan error),
		readyChan:                      make(chan bool),
		stopChan:                       make(chan bool, 1),
		Organization:                   org,
	}, nil
}

func (s *Socket) WithVersion(version string) {
	s.version = version
}

func (s *Socket) WithProxy(proxyHost string) error {
	proxyMatch, err := regexp.Compile(proxyHostRegex)
	if err != nil {
		return fmt.Errorf("failed to compile proxy regex: %s", err)
	}

	if !proxyMatch.MatchString(proxyHost) {
		return fmt.Errorf("invalid proxy URL: %s", proxyHost)
	}

	proxyURL, err := url.Parse(proxyHost)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %s", err)
	}

	s.proxyHost = proxyURL
	return nil
}

func (s *Socket) Listen() (net.Listener, error) {

	s.border0API.StartRefreshAccessTokenJob(context.Background())

	if s.ConnectorAuthenticationEnabled {
		tlsConfig, err := s.generateConnectorAuthenticationTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to generate connector authentication TLS config: %v", err)
		}

		s.ConnectorAuthenticationTLSConfig = tlsConfig
	}

	go s.tunnelConnect()

	select {
	case err := <-s.errChan:
		return nil, err
	case <-s.readyChan:
	}

	go func() {
		for err := range s.errChan {
			log.Printf("border0 listener: %v", err)
		}
	}()

	return s, nil
}

func (s *Socket) tunnelConnect() {
	defer close(s.errChan)
	if err := s.generateSSHKeyPair(); err != nil {
		s.errChan <- err
		return
	}

	userID, err := s.border0API.GetUserID()
	if err != nil {
		s.errChan <- fmt.Errorf("failed to get userid from token: %v", err)
		return
	}

	// keyBytes, err := base64.StdEncoding.DecodeString(tunnelHostKey)
	// if err != nil {
	// 	s.errChan <- fmt.Errorf("failed to decode hostkey %v", err)
	// 	return
	// }

	// hostKey, err := ssh.ParsePublicKey(keyBytes)
	// if err != nil {
	// 	s.errChan <- fmt.Errorf("failed to parse hostkey %v", err)
	// 	return
	// }

	sshConfig := &ssh.ClientConfig{
		User: userID,
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultSSHTimeout,
		ClientVersion:   "SSH-2.0-Border0-" + s.version,
	}

	ebackoff := backoff.NewExponentialBackOff()
	ebackoff.MaxElapsedTime = 0
	ebackoff.MaxInterval = 5 * time.Minute

	err = backoff.Retry(func() error {
		if err := s.refreshSSHCert(); err != nil {
			fmt.Printf("failed to get ssh cert, retrying (%s)...\n", err)
			return err
		}

		sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(s.sshSigner)}

		if err = s.sshConnect(sshConfig, ebackoff); err != nil {
			fmt.Printf("failed to connect to server, retrying (%s)...\n", err)
			return err
		}

		return nil
	}, ebackoff)

	if err != nil {
		s.errChan <- fmt.Errorf("failed to connect to server: %s", err)
		return
	}
}

func (s *Socket) sshConnect(config *ssh.ClientConfig, b backoff.BackOff) error {
	if s.closed {
		return backoff.Permanent(fmt.Errorf("socket is closed"))
	}

	var dialer proxy.Dialer
	var err error

	if s.proxyHost != nil {
		proxy.RegisterDialerType("http", newHttpProxy)
		proxy.RegisterDialerType("https", newHttpProxy)

		dialer, err = proxy.FromURL(s.proxyHost, proxy.Direct)
		if err != nil {
			return fmt.Errorf("failed to create proxy dialer: %v", err)
		}
	} else {
		dialer = proxy.Direct
	}

	conn, err := dialer.Dial("tcp", s.tunnelHost)
	if err != nil {
		return fmt.Errorf("failed to connect to tunnel service: %s", err)
	}
	defer conn.Close()

	sshCon, channel, req, err := ssh.NewClientConn(conn, s.tunnelHost, config)
	if err != nil {
		return fmt.Errorf("failed to setup connection to tunnel service: %s", err)
	}
	defer sshCon.Close()

	client := ssh.NewClient(sshCon, channel, req)
	defer client.Close()

	done := make(chan bool, 1)
	defer func() { done <- true }()

	go s.keepAlive(client, done)

	s.listener, err = client.Listen("tcp", "localhost:0")
	if err != nil {
		return fmt.Errorf("failed to open listener on tunnel server: %w", err)
	}

	defer s.listener.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	modes := ssh.TerminalModes{}

	if err := session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
		return fmt.Errorf("request for pseudo terminal failed %v", err)
	}

	if err := session.Shell(); err != nil {
		return err
	}

	s.readyChan <- true

	sessionStoppedChan := make(chan error, 1)

	go func() {
		defer close(sessionStoppedChan)

		err := session.Wait()
		sessionStoppedChan <- err
	}()

	select {
	case <-s.stopChan:
		return nil
	case err := <-sessionStoppedChan:
		if err != nil {
			b.Reset()
		}

		return err
	}
}

func (s *Socket) generateSSHKeyPair() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	var privBuf bytes.Buffer
	parsed, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	privPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: parsed,
	}

	if err := pem.Encode(&privBuf, privPEM); err != nil {
		return err
	}

	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}

	s.keyPair = sshKeyPair{
		privateKey: bytes.TrimSpace(privBuf.Bytes()),
		publicKey:  bytes.TrimSpace(ssh.MarshalAuthorizedKey(pub)),
	}

	return nil
}

func (s *Socket) refreshSSHCert() error {
	sshCert, err := s.border0API.SignSSHKey(context.Background(), s.SocketID, s.keyPair.publicKey)
	if err != nil {
		return err
	}

	certData := []byte(sshCert)
	pubcert, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return fmt.Errorf("failed to parse ssh certificate: %v", err)
	}

	cert, ok := pubcert.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("error failed to cast to certificate: %v", err)
	}

	clientKey, err := ssh.ParsePrivateKey(s.keyPair.privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	if s.sshSigner, err = ssh.NewCertSigner(cert, clientKey); err != nil {
		return fmt.Errorf("failed to create signer: %v", err)
	}

	return nil
}

func getTunnelHost() string {
	if os.Getenv(tunnelHostEnvVar) != "" {
		if !strings.Contains(os.Getenv(tunnelHostEnvVar), ":") {
			return net.JoinHostPort(os.Getenv(tunnelHostEnvVar), strconv.Itoa(defaultTunnelPort))
		}
		return os.Getenv(tunnelHostEnvVar)
	} else {
		return net.JoinHostPort(defaultTunnelHost, strconv.Itoa(defaultTunnelPort))
	}
}

func (s *Socket) keepAlive(client *ssh.Client, done chan bool) {
	t := time.NewTicker(10 * time.Second)
	max := 4
	n := 0

	defer t.Stop()

	for {
		select {
		case <-done:
			return
		case <-t.C:
			aliveChan := make(chan bool, 1)

			go func() {
				_, _, err := client.SendRequest("keepalive@border0.com", true, nil)
				if err != nil {
					aliveChan <- false
				} else {
					aliveChan <- true
				}
			}()

			select {
			case <-time.After(5 * time.Second):
				n++
			case alive := <-aliveChan:
				if !alive {
					n++
				} else {
					n = 0
				}
			}

			if n >= max {
				log.Println("ssh keepalive timeout, disconnecting")
				client.Close()
				return
			}
		}
	}
}

func (s *Socket) Accept() (net.Conn, error) {
	if s.listener == nil {
		return nil, fmt.Errorf("no listener")
	}

	c, err := s.listener.Accept()
	if err != nil {
		if s.closed {
			return nil, err
		}

		if err == io.EOF {
			fmt.Println("listener closed, reconnecting...")
			<-s.readyChan
			return s.Accept()
		} else {
			return nil, err
		}
	}

	if s.ConnectorAuthenticationEnabled {
		ok, err := s.authenticateConnector(c)
		if !ok {
			return nil, fmt.Errorf("failed to authenticate connector")
		}

		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (s *Socket) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *Socket) Close() error {
	s.closed = true
	s.stopChan <- true
	defer close(s.readyChan)

	if s.listener != nil {
		return s.listener.Close()
	}

	return nil
}

func (s *Socket) authenticateConnector(c net.Conn) (bool, error) {
	tlsConn := tls.Server(c, s.ConnectorAuthenticationTLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return false, fmt.Errorf("client tls handshake failed: %s", err)
	}

	if _, err := c.Write([]byte(connectorAuthenticationHeader)); err != nil {
		return false, fmt.Errorf("failed to complete handshake: %s", err)
	}

	log.Printf("client %s authenticated", tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName)
	time.Sleep(connectorAuthenticationShutdownTime)

	return true, nil
}

func (s *Socket) generateConnectorAuthenticationTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ecdsa key: %s", err)
	}

	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ecdsa key: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   s.SocketID,
			Organization: []string{connectorAuthenticationCertificateOrg},
		},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(connectorAuthenticationCertificateTTL),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              []string{s.SocketID},
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	caCertPool := x509.NewCertPool()
	if caCert, ok := s.Organization.Certificates["mtls_certificate"]; !ok {
		return nil, fmt.Errorf("no organization ca certificate found")
	} else {
		if ok := caCertPool.AppendCertsFromPEM([]byte(caCert)); !ok {
			return nil, fmt.Errorf("failed to parse ca certificate")
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}, nil
}

func ProxyConnection(client net.Conn, remote net.Conn) {
	defer client.Close()
	defer remote.Close()

	chDone := make(chan bool, 1)

	go func() {
		io.Copy(client, remote)
		chDone <- true
	}()

	go func() {
		io.Copy(remote, client)
		chDone <- true
	}()

	<-chDone
}

func Serve(l net.Listener, hostname string, port int) error {
	for {
		rconn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %s", err)
		}

		go func() {
			lconn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", hostname, port), 5*time.Second)
			if err != nil {
				log.Printf("failed to connect to local service: %s", err)
				rconn.Close()
				return
			}

			go ProxyConnection(rconn, lconn)
		}()
	}
}

func (s *Socket) IsClosed() bool {
	return s.closed
}
