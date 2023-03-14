package sqlauthproxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
)

type postgresHandler struct {
	Config
	UpstreamConfig *pgconn.Config
	awsCredentials aws.CredentialsProvider
}

func newPostgresHandler(c Config) (*postgresHandler, error) {
	var awsCredentials aws.CredentialsProvider
	if c.RdsIam {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("failed to load aws config: %s", err)
		}

		awsCredentials = cfg.Credentials
	}

	var sslSettings []string
	if c.UpstreamTLS {
		if c.UpstreamCAFile != "" {
			sslSettings = append(sslSettings, fmt.Sprintf("sslrootcert=%s", c.UpstreamCAFile))
			sslSettings = append(sslSettings, "sslmode=verify-ca")
		} else {
			sslSettings = append(sslSettings, "sslmode=require")
		}

		if c.UpstreamCertFile != "" {
			sslSettings = append(sslSettings, fmt.Sprintf("sslcert=%s", c.UpstreamCertFile))
		}

		if c.UpstreamKeyFile != "" {
			sslSettings = append(sslSettings, fmt.Sprintf("sslkey=%s", c.UpstreamKeyFile))
		}
	} else {
		sslSettings = append(sslSettings, "sslmode=prefer")
	}

	var strSslSettings string
	if len(sslSettings) > 0 {
		strSslSettings = "?" + strings.Join(sslSettings, "&")
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d%s", c.Username, c.Password, c.Hostname, c.Port, strSslSettings)
	config, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}

	return &postgresHandler{
		Config:         c,
		UpstreamConfig: config,
		awsCredentials: awsCredentials,
	}, nil
}

func (h postgresHandler) handleClient(c net.Conn) {
	defer c.Close()

	clientConn := pgproto3.NewBackend(pgproto3.NewChunkReader(c), c)

	startupMessage, err := h.handleClientStartup(clientConn, c)
	if err != nil {
		log.Printf("sqlauthproxy: failed to handle client startup: %s", err)
		return
	}

	if startupMessage == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if db, ok := startupMessage.Parameters["database"]; ok {
		h.UpstreamConfig.Database = db
	}

	if h.RdsIam {
		authenticationToken, err := auth.BuildAuthToken(context.TODO(), net.JoinHostPort(h.Hostname, strconv.Itoa(h.Port)), h.AwsRegion, h.Username, h.awsCredentials)
		if err != nil {
			log.Printf("sqlauthproxy: failed to create authentication token: %s", err)
			return
		}

		h.UpstreamConfig.Password = authenticationToken
	}

	conn, err := pgconn.ConnectConfig(ctx, h.UpstreamConfig)
	if err != nil {
		log.Printf("sqlauthproxy: failed to connect to upstream: %s", err)
		return
	}

	pgconn, err := conn.Hijack()
	if err != nil {
		log.Printf("sqlauthproxy: failed to connect to upstream: %s", err)
		return
	}

	if err = h.handleClientAuthRequest(clientConn, pgconn.ParameterStatuses); err != nil {
		log.Printf("sqlauthproxy: failed to handle client authentication: %s", err)
		return
	}

	border0.ProxyConnection(c, pgconn.Conn)
}

func (h postgresHandler) handleClientStartup(c *pgproto3.Backend, conn net.Conn) (*pgproto3.StartupMessage, error) {
	message, err := c.ReceiveStartupMessage()
	if err != nil {
		return nil, nil
	}

	switch msg := message.(type) {
	case *pgproto3.StartupMessage:
		return msg, nil
	case *pgproto3.SSLRequest:
		_, err = conn.Write([]byte("N"))
		if err != nil {
			return nil, nil
		}

		return nil, nil
	case *pgproto3.CancelRequest:
		conn.Close()
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid startup message (%T)", msg)
	}
}

func (h postgresHandler) handleClientAuthRequest(serverSession *pgproto3.Backend, serverParams map[string]string) error {
	err := serverSession.Send(&pgproto3.AuthenticationOk{})
	if err != nil {
		return err
	}

	for name, value := range serverParams {
		err = serverSession.Send(&pgproto3.ParameterStatus{
			Name:  name,
			Value: value,
		})
		if err != nil {
			return err
		}
	}

	err = serverSession.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err != nil {
		return err
	}

	return nil
}
