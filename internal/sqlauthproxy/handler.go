package sqlauthproxy

import (
	"fmt"
	"net"
)

type handler interface {
	handleClient(c net.Conn)
}

type Config struct {
	Hostname         string
	Port             int
	RdsIam           bool
	Username         string
	Password         string
	UpstreamType     string
	UpstreamCAFile   string
	UpstreamCertFile string
	UpstreamKeyFile  string
	UpstreamTLS      bool
	AwsRegion        string
}

func Serve(l net.Listener, config Config) error {
	var handler handler
	var err error

	switch config.UpstreamType {
	case "postgres":
		handler, err = newPostgresHandler(config)
		if err != nil {
			return fmt.Errorf("sqlauthproxy: %s", err)
		}
	default:
		handler, err = newMysqlHandler(config)
		if err != nil {
			return fmt.Errorf("sqlauthproxy: %s", err)
		}
	}

	for {
		rconn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("sqlauthproxy: failed to accept connection: %s", err)
		}

		go handler.handleClient(rconn)
	}
}
