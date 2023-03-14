package cloudsql

import (
	"context"
	"fmt"
	"log"
	"net"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/borderzero/border0-cli/internal/border0"
)

func Serve(l net.Listener, instanceName, credentialsFile string, withIAM bool) error {
	var opts []cloudsqlconn.Option
	if credentialsFile != "" {
		opts = append(opts, cloudsqlconn.WithCredentialsFile(credentialsFile))
	}

	if withIAM {
		opts = append(opts, cloudsqlconn.WithIAMAuthN())
	}

	ctx := context.Background()
	dialer, err := cloudsqlconn.NewDialer(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create dialer for cloudSQL: %s", err)
	}

	for {
		rconn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %s", err)
		}

		go func() {
			lconn, err := dialer.Dial(ctx, instanceName)
			if err != nil {
				log.Printf("failed to connect to cloudSQL: %s", err)
				return
			}

			border0.ProxyConnection(rconn, lconn)
		}()
	}
}
