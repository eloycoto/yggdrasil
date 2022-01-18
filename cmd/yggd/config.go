package main

import (
	pb "github.com/redhatinsights/yggdrasil/protocol"
	"github.com/urfave/cli/v2"
)

func getConfig(c *cli.Context) *pb.Config {
	config := &pb.Config{
		YggLogLevel: c.String(cliLogLevel),
		YggClientId: c.String(cliClientID),
		SocketAddr:  c.String(cliSocketAddr),
		Server:      c.String(cliServer),
		CertFile:    c.String(cliCertFile),
		KeyFile:     c.String(cliKeyFile),
		CaRoot:      c.String(cliCaRoot),
	}
	return config
}
