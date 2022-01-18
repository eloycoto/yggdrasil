package main

import (
	pb "github.com/redhatinsights/yggdrasil/protocol"
	"github.com/urfave/cli/v2"
)

const (
	cliLogLevel    = "log-level"
	cliCertFile    = "cert-file"
	cliKeyFile     = "key-file"
	cliCaRoot      = "ca-root"
	cliServer      = "server"
	cliSocketAddr  = "socket-addr"
	cliClientID    = "client-id"
	cliTopicPrefix = "topic-prefix"
	cliProtocol    = "protocol"
	cliDataHost    = "data-host"
)

type Config struct {
	LogLevel    string
	ClientId    string
	SocketAddr  string
	Server      string
	CertFile    string
	KeyFile     string
	CaRoot      string
	TopicPrefix string
	Protocol    string
	DataHost    string
}

func NewConfigFromCli(c *cli.Context) *Config {
	return &Config{
		LogLevel:    c.String(cliLogLevel),
		ClientId:    c.String(cliClientID),
		SocketAddr:  c.String(cliSocketAddr),
		Server:      c.String(cliServer),
		CertFile:    c.String(cliCertFile),
		KeyFile:     c.String(cliKeyFile),
		CaRoot:      c.String(cliCaRoot),
		TopicPrefix: c.String(cliTopicPrefix),
		Protocol:    c.String(cliProtocol),
		DataHost:    c.String(cliDataHost),
	}
}

func (conf *Config) Export() *pb.Config {
	return &pb.Config{
		LogLevel:   conf.LogLevel,
		ClientId:   conf.ClientId,
		SocketAddr: conf.SocketAddr,
		Server:     conf.Server,
		CertFile:   conf.CertFile,
		KeyFile:    conf.KeyFile,
		CaRoot:     conf.CaRoot,
	}
}
