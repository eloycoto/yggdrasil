package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"git.sr.ht/~spc/go-log"
	"github.com/redhatinsights/yggdrasil/internal/http"
	"github.com/redhatinsights/yggdrasil/internal/transport"
	pb "github.com/redhatinsights/yggdrasil/protocol"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
	"k8s.io/utils/inotify"
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

	notifyEvents = unix.IN_MOVED_TO | unix.IN_CLOSE_WRITE
)

type transportConfig struct {
	clientID     string
	dataRecvFunc transport.DataReceiveHandlerFunc
	opts         *TransportOps
}

type Config struct {
	LogLevel    string
	ClientId    string
	SocketAddr  string
	Server      string
	CertFile    string
	KeyFile     string
	CaRoot      []string
	TopicPrefix string
	Protocol    string
	DataHost    string

	tlsConfig         *tls.Config
	transporter       transport.Transporter
	transporterConfig transportConfig
	httpClient        *http.Client
	lock              sync.RWMutex
}

func NewConfigFromCli(c *cli.Context) *Config {
	return &Config{
		LogLevel:    c.String(cliLogLevel),
		ClientId:    c.String(cliClientID),
		SocketAddr:  c.String(cliSocketAddr),
		Server:      c.String(cliServer),
		CertFile:    c.String(cliCertFile),
		KeyFile:     c.String(cliKeyFile),
		CaRoot:      c.StringSlice(cliCaRoot),
		TopicPrefix: c.String(cliTopicPrefix),
		Protocol:    c.String(cliProtocol),
		DataHost:    c.String(cliDataHost),
		lock:        sync.RWMutex{},
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
		CaRoot:     strings.Join(conf.CaRoot, ";"),
	}
}

type TransportOps struct {
	UserAgent       string
	PollingInterval time.Duration
}

func (conf *Config) SetHTTPClient() *http.Client {
	httpClient := http.NewHTTPClient(conf.tlsConfig, UserAgent)
	conf.lock.Lock()
	defer conf.lock.Unlock()
	if conf.httpClient == nil {
		conf.httpClient = httpClient
	} else {
		*conf.httpClient = *httpClient
	}
	return conf.httpClient
}

func (conf *Config) GetHTTPClient() *http.Client {
	conf.lock.RLock()
	defer conf.lock.RUnlock()
	return conf.httpClient
}

func (conf *Config) SetTransport(clientID string, dataRecvFunc transport.DataReceiveHandlerFunc, opts *TransportOps) (transport.Transporter, error) {
	var err error
	var transporter transport.Transporter

	if conf.tlsConfig == nil {
		conf.createTLSConfig()
	}

	if opts == nil {
		opts = &TransportOps{}
	}

	switch conf.Protocol {
	case "mqtt":
		transporter, err = transport.NewMQTTTransport(ClientID, conf.Server, conf.tlsConfig, dataRecvFunc)
		if err != nil {
			return nil, err
		}
	case "http":
		transporter, err = transport.NewHTTPTransport(ClientID, conf.Server, conf.tlsConfig, opts.UserAgent, opts.PollingInterval, dataRecvFunc)
		if err != nil {
			return nil, fmt.Errorf("cannot create HTTP transport: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %v", conf.Protocol)
	}

	conf.lock.Lock()
	conf.transporterConfig = transportConfig{
		clientID:     clientID,
		dataRecvFunc: dataRecvFunc,
		opts:         opts,
	}
	conf.transporter = transporter
	conf.lock.Unlock()
	return conf.transporter, nil
}

func (conf *Config) createTLSConfig() error {
	var certData, keyData []byte
	var err error
	rootCAs := make([][]byte, 0)

	if conf.CertFile != "" && conf.KeyFile != "" {
		certData, err = ioutil.ReadFile(conf.CertFile)
		if err != nil {
			return fmt.Errorf("cannot read cert-file '%v': %v", conf.CertFile, err)
		}

		keyData, err = ioutil.ReadFile(conf.KeyFile)
		if err != nil {
			return fmt.Errorf("cannot read key-file '%v': %v", conf.KeyFile, err)
		}
	}

	for _, file := range conf.CaRoot {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return fmt.Errorf("cannot read ca-file '%v': ", err)
		}
		rootCAs = append(rootCAs, data)
	}

	tlsConfig, err := createNewTLSConfig(certData, keyData, rootCAs)
	if err != nil {
		return err
	}
	conf.lock.Lock()
	conf.tlsConfig = tlsConfig
	conf.lock.Unlock()
	return nil
}

func (conf *Config) WatcherUpdate() error {

	watcher, err := inotify.NewWatcher()
	if err != nil {
		return err
	}
	files := conf.CaRoot
	files = append(files, conf.CertFile, conf.KeyFile)

	for _, filename := range files {
		err = watcher.AddWatch(filename, notifyEvents)
		if err != nil {
			log.Error("Cannot subscribe to inotfy events for %v: %v", filename, err)
			return err
		}
		log.Infof("Added filename '%v' on inotify TLS watcher", filename)
	}

	go func(conf *Config, watcher *inotify.Watcher) {
		for {
			select {
			case ev := <-watcher.Event:
				log.Debugf("New inotify event for file '%v'", ev.Name)
				err := conf.createTLSConfig()
				if err != nil {
					log.Error("Cannot create TLS config on cert change: %v", err)
					continue
				}
				err = conf.transporter.Reload(conf.tlsConfig)
				if err != nil {
					log.Errorf("Cannot reload transports on filename change: %v: %v", ev.Name, err)
					continue
				}

				conf.SetHTTPClient()
				log.Debugf("Inotify watcher finished correctly for file '%v'", ev.Name)
			case err := <-watcher.Error:
				log.Error("Failed on notify filename change:", err)
			}
		}
	}(conf, watcher)
	return nil
}

func createNewTLSConfig(certPEMBlock []byte, keyPEMBlock []byte, CARootPEMBlocks [][]byte) (*tls.Config, error) {
	config := &tls.Config{}

	if len(certPEMBlock) > 0 && len(keyPEMBlock) > 0 {
		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return nil, fmt.Errorf("cannot parse x509 key pair: %w", err)
		}

		config.Certificates = []tls.Certificate{cert}
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("cannot copy system certificate pool: %w", err)
	}
	for _, data := range CARootPEMBlocks {
		pool.AppendCertsFromPEM(data)
	}
	config.RootCAs = pool

	return config, nil
}
